use std::collections::BTreeMap;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::Add;

use anyhow::{anyhow, Result};
use ark_ec::bn::G2Affine;
use ark_ec::{msm::FixedBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::UniformRand;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain,
};
use ark_serialize::*;
use ark_std::{end_timer, start_timer};
use ferveo_common::Rng;
use ferveo_common::{Keypair, PublicKey};
use group_threshold_cryptography::{
    prepare_combine_simple, refresh_private_key_share,
    update_share_for_recovery, Ciphertext, DecryptionShareFast,
    DecryptionShareSimple, DecryptionShareSimplePrecomputed, PrivateKeyShare,
};
use itertools::izip;
use itertools::{zip_eq, Itertools};
use measure_time::print_time;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subproductdomain::fast_multiexp;

use crate::{batch_to_projective, PubliclyVerifiableDkg};

/// These are the blinded evaluations of shares of a single random polynomial
pub type ShareEncryptions<E> = <E as PairingEngine>::G2Affine;

/// Marker struct for unaggregated PVSS transcripts
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct Unaggregated;

/// Marker struct for aggregated PVSS transcripts
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct Aggregated;

/// Trait gate used to add extra methods to aggregated PVSS transcripts
pub trait Aggregate {}

/// Apply trait gate to Aggregated marker struct
impl Aggregate for Aggregated {}

/// Type alias for non aggregated PVSS transcripts
pub type Pvss<E> = PubliclyVerifiableSS<E>;

/// Type alias for aggregated PVSS transcripts
pub type AggregatedPvss<E> = PubliclyVerifiableSS<E, Aggregated>;

/// The choice of group generators
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PubliclyVerifiableParams<E: PairingEngine> {
    pub g: E::G1Projective,
    pub h: E::G2Projective,
}

/// Each validator posts a transcript to the chain. Once enough
/// validators have done this (their total voting power exceeds
/// 2/3 the total), this will be aggregated into a final key
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct PubliclyVerifiableSS<E: PairingEngine, T = Unaggregated> {
    /// Used in Feldman commitment to the VSS polynomial, F = g^{\phi}
    pub coeffs: Vec<E::G1Affine>,

    /// The shares to be dealt to each validator
    pub shares: Vec<ShareEncryptions<E>>,

    /// Proof of Knowledge
    pub sigma: E::G2Affine,

    /// Marker struct to distinguish between aggregated and
    /// non aggregated PVSS transcripts
    phantom: PhantomData<T>,
}

impl<E: PairingEngine, T> PubliclyVerifiableSS<E, T> {
    /// Create a new PVSS instance
    /// `s`: the secret constant coefficient to share
    /// `dkg`: the current DKG session
    /// `rng` a cryptographic random number generator
    pub fn new<R: RngCore>(
        s: &E::Fr,
        dkg: &PubliclyVerifiableDkg<E>,
        rng: &mut R,
    ) -> Result<Self> {
        // Our random polynomial, \phi(x) = s + \sum_{i=1}^{t-1} a_i x^i
        let mut phi = DensePolynomial::<E::Fr>::rand(
            (dkg.params.shares_num - dkg.params.security_threshold) as usize,
            rng,
        );
        phi.coeffs[0] = *s; // setting the first coefficient to secret value

        // Evaluations of the polynomial over the domain
        let evals = phi.evaluate_over_domain_by_ref(dkg.domain);
        // commitment to coeffs, F_i
        let coeffs = fast_multiexp(&phi.coeffs, dkg.pvss_params.g);
        let shares = dkg
            .validators
            .iter()
            .map(|val| {
                // ek_{i}^{eval_i}, i = validator index
                fast_multiexp(
                    // &evals.evals[i..i] = &evals.evals[i]
                    &[evals.evals[val.share_index]], // one share per validator
                    val.validator.public_key.encryption_key.into_projective(),
                )[0]
            })
            .collect::<Vec<ShareEncryptions<E>>>();
        if shares.len() != dkg.validators.len() {
            return Err(anyhow!(
                "Not all validator session keys have been announced"
            ));
        }
        // phi.zeroize(); // TODO zeroize?
        // TODO: Cross check proof of knowledge check with the whitepaper; this check proves that there is a relationship between the secret and the pvss transcript
        // Sigma is a proof of knowledge of the secret, sigma = h^s
        let sigma = E::G2Affine::prime_subgroup_generator().mul(*s).into(); //todo hash to curve
        let vss = Self {
            coeffs,
            shares,
            sigma,
            phantom: Default::default(),
        };
        Ok(vss)
    }

    /// Verify the pvss transcript from a validator. This is not the full check,
    /// i.e. we optimistically do not check the commitment. This is deferred
    /// until the aggregation step
    pub fn verify_optimistic(&self) -> bool {
        // We're only checking the proof of knowledge here, sigma ?= h^s
        // "Does the first coefficient of the secret polynomial match the proof of knowledge?"
        E::pairing(
            self.coeffs[0].into_projective(), // F_0 = g^s
            E::G2Affine::prime_subgroup_generator(), // h
        ) == E::pairing(
            E::G1Affine::prime_subgroup_generator(), // g
            self.sigma,                              // h^s
        )
    }

    /// Part of checking the validity of an aggregated PVSS transcript
    ///
    /// Implements check #4 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf
    ///
    /// If aggregation fails, a validator needs to know that their pvss
    /// transcript was at fault so that the can issue a new one. This
    /// function may also be used for that purpose.
    pub fn verify_full(&self, dkg: &PubliclyVerifiableDkg<E>) -> bool {
        // compute the commitment
        let mut commitment = batch_to_projective(&self.coeffs);
        print_time!("commitment fft");
        dkg.domain.fft_in_place(&mut commitment);

        // Each validator checks that their share is correct
        dkg.validators
            .iter()
            .zip(self.shares.iter())
            .all(|(validator, y_i)| {
                // TODO: Check #3 is missing
                // See #3 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf

                // Validator checks checks aggregated shares against commitment
                let ek_i = validator
                    .validator
                    .public_key
                    .encryption_key
                    .into_projective();
                let a_i = commitment[validator.share_index];
                // We verify that e(G, Y_i) = e(A_i, ek_i) for validator i
                // See #4 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf
                // Y = \sum_i y_i \alpha^i
                // A = \sum_i a_i \alpha^i
                // e(G,Y) = e(A, ek)
                E::pairing(dkg.pvss_params.g, *y_i) == E::pairing(a_i, ek_i)
            })
    }
}

/// Extra methods available to aggregated PVSS transcripts
impl<E: PairingEngine, T: Aggregate> PubliclyVerifiableSS<E, T> {
    /// Verify that this PVSS instance is a valid aggregation of
    /// the PVSS instances, produced by [`aggregate`],
    /// and received by the DKG context `dkg`
    /// Returns the total valid weight of the aggregated PVSS
    pub fn verify_aggregation(
        &self,
        dkg: &PubliclyVerifiableDkg<E>,
    ) -> Result<u32> {
        print_time!("PVSS verify_aggregation");
        self.verify_full(dkg);
        // Now, we verify that the aggregated PVSS transcript is a valid aggregation
        // If it is, we return the total weights of the PVSS transcripts
        let mut y = E::G1Projective::zero();
        // TODO: If we don't deal with share weights anymore, do we even need to call `verify_aggregation`?
        let mut shares_total = 0u32;
        for (_, pvss) in dkg.vss.iter() {
            y += pvss.coeffs[0].into_projective();
            shares_total += 1
        }
        if y.into_affine() == self.coeffs[0] {
            Ok(shares_total)
        } else {
            Err(anyhow!(
                "aggregation does not match received PVSS instances"
            ))
        }
    }

    pub fn decrypt_private_key_share(
        &self,
        validator_decryption_key: &E::Fr,
        validator_index: usize,
    ) -> PrivateKeyShare<E> {
        // Decrypt private key shares https://nikkolasg.github.io/ferveo/pvss.html#validator-decryption-of-private-key-shares
        let private_key_share = self
            .shares
            .get(validator_index)
            .unwrap()
            .mul(validator_decryption_key.inverse().unwrap().into_repr())
            .into_affine();
        PrivateKeyShare { private_key_share }
    }

    pub fn make_decryption_share_simple(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
        validator_decryption_key: &E::Fr,
        validator_index: usize,
    ) -> DecryptionShareSimple<E> {
        let private_key_share = self.decrypt_private_key_share(
            validator_decryption_key,
            validator_index,
        );
        DecryptionShareSimple::create(
            validator_index,
            validator_decryption_key,
            &private_key_share,
            ciphertext,
            aad,
        )
        .unwrap() // TODO: Add proper error handling
    }

    pub fn make_decryption_share_simple_precomputed(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
        validator_decryption_key: &E::Fr,
        validator_index: usize,
        domain_points: &[E::Fr],
    ) -> DecryptionShareSimplePrecomputed<E> {
        let private_key_share = self.decrypt_private_key_share(
            validator_decryption_key,
            validator_index,
        );

        let lagrange_coeffs = prepare_combine_simple::<E>(domain_points);

        DecryptionShareSimplePrecomputed::new(
            validator_index,
            validator_decryption_key,
            &private_key_share,
            ciphertext,
            aad,
            &lagrange_coeffs[validator_index],
        )
        .unwrap() // TODO: Add proper error handling
    }

    pub fn refresh_decryption_share(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
        validator_decryption_key: &E::Fr,
        validator_index: usize,
        polynomial: &DensePolynomial<E::Fr>,
        dkg: &PubliclyVerifiableDkg<E>,
    ) -> DecryptionShareSimple<E> {
        let validator_private_key_share = self.decrypt_private_key_share(
            validator_decryption_key,
            validator_index,
        );
        let h = dkg.pvss_params.h;
        let domain_point = dkg.domain.element(validator_index);
        let refreshed_private_key_share = refresh_private_key_share(
            &h,
            &domain_point,
            polynomial,
            &validator_private_key_share,
        );
        DecryptionShareSimple::create(
            validator_index,
            validator_decryption_key,
            &refreshed_private_key_share,
            ciphertext,
            aad,
        )
        .unwrap() // TODO: Add proper error handling
    }

    pub fn update_private_key_share_for_recovery(
        &self,
        validator_decryption_key: &E::Fr,
        validator_index: usize,
        share_updates: &[E::G2Projective],
    ) -> PrivateKeyShare<E> {
        // Retrieves their private key share
        let private_key_share = self.decrypt_private_key_share(
            validator_decryption_key,
            validator_index,
        );

        // And updates their share
        update_share_for_recovery::<E>(&private_key_share, share_updates)
    }
}

/// Aggregate the PVSS instances in `pvss` from DKG session `dkg`
/// into a new PVSS instance
/// See: https://nikkolasg.github.io/ferveo/pvss.html?highlight=aggregate#aggregation
pub fn aggregate<E: PairingEngine>(
    dkg: &PubliclyVerifiableDkg<E>,
) -> PubliclyVerifiableSS<E, Aggregated> {
    let pvss = &dkg.vss;
    let mut pvss_iter = pvss.iter();
    let (_, first_pvss) = pvss_iter.next().unwrap();
    let mut coeffs = batch_to_projective(&first_pvss.coeffs);
    let mut sigma = first_pvss.sigma;

    let mut shares = batch_to_projective(&first_pvss.shares);

    // So now we're iterating over the PVSS instances, and adding their coefficients and shares, and their sigma
    // sigma is the sum of all the sigma_i, which is the proof of knowledge of the secret polynomial
    // Aggregating is just adding the corresponding values in pvss instances, so pvss = pvss + pvss_j
    for (_, next) in pvss_iter {
        sigma = sigma.add(next.sigma);
        coeffs
            .iter_mut()
            .zip_eq(next.coeffs.iter())
            .for_each(|(a, b)| *a += b.into_projective());
        shares
            .iter_mut()
            .zip_eq(next.shares.iter())
            .for_each(|(a, b)| *a += b.into_projective());
    }
    let shares = E::G2Projective::batch_normalization_into_affine(&shares);

    PubliclyVerifiableSS {
        coeffs: E::G1Projective::batch_normalization_into_affine(&coeffs),
        shares,
        sigma,
        phantom: Default::default(),
    }
}

#[cfg(test)]
mod test_pvss {
    use ark_bls12_381::Bls12_381 as EllipticCurve;
    use ark_ff::UniformRand;
    use ferveo_common::ExternalValidator;

    use super::*;
    use crate::dkg::pv::test_common::*;

    type Fr = <EllipticCurve as PairingEngine>::Fr;
    type G1 = <EllipticCurve as PairingEngine>::G1Affine;
    type G2 = <EllipticCurve as PairingEngine>::G2Affine;

    /// Test the happy flow that a pvss with the correct form is created
    /// and that appropriate validations pass
    #[test]
    fn test_new_pvss() {
        let rng = &mut ark_std::test_rng();
        let dkg = setup_dkg(0);
        let s = Fr::rand(rng);
        let pvss =
            Pvss::<EllipticCurve>::new(&s, &dkg, rng).expect("Test failed");
        // check that the chosen secret coefficient is correct
        assert_eq!(pvss.coeffs[0], G1::prime_subgroup_generator().mul(s));
        //check that a polynomial of the correct degree was created
        assert_eq!(
            pvss.coeffs.len(),
            dkg.params.security_threshold as usize + 1
        );
        // check that the correct number of shares were created
        assert_eq!(pvss.shares.len(), dkg.validators.len());
        // check that the prove of knowledge is correct
        assert_eq!(pvss.sigma, G2::prime_subgroup_generator().mul(s));
        // check that the optimistic verify returns true
        assert!(pvss.verify_optimistic());
        // check that the full verify returns true
        assert!(pvss.verify_full(&dkg));
    }

    /// Check that if the proof of knowledge is wrong,
    /// the optimistic verification of PVSS fails
    #[test]
    fn test_verify_pvss_wrong_proof_of_knowledge() {
        let rng = &mut ark_std::test_rng();
        let dkg = setup_dkg(0);
        let mut s = Fr::rand(rng);
        // ensure that the proof of knowledge is not zero
        while s == Fr::zero() {
            s = Fr::rand(rng);
        }
        let mut pvss =
            PubliclyVerifiableSS::<EllipticCurve>::new(&s, &dkg, rng)
                .expect("Test failed");

        pvss.sigma = G2::zero();
        assert!(!pvss.verify_optimistic());
    }

    /// Check that if PVSS shares are tempered with, the full verification fails
    #[test]
    fn test_verify_pvss_bad_shares() {
        let rng = &mut ark_std::test_rng();
        let dkg = setup_dkg(0);
        let s = Fr::rand(rng);
        let pvss = Pvss::<EllipticCurve>::new(&s, &dkg, rng).unwrap();

        // So far, everything works
        assert!(pvss.verify_optimistic());
        assert!(pvss.verify_full(&dkg));

        // Now, we're going to tamper with the PVSS shares
        let mut bad_pvss = pvss;
        bad_pvss.shares[0] = G2::zero();

        // Optimistic verification should not catch this issue
        assert!(bad_pvss.verify_optimistic());
        // Full verification should catch this issue
        assert!(!bad_pvss.verify_full(&dkg));
    }

    /// Check that happy flow of aggregating PVSS transcripts
    /// Should have the correct form and validations pass
    #[test]
    fn test_aggregate_pvss() {
        let dkg = setup_dealt_dkg();
        let aggregate = aggregate(&dkg);
        //check that a polynomial of the correct degree was created
        assert_eq!(
            aggregate.coeffs.len(),
            dkg.params.security_threshold as usize + 1
        );
        // check that the correct number of shares were created
        assert_eq!(aggregate.shares.len(), dkg.validators.len());
        // check that the optimistic verify returns true
        assert!(aggregate.verify_optimistic());
        // check that the full verify returns true
        assert!(aggregate.verify_full(&dkg));
        // check that the verification of aggregation passes
        assert_eq!(
            aggregate.verify_aggregation(&dkg).expect("Test failed"),
            dkg.validators.len() as u32
        );
    }

    /// Check that if the aggregated pvss transcript has an
    /// incorrect constant term, the verification fails
    #[test]
    fn test_verify_aggregation_fails_if_constant_term_wrong() {
        use std::ops::Neg;
        let dkg = setup_dealt_dkg();
        let mut aggregated = aggregate(&dkg);
        while aggregated.coeffs[0] == G1::zero() {
            let dkg = setup_dkg(0);
            aggregated = aggregate(&dkg);
        }
        aggregated.coeffs[0] = G1::zero();
        assert_eq!(
            aggregated
                .verify_aggregation(&dkg)
                .expect_err("Test failed")
                .to_string(),
            "aggregation does not match received PVSS instances"
        )
    }
}
