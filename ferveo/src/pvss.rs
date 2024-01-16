use std::{marker::PhantomData, ops::Mul};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{Field, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, DenseUVPolynomial,
    EvaluationDomain,
};
use ferveo_tdec::{
    prepare_combine_simple, CiphertextHeader, DecryptionSharePrecomputed,
    DecryptionShareSimple, PrivateKeyShare,
};
use itertools::Itertools;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use subproductdomain::fast_multiexp;
use zeroize::{self, Zeroize, ZeroizeOnDrop};

use crate::{
    apply_updates_to_private_share, batch_to_projective_g1,
    batch_to_projective_g2, Error, PVSSMap, PubliclyVerifiableDkg, Result,
    ValidatorsMap,
};

/// These are the blinded evaluations of shares of a single random polynomial
pub type ShareEncryption<E> = <E as Pairing>::G2Affine;

pub type ShareEncryptionMap<E> =
    std::collections::BTreeMap<usize, ShareEncryption<E>>;

/// Marker struct for unaggregated PVSS transcripts
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Unaggregated;

/// Marker struct for aggregated PVSS transcripts
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Aggregated;

/// Trait gate used to add extra methods to aggregated PVSS transcripts
pub trait Aggregate {}

/// Apply trait gate to Aggregated marker struct
impl Aggregate for Aggregated {}

// /// Type alias for non aggregated PVSS transcripts
// pub type Pvss<E> = PubliclyVerifiableSS<E>;

/// Type alias for aggregated PVSS transcripts
pub type AggregatedPvss<E> = PubliclyVerifiableSS<E, Aggregated>;

/// The choice of group generators
#[derive(Clone, Debug)]
pub struct PubliclyVerifiableParams<E: Pairing> {
    pub g: E::G1,
    pub h: E::G2,
}

impl<E: Pairing> PubliclyVerifiableParams<E> {
    pub fn g_inv(&self) -> E::G1Prepared {
        E::G1Prepared::from(-self.g)
    }
}

impl<E: Pairing> Default for PubliclyVerifiableParams<E> {
    fn default() -> Self {
        Self {
            g: E::G1::generator(),
            h: E::G2::generator(),
        }
    }
}

/// Secret polynomial used in the PVSS protocol
/// We wrap this in a struct so that we can zeroize it after use
pub struct SecretPolynomial<E: Pairing>(pub DensePolynomial<E::ScalarField>);

impl<E: Pairing> SecretPolynomial<E> {
    pub fn new(
        s: &E::ScalarField,
        degree: usize,
        rng: &mut impl RngCore,
    ) -> Self {
        // Our random polynomial, \phi(x) = s + \sum_{i=1}^{t-1} a_i x^i
        let mut phi = DensePolynomial::<E::ScalarField>::rand(degree, rng);
        phi.coeffs[0] = *s; // setting the first coefficient to secret value
        Self(phi)
    }
}

impl<E: Pairing> Zeroize for SecretPolynomial<E> {
    fn zeroize(&mut self) {
        self.0.coeffs.iter_mut().for_each(|c| c.zeroize());
    }
}

// `ZeroizeOnDrop` derivation fails because of missing trait bounds, so we manually introduce
// required traits

impl<E: Pairing> Drop for SecretPolynomial<E> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<E: Pairing> ZeroizeOnDrop for SecretPolynomial<E> {}

/// Each validator posts a transcript to the chain. Once enough
/// validators have done this (their total voting power exceeds
/// 2/3 the total), this will be aggregated into a final key
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PubliclyVerifiableSS<E: Pairing, T = Unaggregated> {
    /// Used in Feldman commitment to the VSS polynomial, F = g^{\phi}
    #[serde_as(as = "ferveo_common::serialization::SerdeAs")]
    pub coeffs: Vec<E::G1Affine>,

    /// The shares to be dealt to each validator
    #[serde_as(as = "ferveo_common::serialization::SerdeAs")]
    // pub shares: Vec<ShareEncryptions<E>>, // TODO: Using a custom type instead of referring to E:G2Affine breaks the serialization
    pub shares: ShareEncryptionMap<E>,

    /// Proof of Knowledge
    #[serde_as(as = "ferveo_common::serialization::SerdeAs")]
    pub sigma: E::G2Affine,

    /// Marker struct to distinguish between aggregated and
    /// non aggregated PVSS transcripts
    phantom: PhantomData<T>,
}

impl<E: Pairing, T> PubliclyVerifiableSS<E, T> {
    /// Create a new PVSS instance
    /// `s`: the secret constant coefficient to share
    /// `dkg`: the current DKG session
    /// `rng` a cryptographic random number generator
    pub fn new<R: RngCore>(
        s: &E::ScalarField,
        dkg: &PubliclyVerifiableDkg<E>,
        rng: &mut R,
    ) -> Result<Self> {
        let phi = SecretPolynomial::<E>::new(
            s,
            (dkg.dkg_params.security_threshold() - 1) as usize,
            rng,
        );

        // Evaluations of the polynomial over the domain
        let evals = phi.0.evaluate_over_domain_by_ref(dkg.domain);
        // commitment to coeffs, F_i
        let coeffs = fast_multiexp(&phi.0.coeffs, dkg.pvss_params.g);
        let shares = dkg
            .validators
            .values()
            .map(|validator| {
                // ek_{i}^{eval_i}, i = validator index
                let share_encryption = fast_multiexp(
                    // &evals.evals[i..i] = &evals.evals[i]
                    &[evals.evals[validator.share_index]], // one share per validator
                    validator.validator.public_key.encryption_key.into_group(),
                )[0];
                println!(
                    "share_index: {}, share_encryption: {}",
                    validator.share_index, share_encryption
                );
                (validator.share_index, share_encryption)
            })
            .collect::<ShareEncryptionMap<E>>();

        if shares.len() < dkg.dkg_params.shares_num() as usize {
            return Err(Error::InsufficientValidators(
                shares.len() as u32,
                dkg.dkg_params.shares_num(),
            ));
        }

        // TODO: Cross check proof of knowledge check with the whitepaper; this check proves that there is a relationship between the secret and the pvss transcript
        // Sigma is a proof of knowledge of the secret, sigma = h^s
        let sigma = E::G2Affine::generator().mul(*s).into(); //todo hash to curve
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
        let pvss_params = PubliclyVerifiableParams::<E>::default();
        // We're only checking the proof of knowledge here, sigma ?= h^s
        // "Does the first coefficient of the secret polynomial match the proof of knowledge?"
        E::pairing(
            self.coeffs[0].into_group(), // F_0 = g^s
            pvss_params.h,
        ) == E::pairing(
            pvss_params.g,
            self.sigma, // h^s
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
        do_verify_full(
            &self.coeffs,
            &self.shares,
            &dkg.pvss_params,
            &dkg.validators,
            &dkg.domain,
        )
    }
}

// TODO: Return validator that failed the check
pub fn do_verify_full<E: Pairing>(
    pvss_coefficients: &[E::G1Affine],
    pvss_share_map: &ShareEncryptionMap<E>,
    pvss_params: &PubliclyVerifiableParams<E>,
    validator_map: &ValidatorsMap<E>,
    domain: &ark_poly::GeneralEvaluationDomain<E::ScalarField>,
) -> bool {
    let mut commitment = batch_to_projective_g1::<E>(pvss_coefficients);
    domain.fft_in_place(&mut commitment);

    for validator in validator_map.values() {
        println!("validator.share_index: {}", validator.share_index);
    }

    println!("pvss_encrypted_shares.len(): {}", pvss_share_map.len());
    println!("validator_map.len(): {}", validator_map.len());

    // Each validator checks that their share is correct
    validator_map.values().all(|validator| {
        // TODO: Check #3 is missing
        // See #3 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf

        // Validator checks aggregated shares against commitment
        let ek_i = validator.validator.public_key.encryption_key.into_group();
        let a_i = &commitment[validator.share_index];
        let y_i = &pvss_share_map[&validator.share_index];
        println!("share index: {}", validator.share_index);
        println!("ek_i: {ek_i}");
        println!("a_i: {a_i}");
        println!("y_i: {y_i}");

        // We verify that e(G, Y_i) = e(A_i, ek_i) for validator i
        // See #4 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf
        // e(G,Y) = e(A, ek)
        let result = E::pairing(pvss_params.g, *y_i) == E::pairing(a_i, ek_i);
        println!("result: {result}");
        result
    })
}

pub fn do_verify_aggregation<E: Pairing>(
    pvss_agg_coefficients: &[E::G1Affine],
    share_encryption_map: &ShareEncryptionMap<E>,
    pvss_params: &PubliclyVerifiableParams<E>,
    validator_map: &ValidatorsMap<E>,
    domain: &ark_poly::GeneralEvaluationDomain<E::ScalarField>,
    pvss_map: &PVSSMap<E>,
) -> Result<bool> {
    let is_valid = do_verify_full(
        pvss_agg_coefficients,
        share_encryption_map,
        pvss_params,
        validator_map,
        domain,
    );
    if !is_valid {
        // TODO: Throws here
        return Err(Error::InvalidTranscriptAggregate);
    }

    // Now, we verify that the aggregated PVSS transcript is a valid aggregation
    let mut y = E::G1::zero();
    for (_, pvss) in pvss_map.iter() {
        y += pvss.coeffs[0].into_group();
    }
    if y.into_affine() == pvss_agg_coefficients[0] {
        Ok(true)
    } else {
        Err(Error::InvalidTranscriptAggregate)
    }
}

/// Extra methods available to aggregated PVSS transcripts
impl<E: Pairing, T: Aggregate> PubliclyVerifiableSS<E, T> {
    /// Verify that this PVSS instance is a valid aggregation of
    /// the PVSS instances, produced by [`aggregate`],
    /// and received by the DKG context `dkg`
    /// Returns the total nr of shares in the aggregated PVSS
    pub fn verify_aggregation(
        &self,
        dkg: &PubliclyVerifiableDkg<E>,
    ) -> Result<bool> {
        do_verify_aggregation(
            &self.coeffs,
            &self.shares,
            &dkg.pvss_params,
            &dkg.validators,
            &dkg.domain,
            &dkg.vss,
        )
    }

    pub fn decrypt_private_key_share(
        &self,
        validator_decryption_key: &E::ScalarField,
        share_index: usize,
    ) -> Result<PrivateKeyShare<E>> {
        // Decrypt private key shares https://nikkolasg.github.io/ferveo/pvss.html#validator-decryption-of-private-key-shares
        let private_key_share = self
            .shares
            .get(&share_index)
            .ok_or(Error::InvalidShareIndex(share_index as u32))?
            .mul(
                validator_decryption_key
                    .inverse()
                    .expect("Validator decryption key must have an inverse"),
            )
            .into_affine();
        Ok(PrivateKeyShare { private_key_share })
    }

    pub fn make_decryption_share_simple(
        &self,
        ciphertext: &CiphertextHeader<E>,
        aad: &[u8],
        validator_decryption_key: &E::ScalarField,
        share_index: usize,
        g_inv: &E::G1Prepared,
    ) -> Result<DecryptionShareSimple<E>> {
        let private_key_share = self
            .decrypt_private_key_share(validator_decryption_key, share_index)?;
        DecryptionShareSimple::create(
            validator_decryption_key,
            &private_key_share,
            ciphertext,
            aad,
            g_inv,
        )
        .map_err(|e| e.into())
    }

    pub fn make_decryption_share_simple_precomputed(
        &self,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        validator_decryption_key: &E::ScalarField,
        share_index: usize,
        domain_points: &[E::ScalarField],
        g_inv: &E::G1Prepared,
    ) -> Result<DecryptionSharePrecomputed<E>> {
        let private_key_share = self
            .decrypt_private_key_share(validator_decryption_key, share_index)?;

        // We use the `prepare_combine_simple` function to precompute the lagrange coefficients
        let lagrange_coeffs = prepare_combine_simple::<E>(domain_points);

        DecryptionSharePrecomputed::new(
            share_index,
            validator_decryption_key,
            &private_key_share,
            ciphertext_header,
            aad,
            &lagrange_coeffs[share_index],
            g_inv,
        )
        .map_err(|e| e.into())
    }

    // TODO: Consider relocate to different place, maybe PrivateKeyShare? (see #162, #163)
    pub fn update_private_key_share_for_recovery(
        &self,
        validator_decryption_key: &E::ScalarField,
        share_index: usize,
        share_updates: &[E::G2],
    ) -> Result<PrivateKeyShare<E>> {
        // Retrieves their private key share
        let private_key_share = self
            .decrypt_private_key_share(validator_decryption_key, share_index)?;

        // And updates their share
        Ok(apply_updates_to_private_share::<E>(
            &private_key_share,
            share_updates,
        ))
    }
}

/// Aggregate the PVSS instances in `pvss` from DKG session `dkg`
/// into a new PVSS instance
/// See: https://nikkolasg.github.io/ferveo/pvss.html?highlight=aggregate#aggregation
pub fn aggregate<E: Pairing>(
    pvss_map: &PVSSMap<E>,
) -> PubliclyVerifiableSS<E, Aggregated> {
    let mut pvss_iter = pvss_map.iter();
    let (_, first_pvss) = pvss_iter
        .next()
        .expect("May not aggregate empty PVSS instances");
    let mut coeffs = batch_to_projective_g1::<E>(&first_pvss.coeffs);
    let mut sigma = first_pvss.sigma;

    // Ordering of shares doesn't matter here, so we can just collect them from the map
    let shares = first_pvss
        .shares
        .values()
        .cloned()
        .collect::<Vec<ShareEncryption<E>>>();
    let mut shares = batch_to_projective_g2::<E>(&shares);

    // So now we're iterating over the PVSS instances, and adding their coefficients and shares, and their sigma
    // sigma is the sum of all the sigma_i, which is the proof of knowledge of the secret polynomial
    // Aggregating is just adding the corresponding values in pvss instances, so pvss = pvss + pvss_j
    for (_, next) in pvss_iter {
        sigma = (sigma + next.sigma).into();
        coeffs
            .iter_mut()
            .zip_eq(next.coeffs.iter())
            .for_each(|(a, b)| *a += b);
        shares
            .iter_mut()
            .zip_eq(next.shares.iter())
            .for_each(|(a, (_, b))| *a += b);
    }
    let shares = E::G2::normalize_batch(&shares);
    // TODO: There is just one share, but we need to convert it back to a map
    // TODO: Find a better way to do this
    let shares = shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| (i, share))
        .collect::<ShareEncryptionMap<E>>();

    PubliclyVerifiableSS {
        coeffs: E::G1::normalize_batch(&coeffs),
        shares,
        sigma,
        phantom: Default::default(),
    }
}

pub fn aggregate_for_decryption<E: Pairing>(
    dkg: &PubliclyVerifiableDkg<E>,
) -> Vec<ShareEncryption<E>> {
    // From docs: https://nikkolasg.github.io/ferveo/pvss.html?highlight=aggregate#aggregation
    // "Two PVSS instances may be aggregated into a single PVSS instance by adding elementwise each of the corresponding group elements."
    let share_maps = dkg
        .vss
        .values()
        .map(|pvss| pvss.shares.clone())
        .collect::<Vec<ShareEncryptionMap<E>>>();

    // Now, get shares from each map. Sort them by index, and then collect them into a vector
    let shares = share_maps
        .into_iter()
        .map(|share_map| {
            share_map
                .into_iter()
                .sorted_by_key(|(index, _)| *index)
                .map(|(_, share)| share)
                .collect::<Vec<ShareEncryption<E>>>()
        })
        .collect::<Vec<Vec<ShareEncryption<E>>>>();

    // Now, we're going to add the shares together
    let first_share = shares[0].clone();

    shares
        .into_iter()
        .skip(1)
        // We're assuming that in every PVSS instance, the shares are in the same order
        .fold(first_share, |acc, shares| {
            acc.into_iter()
                .zip_eq(shares)
                .map(|(a, b)| (a + b).into())
                .collect()
        })
}

#[cfg(test)]
mod test_pvss {
    use ark_bls12_381::{Bls12_381 as EllipticCurve, Bls12_381};
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use rand::seq::SliceRandom;
    use test_case::test_case;

    use super::*;
    use crate::{dkg::test_common::*, utils::is_sorted};

    type ScalarField = <EllipticCurve as Pairing>::ScalarField;
    type G1 = <EllipticCurve as Pairing>::G1Affine;
    type G2 = <EllipticCurve as Pairing>::G2Affine;

    fn _setup_dkg(
        shares_num: u32,
        validators_num: u32,
    ) -> PubliclyVerifiableDkg<Bls12_381> {
        let (dkg, _) = setup_dkg_for_me_with_n_validators(
            2,
            shares_num,
            0,
            validators_num,
        );
        dkg
    }

    fn _setup_dealt_dkg(
        shares_num: u32,
        validators_num: u32,
    ) -> PubliclyVerifiableDkg<Bls12_381> {
        let (dkg, _) =
            setup_dealt_dkg_with_n_validators(2, shares_num, validators_num);
        dkg
    }

    /// Test the happy flow that a pvss with the correct form is created
    /// and that appropriate validations pass
    #[test_case(4, 4; "number of shares is equal to number of validators")]
    #[test_case(4, 6; "number of shares is smaller than the number of validators")]
    fn test_new_pvss(shares_num: u32, validators_num: u32) {
        let rng = &mut ark_std::test_rng();
        let dkg = _setup_dkg(shares_num, validators_num);
        let s = ScalarField::rand(rng);
        let pvss = PubliclyVerifiableSS::<EllipticCurve>::new(&s, &dkg, rng)
            .expect("Test failed");
        // Check that the chosen secret coefficient is correct
        assert_eq!(pvss.coeffs[0], G1::generator().mul(s));
        // Check that a polynomial of the correct degree was created
        assert_eq!(
            pvss.coeffs.len(),
            dkg.dkg_params.security_threshold() as usize
        );
        // Check that the correct number of shares were created
        assert_eq!(pvss.shares.len(), dkg.validators.len());
        // Check that the prove of knowledge is correct
        assert_eq!(pvss.sigma, G2::generator().mul(s));
        // Check that the optimistic verify returns true
        assert!(pvss.verify_optimistic());
        // Check that the full verify returns true
        assert!(pvss.verify_full(&dkg));
    }

    /// Check that if the proof of knowledge is wrong,
    /// the optimistic verification of PVSS fails
    #[test_case(4, 4; "number of shares is equal to number of validators")]
    #[test_case(4, 6; "number of shares is smaller than the number of validators")]
    fn test_verify_pvss_wrong_proof_of_knowledge(
        shares_num: u32,
        validators_num: u32,
    ) {
        let rng = &mut ark_std::test_rng();
        // Make sure it works for relaxed DKG ceremony constraints
        let dkg = _setup_dkg(shares_num, validators_num);
        let mut s = ScalarField::rand(rng);
        // Ensure that the proof of knowledge is not zero
        while s == ScalarField::zero() {
            s = ScalarField::rand(rng);
        }
        let mut pvss =
            PubliclyVerifiableSS::<EllipticCurve>::new(&s, &dkg, rng)
                .expect("Test failed");

        pvss.sigma = G2::zero();
        assert!(!pvss.verify_optimistic());
    }

    /// Check that if PVSS shares are tampered with, the full verification fails
    #[test_case(4, 4; "number of shares is equal to number of validators")]
    #[test_case(4, 6; "number of shares is smaller than the number of validators")]
    fn test_verify_pvss_bad_shares(shares_num: u32, validators_num: u32) {
        let rng = &mut ark_std::test_rng();
        let keypairs = gen_keypairs(validators_num);
        let mut validators = gen_validators(&keypairs);
        validators.sort();
        let _me = validators[0].clone();

        let dkg = _setup_dkg(shares_num, validators_num);
        let secret = ScalarField::rand(rng);
        let pvss =
            PubliclyVerifiableSS::<EllipticCurve>::new(&secret, &dkg, rng)
                .unwrap();

        // So far, everything works
        assert!(pvss.verify_optimistic());
        assert!(pvss.verify_full(&dkg));

        // Now, we're going to tamper with the PVSS shares
        let mut bad_pvss = pvss;
        bad_pvss.shares.insert(0_usize, G2::zero());

        // Optimistic verification should not catch this issue
        assert!(bad_pvss.verify_optimistic());
        // Full verification should catch this issue
        assert!(!bad_pvss.verify_full(&dkg));
    }

    /// Check that the explicit ordering of validators is expected and enforced
    /// by the DKG methods.
    #[test]
    fn test_ordering_of_validators_is_enforced() {
        let rng = &mut ark_std::test_rng();

        let shares_num = 4;
        let keypairs = gen_keypairs(shares_num);
        let mut validators = gen_validators(&keypairs);
        let me = validators[0].clone();

        // Validators are not sorted
        validators.shuffle(rng);
        assert!(!is_sorted(&validators));

        // And because of that the DKG should fail
        let result = PubliclyVerifiableDkg::new(
            &validators,
            &DkgParams::new(0, 2, shares_num).unwrap(),
            &me,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            Error::ValidatorsNotSorted.to_string()
        );
    }

    /// Check that happy flow of aggregating PVSS transcripts
    /// Should have the correct form and validations pass
    #[test_case(4, 4; "number of shares is equal to number of validators")]
    #[test_case(4, 6; "number of shares is smaller than the number of validators")]
    fn test_aggregate_pvss(shares_num: u32, validators_num: u32) {
        let dkg = _setup_dealt_dkg(shares_num, validators_num);
        let aggregate = aggregate(&dkg.vss);
        // Check that a polynomial of the correct degree was created
        assert_eq!(
            aggregate.coeffs.len(),
            dkg.dkg_params.security_threshold() as usize
        );
        // Check that the correct number of shares were created
        assert_eq!(aggregate.shares.len(), dkg.validators.len());
        // Check that the optimistic verify returns true
        assert!(aggregate.verify_optimistic());
        // Check that the full verify returns true
        assert!(aggregate.verify_full(&dkg));
        // Check that the verification of aggregation passes
        assert!(aggregate.verify_aggregation(&dkg).expect("Test failed"),);
    }

    /// Check that if the aggregated pvss transcript has an
    /// incorrect constant term, the verification fails
    #[test_case(4, 4; "number of shares is equal to number of validators")]
    #[test_case(4, 6; "number of shares is smaller than the number of validators")]
    fn test_verify_aggregation_fails_if_constant_term_wrong(
        shares_num: u32,
        validators_num: u32,
    ) {
        let dkg = _setup_dealt_dkg(shares_num, validators_num);
        let mut aggregated = aggregate(&dkg.vss);
        while aggregated.coeffs[0] == G1::zero() {
            let (dkg, _) = setup_dkg();
            aggregated = aggregate(&dkg.vss);
        }
        aggregated.coeffs[0] = G1::zero();
        assert_eq!(
            aggregated
                .verify_aggregation(&dkg)
                .expect_err("Test failed")
                .to_string(),
            "Transcript aggregate doesn't match the received PVSS instances"
        )
    }
}
