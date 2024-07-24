use std::{marker::PhantomData, ops::Mul};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{Field, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, DenseUVPolynomial,
    EvaluationDomain, Polynomial,
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
    apply_updates_to_private_share, assert_no_share_duplicates,
    batch_to_projective_g1, batch_to_projective_g2, Error, PVSSMap,
    PubliclyVerifiableDkg, Result, Validator,
};

/// These are the blinded evaluations of shares of a single random polynomial
pub type ShareEncryptions<E> = <E as Pairing>::G2Affine;

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
    pub shares: Vec<E::G2Affine>,

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
        let evals = dkg
            .domain_points()
            .iter()
            .map(|x| phi.0.evaluate(x))
            .collect::<Vec<_>>();
        debug_assert_eq!(evals.len(), dkg.validators.len());

        // commitment to coeffs, F_i
        let coeffs = fast_multiexp(&phi.0.coeffs, dkg.pvss_params.g);
        let shares = dkg
            .validators
            .values()
            .map(|validator| {
                // ek_{i}^{eval_i}, i = validator index
                // TODO: Replace with regular, single-element exponentiation
                fast_multiexp(
                    // &evals.evals[i..i] = &evals.evals[i]
                    &[evals[validator.share_index as usize]], // one share per validator
                    validator.public_key.encryption_key.into_group(),
                )[0]
            })
            .collect::<Vec<ShareEncryptions<E>>>();
        if shares.len() != dkg.validators.len() {
            return Err(Error::InsufficientValidators(
                shares.len() as u32,
                dkg.validators.len() as u32,
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
        let validators = dkg.validators.values().cloned().collect::<Vec<_>>();
        do_verify_full(
            &self.coeffs,
            &self.shares,
            &dkg.pvss_params,
            &validators,
            &dkg.domain,
        )
    }
}

// TODO: Return validator that failed the check
pub fn do_verify_full<E: Pairing>(
    pvss_coefficients: &[E::G1Affine],
    pvss_encrypted_shares: &[E::G2Affine],
    pvss_params: &PubliclyVerifiableParams<E>,
    validators: &[Validator<E>],
    domain: &ark_poly::GeneralEvaluationDomain<E::ScalarField>,
) -> bool {
    let mut commitment = batch_to_projective_g1::<E>(pvss_coefficients);
    domain.fft_in_place(&mut commitment);

    assert_no_share_duplicates(validators).expect("Validators must be unique");

    // Each validator checks that their share is correct
    validators
        .iter()
        .zip(pvss_encrypted_shares.iter())
        .enumerate()
        .all(|(share_index, (validator, y_i))| {
            // TODO: Check #3 is missing
            // See #3 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf

            // Validator checks aggregated shares against commitment
            let ek_i = validator.public_key.encryption_key.into_group();
            let a_i = &commitment[share_index];
            // We verify that e(G, Y_i) = e(A_i, ek_i) for validator i
            // See #4 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf
            // e(G,Y) = e(A, ek)
            E::pairing(pvss_params.g, *y_i) == E::pairing(a_i, ek_i)
        })
}

pub fn do_verify_aggregation<E: Pairing>(
    pvss_agg_coefficients: &[E::G1Affine],
    pvss_agg_encrypted_shares: &[E::G2Affine],
    pvss_params: &PubliclyVerifiableParams<E>,
    validators: &[Validator<E>],
    domain: &ark_poly::GeneralEvaluationDomain<E::ScalarField>,
    vss: &PVSSMap<E>,
) -> Result<bool> {
    let is_valid = do_verify_full(
        pvss_agg_coefficients,
        pvss_agg_encrypted_shares,
        pvss_params,
        validators,
        domain,
    );
    if !is_valid {
        return Err(Error::InvalidTranscriptAggregate);
    }

    // Now, we verify that the first element of the aggregated PVSS transcript 
    // (i.e. the final DKG public key) is actually the sum of the first element
    // of all the transcripts
    let mut y = E::G1::zero();
    for pvss in vss.values() {
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
    /// and received by the DKG context `dkg`.
    /// Returns the total nr of shares in the aggregated PVSS
    pub fn verify_aggregation(
        &self,
        dkg: &PubliclyVerifiableDkg<E>,
    ) -> Result<bool> {
        let validators = dkg.validators.values().cloned().collect::<Vec<_>>();
        do_verify_aggregation(
            &self.coeffs,
            &self.shares,
            &dkg.pvss_params,
            &validators,
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
            .get(share_index)
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
pub(crate) fn aggregate<E: Pairing>(
    pvss_list: &[PubliclyVerifiableSS<E>],
) -> Result<PubliclyVerifiableSS<E, Aggregated>> {
    let mut pvss_iter = pvss_list.iter();
    let first_pvss = pvss_iter
        .next()
        .ok_or_else(|| Error::NoTranscriptsToAggregate)?;
    let mut coeffs = batch_to_projective_g1::<E>(&first_pvss.coeffs);
    let mut sigma = first_pvss.sigma;

    let mut shares = batch_to_projective_g2::<E>(&first_pvss.shares);

    // So now we're iterating over the PVSS instances, and adding their coefficients and shares, and their
    // sigma is the sum of all the sigma_i, which is the proof of knowledge of the secret polynomial
    // Aggregating is just adding the corresponding values in PVSS instances, so PVSS = PVSS + PVSS_i
    for next_pvss in pvss_iter {
        sigma = (sigma + next_pvss.sigma).into();
        coeffs
            .iter_mut()
            .zip_eq(next_pvss.coeffs.iter())
            .for_each(|(a, b)| *a += b);
        shares
            .iter_mut()
            .zip_eq(next_pvss.shares.iter())
            .for_each(|(a, b)| *a += b);
    }
    let shares = E::G2::normalize_batch(&shares);

    Ok(PubliclyVerifiableSS {
        coeffs: E::G1::normalize_batch(&coeffs),
        shares,
        sigma,
        phantom: Default::default(),
    })
}

#[cfg(test)]
mod test_pvss {
    use ark_bls12_381::Bls12_381 as EllipticCurve;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use test_case::test_case;

    use super::*;
    use crate::test_common::*;

    /// Test the happy flow such that the PVSS with the correct form is created
    /// and that appropriate validations pass
    #[test_case(4,4; "number of validators is equal to the number of shares")]
    #[test_case(4,6; "number of validators is greater than the number of shares")]
    fn test_new_pvss(shares_num: u32, validators_num: u32) {
        let rng = &mut ark_std::test_rng();
        let security_threshold = shares_num - 1;

        let (dkg, _) = setup_dealt_dkg_with_n_validators(
            security_threshold,
            shares_num,
            validators_num,
        );
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
    /// then the optimistic verification of the PVSS fails
    #[test]
    fn test_verify_pvss_wrong_proof_of_knowledge() {
        let rng = &mut ark_std::test_rng();
        let (dkg, _) = setup_dkg(0);
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
    #[test]
    fn test_verify_pvss_bad_shares() {
        let rng = &mut ark_std::test_rng();
        let (dkg, _) = setup_dkg(0);
        let s = ScalarField::rand(rng);
        let pvss =
            PubliclyVerifiableSS::<EllipticCurve>::new(&s, &dkg, rng).unwrap();

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
    /// has the correct form and it's validations passes
    #[test_case(4,4; "number of validators is equal to the number of shares")]
    #[test_case(4,6; "number of validators is greater than the number of shares")]
    fn test_aggregate_pvss(shares_num: u32, validators_num: u32) {
        let security_threshold = shares_num - 1;
        let (dkg, _) = setup_dealt_dkg_with_n_validators(
            security_threshold,
            shares_num,
            validators_num,
        );
        let pvss_list = dkg.vss.values().cloned().collect::<Vec<_>>();
        let aggregate = aggregate(&pvss_list).unwrap();
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

    /// Check that if the aggregated PVSS transcript has an
    /// incorrect constant term, the verification fails
    #[test]
    fn test_verify_aggregation_fails_if_constant_term_wrong() {
        let (dkg, _) = setup_dealt_dkg();
        let pvss_list = dkg.vss.values().cloned().collect::<Vec<_>>();
        let mut aggregated = aggregate(&pvss_list).unwrap();
        while aggregated.coeffs[0] == G1::zero() {
            let (dkg, _) = setup_dkg(0);
            let pvss_list = dkg.vss.values().cloned().collect::<Vec<_>>();
            aggregated = aggregate(&pvss_list).unwrap();
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
