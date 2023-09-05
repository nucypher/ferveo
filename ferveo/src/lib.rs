#![warn(rust_2018_idioms)]

#[cfg(feature = "bindings-wasm")]
extern crate alloc;

use ark_ec::pairing::Pairing;
use group_threshold_cryptography as tpke;
use itertools::zip_eq;

#[cfg(feature = "bindings-python")]
pub mod bindings_python;

#[cfg(feature = "bindings-wasm")]
pub mod bindings_wasm;

pub mod api;
pub mod dkg;
pub mod primitives;
pub mod pvss;
pub mod validator;

mod utils;

pub use dkg::*;
pub use primitives::*;
pub use pvss::*;
pub use validator::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ThresholdEncryptionError(#[from] tpke::Error),

    /// DKG is not in a valid state to deal PVSS shares
    #[error("Invalid DKG state to deal PVSS shares")]
    InvalidDkgStateToDeal,

    /// DKG is not in a valid state to aggregate PVSS transcripts
    #[error("Invalid DKG state to aggregate PVSS transcripts")]
    InvalidDkgStateToAggregate,

    /// DKG is not in a valid state to verify PVSS transcripts
    #[error("Invalid DKG state to verify PVSS transcripts")]
    InvalidDkgStateToVerify,

    /// DKG is not in a valid state to ingest PVSS transcripts
    #[error("Invalid DKG state to ingest PVSS transcripts")]
    InvalidDkgStateToIngest,

    /// DKG validator set must contain the validator with the given address
    #[error("Expected validator to be a part of the DKG validator set: {0}")]
    DealerNotInValidatorSet(EthereumAddress),

    /// DKG received an unknown dealer. Dealer must be the part of the DKG validator set.
    #[error("DKG received an unknown dealer: {0}")]
    UnknownDealer(EthereumAddress),

    /// DKG received a PVSS transcript from a dealer that has already been dealt.
    #[error("DKG received a PVSS transcript from a dealer that has already been dealt: {0}")]
    DuplicateDealer(EthereumAddress),

    /// DKG received an invalid transcript for which optimistic verification failed
    #[error("DKG received an invalid transcript")]
    InvalidPvssTranscript,

    /// Aggregation failed because the DKG did not receive enough PVSS transcripts
    #[error(
        "Insufficient transcripts for aggregation (expected {0}, got {1})"
    )]
    InsufficientTranscriptsForAggregate(u32, u32),

    /// Failed to derive a valid final key for the DKG
    #[error("Failed to derive a valid final key for the DKG")]
    InvalidDkgPublicKey,

    /// Not enough validators to perform the DKG for a given number of shares
    #[error("Not enough validators (expected {0}, got {1})")]
    InsufficientValidators(u32, u32),

    /// Transcript aggregate doesn't match the received PVSS instances
    #[error("Transcript aggregate doesn't match the received PVSS instances")]
    InvalidTranscriptAggregate,

    /// DKG validators must be sorted by their Ethereum address
    #[error("DKG validators not sorted")]
    ValidatorsNotSorted,

    /// The validator public key doesn't match the one in the DKG
    #[error("Validator public key mismatch")]
    ValidatorPublicKeyMismatch,

    #[error(transparent)]
    BincodeError(#[from] bincode::Error),

    #[error(transparent)]
    ArkSerializeError(#[from] ark_serialize::SerializationError),

    #[error("Invalid byte length. Expected {0}, got {1}")]
    InvalidByteLength(usize, usize),

    #[error("Invalid variant: {0}")]
    InvalidVariant(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn make_pvss_map<E: Pairing>(
    transcripts: &[PubliclyVerifiableSS<E>],
    validators: &[Validator<E>],
) -> PVSSMap<E> {
    let mut pvss_map: PVSSMap<E> = PVSSMap::new();
    zip_eq(transcripts, validators).for_each(|(transcript, validator)| {
        pvss_map.insert(validator.address.clone(), transcript.clone());
    });
    pvss_map
}

#[cfg(test)]
mod test_dkg_full {
    use std::collections::HashMap;

    use ark_bls12_381::{Bls12_381 as E, Fr, G1Affine};
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::{UniformRand, Zero};
    use ark_poly::EvaluationDomain;
    use ark_std::test_rng;
    use ferveo_common::Keypair;
    use group_threshold_cryptography as tpke;
    use group_threshold_cryptography::{
        DecryptionSharePrecomputed, DecryptionShareSimple, SecretBox,
        SharedSecret,
    };
    use itertools::izip;

    use super::*;
    use crate::dkg::test_common::*;

    type TargetField = <E as Pairing>::TargetField;

    fn make_shared_secret_simple_tdec(
        dkg: &PubliclyVerifiableDkg<E>,
        aad: &[u8],
        ciphertext_header: &tpke::CiphertextHeader<E>,
        validator_keypairs: &[Keypair<E>],
    ) -> (
        PubliclyVerifiableSS<E, Aggregated>,
        Vec<DecryptionShareSimple<E>>,
        SharedSecret<E>,
    ) {
        let pvss_aggregated = aggregate(&dkg.vss);
        assert!(pvss_aggregated.verify_aggregation(dkg).is_ok());

        let decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .map(|validator_keypair| {
                    let validator = dkg
                        .get_validator(&validator_keypair.public_key())
                        .unwrap();
                    pvss_aggregated
                        .make_decryption_share_simple(
                            ciphertext_header,
                            aad,
                            &validator_keypair.decryption_key,
                            validator.share_index,
                            &dkg.pvss_params.g_inv(),
                        )
                        .unwrap()
                })
                .collect();

        let domain_points = &dkg
            .domain
            .elements()
            .take(decryption_shares.len())
            .collect::<Vec<_>>();
        assert_eq!(domain_points.len(), decryption_shares.len());

        // TODO: Consider refactor this part into tpke::combine_simple and expose it
        //  as a public API in tpke::api

        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(domain_points);
        let shared_secret = tpke::share_combine_simple::<E>(
            &decryption_shares,
            &lagrange_coeffs,
        );

        (pvss_aggregated, decryption_shares, shared_secret)
    }

    #[test]
    fn test_dkg_simple_tdec() {
        let rng = &mut test_rng();

        // Works for both power of 2 and non-power of 2
        for shares_num in [4, 7] {
            let threshold = shares_num / 2 + 1;
            let (dkg, validator_keypairs) =
                setup_dealt_dkg_with_n_validators(threshold, shares_num);
            let msg = "my-msg".as_bytes().to_vec();
            let aad: &[u8] = "my-aad".as_bytes();
            let public_key = dkg.public_key();
            let ciphertext = tpke::encrypt::<E>(
                SecretBox::new(msg.clone()),
                aad,
                &public_key,
                rng,
            )
            .unwrap();

            let (_, _, shared_secret) = make_shared_secret_simple_tdec(
                &dkg,
                aad,
                &ciphertext.header().unwrap(),
                &validator_keypairs,
            );

            let plaintext = tpke::decrypt_with_shared_secret(
                &ciphertext,
                aad,
                &shared_secret,
                &dkg.pvss_params.g_inv(),
            )
            .unwrap();
            assert_eq!(plaintext, msg);
        }
    }

    #[test]
    fn test_dkg_simple_tdec_precomputed() {
        let rng = &mut test_rng();

        // Works for both power of 2 and non-power of 2
        for shares_num in [4, 7] {
            // In precomputed variant, threshold must be equal to shares_num
            let threshold = shares_num;
            let (dkg, validator_keypairs) =
                setup_dealt_dkg_with_n_validators(threshold, shares_num);
            let msg = "my-msg".as_bytes().to_vec();
            let aad: &[u8] = "my-aad".as_bytes();
            let public_key = dkg.public_key();
            let ciphertext = tpke::encrypt::<E>(
                SecretBox::new(msg.clone()),
                aad,
                &public_key,
                rng,
            )
            .unwrap();

            let pvss_aggregated = aggregate(&dkg.vss);
            pvss_aggregated.verify_aggregation(&dkg).unwrap();
            let domain_points = dkg
                .domain
                .elements()
                .take(validator_keypairs.len())
                .collect::<Vec<_>>();

            let decryption_shares: Vec<DecryptionSharePrecomputed<E>> =
                validator_keypairs
                    .iter()
                    .map(|validator_keypair| {
                        let validator = dkg
                            .get_validator(&validator_keypair.public_key())
                            .unwrap();
                        pvss_aggregated
                            .make_decryption_share_simple_precomputed(
                                &ciphertext.header().unwrap(),
                                aad,
                                &validator_keypair.decryption_key,
                                validator.share_index,
                                &domain_points,
                                &dkg.pvss_params.g_inv(),
                            )
                            .unwrap()
                    })
                    .collect();
            assert_eq!(domain_points.len(), decryption_shares.len());

            let shared_secret =
                tpke::share_combine_precomputed::<E>(&decryption_shares);

            // Combination works, let's decrypt
            let plaintext = tpke::decrypt_with_shared_secret(
                &ciphertext,
                aad,
                &shared_secret,
                &dkg.pvss_params.g_inv(),
            )
            .unwrap();
            assert_eq!(plaintext, msg);
        }
    }

    #[test]
    fn test_dkg_simple_tdec_share_verification() {
        let rng = &mut test_rng();

        let (dkg, validator_keypairs) = setup_dealt_dkg_with_n_validators(3, 4);
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.public_key();
        let ciphertext =
            tpke::encrypt::<E>(SecretBox::new(msg), aad, &public_key, rng)
                .unwrap();

        let (pvss_aggregated, decryption_shares, _) =
            make_shared_secret_simple_tdec(
                &dkg,
                aad,
                &ciphertext.header().unwrap(),
                &validator_keypairs,
            );

        izip!(
            &pvss_aggregated.shares,
            &validator_keypairs,
            &decryption_shares,
        )
        .for_each(
            |(aggregated_share, validator_keypair, decryption_share)| {
                assert!(decryption_share.verify(
                    aggregated_share,
                    &validator_keypair.public_key().encryption_key,
                    &dkg.pvss_params.h,
                    &ciphertext,
                ));
            },
        );

        // Testing red-path decryption share verification
        let decryption_share = decryption_shares[0].clone();

        // Should fail because of the bad decryption share
        let mut with_bad_decryption_share = decryption_share.clone();
        with_bad_decryption_share.decryption_share = TargetField::zero();
        assert!(!with_bad_decryption_share.verify(
            &pvss_aggregated.shares[0],
            &validator_keypairs[0].public_key().encryption_key,
            &dkg.pvss_params.h,
            &ciphertext,
        ));

        // Should fail because of the bad checksum
        let mut with_bad_checksum = decryption_share;
        with_bad_checksum.validator_checksum.checksum = G1Affine::zero();
        assert!(!with_bad_checksum.verify(
            &pvss_aggregated.shares[0],
            &validator_keypairs[0].public_key().encryption_key,
            &dkg.pvss_params.h,
            &ciphertext,
        ));
    }

    #[test]
    fn test_dkg_simple_tdec_share_recovery() {
        let rng = &mut test_rng();

        let security_threshold = 3;
        let shares_num = 4;
        let (dkg, validator_keypairs) =
            setup_dealt_dkg_with_n_validators(security_threshold, shares_num);
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = &dkg.public_key();
        let ciphertext =
            tpke::encrypt::<E>(SecretBox::new(msg), aad, public_key, rng)
                .unwrap();

        // Create an initial shared secret
        let (_, _, old_shared_secret) = make_shared_secret_simple_tdec(
            &dkg,
            aad,
            &ciphertext.header().unwrap(),
            &validator_keypairs,
        );

        // Now, we're going to recover a new share at a random point and check that the shared secret is still the same

        // Remove one participant from the contexts and all nested structure
        let removed_validator_addr =
            dkg.validators.keys().last().unwrap().clone();
        let mut remaining_validators = dkg.validators.clone();
        remaining_validators.remove(&removed_validator_addr);
        // dkg.vss.remove(&removed_validator_addr); // TODO: Test whether it makes any difference

        // Remember to remove one domain point too
        let mut domain_points = dkg.domain.elements().collect::<Vec<_>>();
        domain_points.pop().unwrap();

        // Our random point
        let x_r = Fr::rand(rng);
        // domain_points.push(x_r);

        // Each participant prepares an update for each other participant
        let share_updates = remaining_validators
            .keys()
            .map(|v_addr| {
                let deltas_i = tpke::prepare_share_updates_for_recovery::<E>(
                    &domain_points,
                    &dkg.pvss_params.h.into_affine(),
                    &x_r,
                    dkg.dkg_params.security_threshold as usize,
                    rng,
                );
                (v_addr.clone(), deltas_i)
            })
            .collect::<HashMap<_, _>>();

        // Participants share updates and update their shares
        // TODO: Consider moving into the loop
        let pvss_aggregated = aggregate(&dkg.vss);

        // Now, every participant separately:
        let updated_shares: Vec<_> = remaining_validators
            .iter()
            .map(|(validator_address, validator)| {
                // Receives updates from other participants
                let updates_for_participant =
                    share_updates.get(validator_address).unwrap();

                // Each validator uses their decryption key to update their share
                let decryption_key = validator_keypairs
                    .get(validator.share_index)
                    .unwrap()
                    .decryption_key;

                // Creates updated private key shares
                pvss_aggregated.update_private_key_share_for_recovery(
                    &decryption_key,
                    validator.share_index,
                    updates_for_participant,
                )
            })
            .collect();

        // TODO: Rename updated_private_shares to something that doesn't imply mutation

        // Now, we have to combine new share fragments into a new share
        let new_private_key_share =
            tpke::recover_share_from_updated_private_shares(
                &x_r,
                &domain_points,
                &updated_shares,
            );

        // Get decryption shares from remaining participants
        let mut remaining_validator_keypairs = validator_keypairs;
        remaining_validator_keypairs
            .pop()
            .expect("Should have a keypair");
        let mut decryption_shares: Vec<DecryptionShareSimple<E>> =
            remaining_validator_keypairs
                .iter()
                .enumerate()
                .map(|(share_index, validator_keypair)| {
                    pvss_aggregated
                        .make_decryption_share_simple(
                            &ciphertext.header().unwrap(),
                            aad,
                            &validator_keypair.decryption_key,
                            share_index,
                            &dkg.pvss_params.g_inv(),
                        )
                        .unwrap()
                })
                .collect();

        // Create a decryption share from a recovered private key share
        let new_validator_decryption_key = Fr::rand(rng);
        decryption_shares.push(
            DecryptionShareSimple::create(
                &new_validator_decryption_key,
                &new_private_key_share,
                &ciphertext.header().unwrap(),
                aad,
                &dkg.pvss_params.g_inv(),
            )
            .unwrap(),
        );

        domain_points.push(x_r);
        assert_eq!(domain_points.len(), shares_num as usize);
        assert_eq!(decryption_shares.len(), shares_num as usize);

        let domain_points = &domain_points[1..];
        let decryption_shares = &decryption_shares[1..];
        assert_eq!(domain_points.len(), security_threshold as usize);
        assert_eq!(decryption_shares.len(), security_threshold as usize);

        let lagrange = tpke::prepare_combine_simple::<E>(domain_points);
        let new_shared_secret =
            tpke::share_combine_simple::<E>(decryption_shares, &lagrange);

        assert_eq!(old_shared_secret, new_shared_secret);
    }

    #[test]
    fn test_simple_tdec_share_refreshing() {
        let rng = &mut test_rng();
        let (dkg, validator_keypairs) = setup_dealt_dkg_with_n_validators(3, 4);

        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.public_key();
        let ciphertext =
            tpke::encrypt::<E>(SecretBox::new(msg), aad, &public_key, rng)
                .unwrap();

        let pvss_aggregated = aggregate(&dkg.vss);

        // Create an initial shared secret
        let (_, _, old_shared_secret) = make_shared_secret_simple_tdec(
            &dkg,
            aad,
            &ciphertext.header().unwrap(),
            &validator_keypairs,
        );

        // Now, we're going to refresh the shares and check that the shared secret is the same

        // Dealer computes a new random polynomial with constant term x_r = 0
        let polynomial = tpke::make_random_polynomial_at::<E>(
            dkg.dkg_params.security_threshold as usize,
            &Fr::zero(),
            rng,
        );

        // Dealer shares the polynomial with participants

        // Participants computes new decryption shares
        let new_decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(validator_address, validator_keypair)| {
                    pvss_aggregated
                        .refresh_decryption_share(
                            &ciphertext.header().unwrap(),
                            aad,
                            &validator_keypair.decryption_key,
                            validator_address,
                            &polynomial,
                            &dkg,
                        )
                        .unwrap()
                })
                .collect();

        // Create a new shared secret
        let domain = &dkg.domain.elements().collect::<Vec<_>>();
        // TODO: Combine `tpke::prepare_combine_simple` and `tpke::share_combine_simple` into
        //  one function and expose it in the tpke::api?
        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(domain);
        let new_shared_secret = tpke::share_combine_simple::<E>(
            &new_decryption_shares,
            &lagrange_coeffs,
        );

        assert_eq!(old_shared_secret, new_shared_secret);
    }
}
