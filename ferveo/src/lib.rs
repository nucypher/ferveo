#![warn(rust_2018_idioms)]

#[cfg(feature = "bindings-wasm")]
extern crate alloc;
extern crate core;

#[cfg(feature = "bindings-python")]
pub mod bindings_python;

#[cfg(feature = "bindings-wasm")]
pub mod bindings_wasm;

pub mod api;
pub mod dkg;
pub mod primitives;
pub mod pvss;
pub mod refresh;
pub mod validator;

#[cfg(test)]
mod debug;
#[cfg(test)]
mod test_common;

pub use dkg::*;
pub use primitives::*;
pub use pvss::*;
pub use refresh::*;
pub use validator::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ThresholdEncryptionError(#[from] ferveo_tdec::Error),

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

    /// The validator public key doesn't match the one in the DKG
    #[error("Validator public key mismatch")]
    ValidatorPublicKeyMismatch,

    #[error(transparent)]
    BincodeError(#[from] bincode::Error),

    #[error(transparent)]
    ArkSerializeError(#[from] ark_serialize::SerializationError),

    /// Invalid byte length
    #[error("Invalid byte length. Expected {0}, got {1}")]
    InvalidByteLength(usize, usize),

    /// Invalid variant
    #[error("Invalid variant: {0}")]
    InvalidVariant(String),

    /// DKG parameters validaiton failed
    #[error("Invalid DKG parameters: number of shares {0}, threshold {1}")]
    InvalidDkgParameters(u32, u32),

    /// Failed to access a share for a given share index
    #[error("Invalid share index: {0}")]
    InvalidShareIndex(u32),

    /// Failed to produce a precomputed variant decryption share
    #[error("Invalid DKG parameters for precomputed variant: number of shares {0}, threshold {1}")]
    InvalidDkgParametersForPrecomputedVariant(u32, u32),

    /// DKG may not contain duplicated share indices
    #[error("Duplicated share index: {0}")]
    DuplicatedShareIndex(u32),

    /// Creating a transcript aggregate requires at least one transcript
    #[error("No transcripts to aggregate")]
    NoTranscriptsToAggregate,

    /// The number of messages may not be greater than the number of validators
    #[error("Invalid aggregate verification parameters: number of validators {0}, number of messages: {1}")]
    InvalidAggregateVerificationParameters(u32, u32),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test_dkg_full {
    use std::collections::HashMap;

    use ark_bls12_381::{Bls12_381 as E, Fr, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{UniformRand, Zero};
    use ark_poly::EvaluationDomain;
    use ark_std::test_rng;
    use ferveo_common::Keypair;
    use ferveo_tdec::{
        self, DecryptionSharePrecomputed, DecryptionShareSimple, SecretBox,
        SharedSecret,
    };
    use itertools::izip;
    use rand::seq::SliceRandom;
    use test_case::test_case;

    use super::*;
    use crate::test_common::*;

    fn make_shared_secret_simple_tdec(
        dkg: &PubliclyVerifiableDkg<E>,
        aad: &[u8],
        ciphertext_header: &ferveo_tdec::CiphertextHeader<E>,
        validator_keypairs: &[Keypair<E>],
    ) -> (
        PubliclyVerifiableSS<E, Aggregated>,
        Vec<DecryptionShareSimple<E>>,
        SharedSecret<E>,
    ) {
        let pvss_list = dkg.vss.values().cloned().collect::<Vec<_>>();
        let pvss_aggregated = aggregate(&pvss_list).unwrap();
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
                            validator.share_index as usize,
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

        // TODO: Consider refactor this part into ferveo_tdec::combine_simple and expose it
        //  as a public API in ferveo_tdec::api

        let lagrange_coeffs =
            ferveo_tdec::prepare_combine_simple::<E>(domain_points);
        let shared_secret = ferveo_tdec::share_combine_simple::<E>(
            &decryption_shares,
            &lagrange_coeffs,
        );

        (pvss_aggregated, decryption_shares, shared_secret)
    }

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn test_dkg_simple_tdec(shares_num: u32, validators_num: u32) {
        let rng = &mut test_rng();

        let security_threshold = shares_num / 2 + 1;
        let (dkg, validator_keypairs) = setup_dealt_dkg_with_n_validators(
            security_threshold,
            shares_num,
            validators_num,
        );

        let public_key = dkg.public_key();
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            &public_key,
            rng,
        )
        .unwrap();

        let (_, _, shared_secret) = make_shared_secret_simple_tdec(
            &dkg,
            AAD,
            &ciphertext.header().unwrap(),
            validator_keypairs.as_slice(),
        );

        let plaintext = ferveo_tdec::decrypt_with_shared_secret(
            &ciphertext,
            AAD,
            &shared_secret,
            &dkg.pvss_params.g_inv(),
        )
        .unwrap();
        assert_eq!(plaintext, MSG);
    }

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn test_dkg_simple_tdec_precomputed(shares_num: u32, validators_num: u32) {
        let rng = &mut test_rng();

        // In precomputed variant, threshold must be equal to shares_num
        let security_threshold = shares_num;
        let (dkg, validator_keypairs) = setup_dealt_dkg_with_n_validators(
            security_threshold,
            shares_num,
            validators_num,
        );
        let public_key = dkg.public_key();
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            &public_key,
            rng,
        )
        .unwrap();

        let pvss_list = dkg.vss.values().cloned().collect::<Vec<_>>();
        let pvss_aggregated = aggregate(&pvss_list).unwrap();
        pvss_aggregated.verify_aggregation(&dkg).unwrap();
        let domain_points = dkg
            .domain
            .elements()
            .take(validator_keypairs.len())
            .collect::<Vec<_>>();

        let mut decryption_shares: Vec<DecryptionSharePrecomputed<E>> =
            validator_keypairs
                .iter()
                .map(|validator_keypair| {
                    let validator = dkg
                        .get_validator(&validator_keypair.public_key())
                        .unwrap();
                    pvss_aggregated
                        .make_decryption_share_simple_precomputed(
                            &ciphertext.header().unwrap(),
                            AAD,
                            &validator_keypair.decryption_key,
                            validator.share_index as usize,
                            &domain_points,
                            &dkg.pvss_params.g_inv(),
                        )
                        .unwrap()
                })
                .collect();
        decryption_shares.shuffle(rng);
        assert_eq!(domain_points.len(), decryption_shares.len());

        let shared_secret =
            ferveo_tdec::share_combine_precomputed::<E>(&decryption_shares);

        // Combination works, let's decrypt
        let plaintext = ferveo_tdec::decrypt_with_shared_secret(
            &ciphertext,
            AAD,
            &shared_secret,
            &dkg.pvss_params.g_inv(),
        )
        .unwrap();
        assert_eq!(plaintext, MSG);
    }

    #[test_case(4, 4; "number of validators equal to the number of shares")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn test_dkg_simple_tdec_share_verification(
        shares_num: u32,
        validators_num: u32,
    ) {
        let rng = &mut test_rng();
        let security_threshold = shares_num / 2 + 1;

        let (dkg, validator_keypairs) = setup_dealt_dkg_with_n_validators(
            security_threshold,
            shares_num,
            validators_num,
        );
        let public_key = dkg.public_key();
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            &public_key,
            rng,
        )
        .unwrap();

        let (pvss_aggregated, decryption_shares, _) =
            make_shared_secret_simple_tdec(
                &dkg,
                AAD,
                &ciphertext.header().unwrap(),
                validator_keypairs.as_slice(),
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

        let (dkg, validator_keypairs) =
            setup_dealt_dkg_with(SECURITY_THRESHOLD, SHARES_NUM);
        let public_key = &dkg.public_key();
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            public_key,
            rng,
        )
        .unwrap();

        // Create an initial shared secret
        let (_, _, old_shared_secret) = make_shared_secret_simple_tdec(
            &dkg,
            AAD,
            &ciphertext.header().unwrap(),
            validator_keypairs.as_slice(),
        );

        // Remove one participant from the contexts and all nested structure
        let removed_validator_addr =
            dkg.validators.keys().last().unwrap().clone();
        let mut remaining_validators = dkg.validators.clone();
        remaining_validators
            .remove(&removed_validator_addr)
            .unwrap();
        // dkg.vss.remove(&removed_validator_addr); // TODO: Test whether it makes any difference

        // Remember to remove one domain point too
        let mut domain_points = dkg.domain_points();
        domain_points.pop().unwrap();

        // Now, we're going to recover a new share at a random point,
        // and check that the shared secret is still the same.

        // Our random point:
        let x_r = Fr::rand(rng);

        // Each participant prepares an update for each other participant
        let share_updates = remaining_validators
            .keys()
            .map(|v_addr| {
                let deltas_i = prepare_share_updates_for_recovery::<E>(
                    &domain_points,
                    &dkg.pvss_params.h.into_affine(),
                    &x_r,
                    dkg.dkg_params.security_threshold() as usize,
                    rng,
                );
                (v_addr.clone(), deltas_i)
            })
            .collect::<HashMap<_, _>>();

        // Participants share updates and update their shares

        // Now, every participant separately:
        // TODO: Move this logic outside tests (see #162, #163)
        let updated_shares: Vec<_> = remaining_validators
            .values()
            .map(|validator| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| {
                        *updates.get(validator.share_index as usize).unwrap()
                    })
                    .collect();

                // Each validator uses their decryption key to update their share
                let decryption_key = validator_keypairs
                    .get(validator.share_index as usize)
                    .unwrap()
                    .decryption_key;

                // Creates updated private key shares
                // TODO: Why not using dkg.aggregate()?
                let pvss_list = dkg.vss.values().cloned().collect::<Vec<_>>();
                let pvss_aggregated = aggregate(&pvss_list).unwrap();
                pvss_aggregated
                    .update_private_key_share_for_recovery(
                        &decryption_key,
                        validator.share_index as usize,
                        updates_for_participant.as_slice(),
                    )
                    .unwrap()
            })
            .collect();

        // TODO: Rename updated_private_shares to something that doesn't imply mutation (see #162, #163)

        // Now, we have to combine new share fragments into a new share
        let new_private_key_share = recover_share_from_updated_private_shares(
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
                    // TODO: Why not using dkg.aggregate()?
                    let pvss_list =
                        dkg.vss.values().cloned().collect::<Vec<_>>();
                    let pvss_aggregated = aggregate(&pvss_list).unwrap();
                    pvss_aggregated
                        .make_decryption_share_simple(
                            &ciphertext.header().unwrap(),
                            AAD,
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
                AAD,
                &dkg.pvss_params.g_inv(),
            )
            .unwrap(),
        );

        domain_points.push(x_r);
        assert_eq!(domain_points.len(), SHARES_NUM as usize);
        assert_eq!(decryption_shares.len(), SHARES_NUM as usize);

        // Maybe parametrize this test with [1..] and [..threshold]
        let domain_points = &domain_points[1..];
        let decryption_shares = &decryption_shares[1..];
        assert_eq!(domain_points.len(), SECURITY_THRESHOLD as usize);
        assert_eq!(decryption_shares.len(), SECURITY_THRESHOLD as usize);

        let lagrange = ferveo_tdec::prepare_combine_simple::<E>(domain_points);
        let new_shared_secret = ferveo_tdec::share_combine_simple::<E>(
            decryption_shares,
            &lagrange,
        );

        assert_eq!(
            old_shared_secret, new_shared_secret,
            "Shared secret reconstruction failed"
        );
    }

    #[test]
    fn test_dkg_simple_tdec_share_refreshing() {
        let rng = &mut test_rng();

        let (dkg, validator_keypairs) =
            setup_dealt_dkg_with(SECURITY_THRESHOLD, SHARES_NUM);
        let public_key = &dkg.public_key();
        let ciphertext = ferveo_tdec::encrypt::<E>(
            SecretBox::new(MSG.to_vec()),
            AAD,
            public_key,
            rng,
        )
        .unwrap();

        // Create an initial shared secret
        let (_, _, old_shared_secret) = make_shared_secret_simple_tdec(
            &dkg,
            AAD,
            &ciphertext.header().unwrap(),
            validator_keypairs.as_slice(),
        );

        // Each participant prepares an update for each other participant
        let share_updates = dkg
            .validators
            .keys()
            .map(|v_addr| {
                let deltas_i = prepare_share_updates_for_refresh::<E>(
                    &dkg.domain_points(),
                    &dkg.pvss_params.h.into_affine(),
                    dkg.dkg_params.security_threshold() as usize,
                    rng,
                );
                (v_addr.clone(), deltas_i)
            })
            .collect::<HashMap<_, _>>();

        // Participants share updates and update their shares

        // Now, every participant separately:
        // TODO: Move this logic outside tests (see #162, #163)
        let updated_shares: Vec<_> = dkg
            .validators
            .values()
            .map(|validator| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| {
                        *updates.get(validator.share_index as usize).unwrap()
                    })
                    .collect();

                // Each validator uses their decryption key to update their share
                let decryption_key = validator_keypairs
                    .get(validator.share_index as usize)
                    .unwrap()
                    .decryption_key;

                // Creates updated private key shares
                // TODO: Why not using dkg.aggregate()?
                let pvss_list = dkg.vss.values().cloned().collect::<Vec<_>>();
                let pvss_aggregated = aggregate(&pvss_list).unwrap();
                pvss_aggregated
                    .update_private_key_share_for_recovery(
                        &decryption_key,
                        validator.share_index as usize,
                        updates_for_participant.as_slice(),
                    )
                    .unwrap()
            })
            .collect();

        // Get decryption shares, now with refreshed private shares:
        let decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(share_index, validator_keypair)| {
                    DecryptionShareSimple::create(
                        &validator_keypair.decryption_key,
                        updated_shares.get(share_index).unwrap(),
                        &ciphertext.header().unwrap(),
                        AAD,
                        &dkg.pvss_params.g_inv(),
                    )
                    .unwrap()
                })
                .collect();

        let lagrange = ferveo_tdec::prepare_combine_simple::<E>(
            &dkg.domain_points()[..SECURITY_THRESHOLD as usize],
        );
        let new_shared_secret = ferveo_tdec::share_combine_simple::<E>(
            &decryption_shares[..SECURITY_THRESHOLD as usize],
            &lagrange,
        );

        assert_eq!(old_shared_secret, new_shared_secret);
    }
}
