#![warn(rust_2018_idioms)]

// TODO: Use explicit imports - #194
pub mod ciphertext;
pub mod combine;
pub mod context;
pub mod decryption;
pub mod hash_to_curve;
pub mod key_share;
pub mod secret_box;

// TODO: Only show the public API, tpke::api
// use ciphertext::*;
// use combine::*;
// use context::*;
// use decryption::*;
// use hash_to_curve::*;
// use key_share::*;
// use refresh::*;

pub use ciphertext::*;
pub use combine::*;
pub use context::*;
pub use decryption::*;
pub use hash_to_curve::*;
pub use key_share::*;
pub use secret_box::*;

#[cfg(feature = "api")]
pub mod api;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Ciphertext verification failed
    /// Refers to the check 4.4.2 in the paper: https://eprint.iacr.org/2022/898.pdf
    #[error("Ciphertext verification failed")]
    CiphertextVerificationFailed,

    /// Decryption share verification failed
    /// Refers to the check 4.4.4 in the paper: https://eprint.iacr.org/2022/898.pdf
    #[error("Decryption share verification failed")]
    DecryptionShareVerificationFailed,

    /// Symmetric encryption failed"
    #[error("Symmetric encryption failed")]
    SymmetricEncryptionError(chacha20poly1305::aead::Error),

    #[error(transparent)]
    BincodeError(#[from] bincode::Error),

    #[error(transparent)]
    ArkSerializeError(#[from] ark_serialize::SerializationError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Factory functions for testing
#[cfg(any(test, feature = "test-common"))]
pub mod test_common {
    use std::{ops::Mul, usize};

    pub use ark_bls12_381::Bls12_381 as EllipticCurve;
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    pub use ark_ff::UniformRand;
    use ark_ff::{Field, Zero};
    use ark_poly::{
        univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
        Polynomial,
    };
    use itertools::izip;
    use subproductdomain::fast_multiexp;

    pub use super::*;

    pub fn setup_simple<E: Pairing>(
        shares_num: usize,
        threshold: usize,
        rng: &mut impl rand::Rng,
    ) -> (
        DkgPublicKey<E>,
        PrivateKeyShare<E>,
        Vec<PrivateDecryptionContextSimple<E>>,
    ) {
        let g = E::G1Affine::generator();
        let h = E::G2Affine::generator();

        // The dealer chooses a uniformly random polynomial f of degree t-1
        let threshold_poly =
            DensePolynomial::<E::ScalarField>::rand(threshold - 1, rng);

        // Domain, or omega Ω
        let fft_domain =
            ark_poly::GeneralEvaluationDomain::<E::ScalarField>::new(
                shares_num,
            )
            .unwrap();

        // domain points: - ω_j in Ω
        let domain_points = fft_domain.elements().collect::<Vec<_>>();

        // `evals` are evaluations of the polynomial f over the domain, omega: f(ω_j) for ω_j in Ω
        let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

        // A_j, share commitments of participants:  [f(ω_j)] G
        let share_commitments = fast_multiexp(&evals.evals, g.into_group());

        // FIXME: These 2 lines don't make sense
        //let pubkey_share = g.mul(evals.evals[0]);
        //debug_assert!(share_commitments[0] == E::G1Affine::from(pubkey_share));

        // Z_j, private key shares of participants (unblinded): [f(ω_j)] H
        // NOTE: In production, these are never produced this way, as the DKG
        // directly generates blinded shares Y_j. Only then, node j can use their
        // validator key to unblind Y_j and obtain the private key share Z_j.
        let privkey_shares = fast_multiexp(&evals.evals, h.into_group());

        // The shared secret is the free coefficient from threshold poly
        let a_0 = threshold_poly.coeffs[0];

        // F_0, group's public key
        let group_pubkey = g.mul(a_0);

        // group's private key (NOTE: just for tests, this is NEVER constructed in production)
        let group_privkey = h.mul(a_0);

        // As in SSS, shared secret should be f(0), which is also the free coefficient
        let secret = threshold_poly.evaluate(&E::ScalarField::zero());
        debug_assert!(secret == a_0);

        let mut private_contexts = vec![];
        let mut public_contexts = vec![];

        // (domain_point, A, Z)
        for (index, (domain_point, share_commit, private_share)) in izip!(
            domain_points.iter(),
            share_commitments.iter(),
            privkey_shares.iter()
        )
        .enumerate()
        {
            let private_key_share = PrivateKeyShare::<E>(*private_share);
            let blinding_factor = E::ScalarField::rand(rng);

            let validator_public_key = h.mul(blinding_factor).into_affine();
            let blinded_key_share = BlindedKeyShare::<E> {
                validator_public_key,
                blinded_key_share: private_key_share
                    .0
                    .mul(blinding_factor)
                    .into_affine(),
            };

            private_contexts.push(PrivateDecryptionContextSimple::<E> {
                index,
                setup_params: SetupParams {
                    b: blinding_factor,
                    b_inv: blinding_factor.inverse().unwrap(),
                    g,
                    h_inv: E::G2Prepared::from(-h.into_group()),
                    g_inv: E::G1Prepared::from(-g.into_group()),
                    h,
                },
                private_key_share,
                public_decryption_contexts: vec![],
            });
            public_contexts.push(PublicDecryptionContextSimple::<E> {
                domain: *domain_point,
                share_commitment: ShareCommitment::<E>(*share_commit), // FIXME
                blinded_key_share,
                h,
                validator_public_key: blinded_key_share
                    .validator_public_key
                    .into_group(),
            });
        }
        for private_ctxt in private_contexts.iter_mut() {
            private_ctxt.public_decryption_contexts = public_contexts.clone();
        }

        (
            DkgPublicKey(group_pubkey.into()),
            PrivateKeyShare(group_privkey.into()), // TODO: Not the correct type, but whatever
            private_contexts,
        )
    }

    pub fn setup_precomputed<E: Pairing>(
        shares_num: usize,
        threshold: usize,
        rng: &mut impl rand::Rng,
    ) -> (
        DkgPublicKey<E>,
        PrivateKeyShare<E>,
        Vec<PrivateDecryptionContextSimple<E>>,
    ) {
        setup_simple::<E>(shares_num, threshold, rng)
    }

    pub fn create_shared_secret_simple<E: Pairing>(
        pub_contexts: &[PublicDecryptionContextSimple<E>],
        decryption_shares: &[DecryptionShareSimple<E>],
    ) -> SharedSecret<E> {
        let domain = pub_contexts.iter().map(|c| c.domain).collect::<Vec<_>>();
        let lagrange_coeffs = prepare_combine_simple::<E>(&domain);
        share_combine_simple::<E>(decryption_shares, &lagrange_coeffs)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Mul;

    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_std::{test_rng, UniformRand};
    use ferveo_common::{FromBytes, ToBytes};
    use rand::seq::IteratorRandom;

    use crate::{
        api::DecryptionSharePrecomputed,
        test_common::{create_shared_secret_simple, setup_simple, *},
    };

    type E = ark_bls12_381::Bls12_381;
    type TargetField = <E as Pairing>::TargetField;
    type ScalarField = <E as Pairing>::ScalarField;

    #[test]
    fn ciphertext_serialization() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, _) = setup_simple::<E>(threshold, shares_num, rng);

        let ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        let serialized = ciphertext.to_bytes().unwrap();
        let deserialized: Ciphertext<E> =
            Ciphertext::from_bytes(&serialized).unwrap();

        assert_eq!(serialized, deserialized.to_bytes().unwrap())
    }

    fn test_ciphertext_validation_fails<E: Pairing>(
        msg: &[u8],
        aad: &[u8],
        ciphertext: &Ciphertext<E>,
        shared_secret: &SharedSecret<E>,
        g_inv: &E::G1Prepared,
    ) {
        // So far, the ciphertext is valid
        let plaintext =
            decrypt_with_shared_secret(ciphertext, aad, shared_secret, g_inv)
                .unwrap();
        assert_eq!(plaintext, msg);

        // Malformed the ciphertext
        let mut ciphertext = ciphertext.clone();
        ciphertext.ciphertext[0] += 1;
        assert!(decrypt_with_shared_secret(
            &ciphertext,
            aad,
            shared_secret,
            g_inv,
        )
        .is_err());

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        assert!(decrypt_with_shared_secret(
            &ciphertext,
            aad,
            shared_secret,
            g_inv,
        )
        .is_err());
    }

    #[test]
    fn tdec_simple_variant_share_validation() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(shares_num, threshold, rng);
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        let bad_aad = "bad aad".as_bytes();
        assert!(contexts[0]
            .create_share(&ciphertext.header().unwrap(), bad_aad)
            .is_err());
    }

    #[test]
    fn tdec_simple_variant_e2e() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(shares_num, threshold, &mut rng);
        let g_inv = &contexts[0].setup_params.g_inv;

        let ciphertext =
            encrypt::<E>(SecretBox::new(msg.clone()), aad, &pubkey, rng)
                .unwrap();

        // We need at least threshold shares to decrypt
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|c| {
                c.create_share(&ciphertext.header().unwrap(), aad).unwrap()
            })
            .take(threshold)
            .collect();
        let selected_contexts =
            contexts[0].public_decryption_contexts[..threshold].to_vec();
        let shared_secret =
            create_shared_secret_simple(&selected_contexts, &decryption_shares);

        test_ciphertext_validation_fails(
            &msg,
            aad,
            &ciphertext,
            &shared_secret,
            g_inv,
        );

        // If we use less than threshold shares, we should fail
        let not_enough_dec_shares = decryption_shares[..threshold - 1].to_vec();
        let not_enough_contexts = selected_contexts[..threshold - 1].to_vec();
        let bash_shared_secret = create_shared_secret_simple(
            &not_enough_contexts,
            &not_enough_dec_shares,
        );
        let result = decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &bash_shared_secret,
            g_inv,
        );
        assert!(result.is_err());
    }

    #[test]
    fn tdec_precomputed_variant_e2e() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_precomputed::<E>(shares_num, threshold, &mut rng);
        let g_inv = &contexts[0].setup_params.g_inv;
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg.clone()), aad, &pubkey, rng)
                .unwrap();

        let selected_participants =
            (0..threshold).choose_multiple(rng, threshold);
        let selected_contexts = contexts
            .iter()
            .filter(|c| selected_participants.contains(&c.index))
            .cloned()
            .collect::<Vec<_>>();

        let decryption_shares = selected_contexts
            .iter()
            .map(|context| {
                context
                    .create_share_precomputed(
                        &ciphertext.header().unwrap(),
                        aad,
                        &selected_participants,
                    )
                    .unwrap()
            })
            .collect::<Vec<DecryptionSharePrecomputed>>();

        let shared_secret = share_combine_precomputed::<E>(&decryption_shares);
        test_ciphertext_validation_fails(
            &msg,
            aad,
            &ciphertext,
            &shared_secret,
            g_inv,
        );

        // If we use less than threshold shares, we should fail
        let not_enough_dec_shares = decryption_shares[..threshold - 1].to_vec();
        let bash_shared_secret =
            share_combine_precomputed(&not_enough_dec_shares);
        let result = decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &bash_shared_secret,
            g_inv,
        );
        assert!(result.is_err());
    }

    #[test]
    fn tdec_simple_variant_share_verification() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(shares_num, threshold, &mut rng);

        let ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|c| {
                c.create_share(&ciphertext.header().unwrap(), aad).unwrap()
            })
            .collect();

        // In simple tDec variant, we verify decryption shares only after decryption fails.
        // We could do that before, but we prefer to optimize for the happy path.

        // Let's assume that combination failed here. We'll try to verify decryption shares
        // against validator checksums.

        // There is no share aggregation in current version of tpke (it's mocked).
        // ShareEncryptions are called BlindedKeyShares.
        // TOOD: ^Fix this comment later

        let pub_contexts = &contexts[0].public_decryption_contexts;
        assert!(verify_decryption_shares_simple(
            pub_contexts,
            &ciphertext,
            &decryption_shares,
        ));

        // Now, let's test that verification fails if we one of the decryption shares is invalid.

        let mut has_bad_checksum = decryption_shares[0].clone();
        has_bad_checksum.validator_checksum.checksum = has_bad_checksum
            .validator_checksum
            .checksum
            .mul(ScalarField::rand(rng))
            .into_affine();

        assert!(!has_bad_checksum.verify(
            &pub_contexts[0].blinded_key_share.blinded_key_share,
            &pub_contexts[0].validator_public_key.into_affine(),
            &pub_contexts[0].h.into_group(),
            &ciphertext,
        ));

        let mut has_bad_share = decryption_shares[0].clone();
        has_bad_share.decryption_share =
            has_bad_share.decryption_share.mul(TargetField::rand(rng));

        assert!(!has_bad_share.verify(
            &pub_contexts[0].blinded_key_share.blinded_key_share,
            &pub_contexts[0].validator_public_key.into_affine(),
            &pub_contexts[0].h.into_group(),
            &ciphertext,
        ));
    }
}
