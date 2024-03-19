#![warn(rust_2018_idioms)]

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
    use ark_ec::{pairing::Pairing, AffineRepr};
    pub use ark_ff::UniformRand;
    use ark_ff::{Field, One, Zero};
    use ark_poly::{
        univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
        Polynomial,
    };
    use itertools::izip;
    use rand_core::RngCore;
    use subproductdomain::fast_multiexp;

    pub use super::*;

    pub fn setup_fast<E: Pairing>(
        threshold: usize,
        shares_num: usize,
        rng: &mut impl RngCore,
    ) -> (
        PublicKey<E>,
        PrivateKeyShare<E>,
        Vec<PrivateDecryptionContextFast<E>>,
    ) {
        assert!(shares_num >= threshold);

        // Generators G∈G1, H∈G2
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
        // `evals` are evaluations of the polynomial f over the domain, omega: f(ω_j) for ω_j in Ω
        let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

        // A - public key shares of participants
        let pubkey_shares = fast_multiexp(&evals.evals, g.into_group());
        let pubkey_share = g.mul(evals.evals[0]);
        debug_assert!(pubkey_shares[0] == E::G1Affine::from(pubkey_share));

        // Y, but only when b = 1 - private key shares of participants
        let privkey_shares = fast_multiexp(&evals.evals, h.into_group());

        // a_0
        let x = threshold_poly.coeffs[0];

        // F_0 - The commitment to the constant term, and is the public key output Y from PVDKG
        let pubkey = g.mul(x);
        let privkey = h.mul(x);

        let mut domain_points = Vec::with_capacity(shares_num);
        let mut point = E::ScalarField::one();
        let mut domain_points_inv = Vec::with_capacity(shares_num);
        let mut point_inv = E::ScalarField::one();

        for _ in 0..shares_num {
            domain_points.push(point); // 1, t, t^2, t^3, ...; where t is a scalar generator fft_domain.group_gen
            point *= fft_domain.group_gen();
            domain_points_inv.push(point_inv);
            point_inv *= fft_domain.group_gen_inv();
        }

        let mut private_contexts = vec![];
        let mut public_contexts = vec![];

        // (domain, domain_inv, A, Y)
        for (index, (domain, domain_inv, public, private)) in izip!(
            domain_points.iter(),
            domain_points_inv.iter(),
            pubkey_shares.iter(),
            privkey_shares.iter()
        )
        .enumerate()
        {
            let private_key_share = PrivateKeyShare(*private);
            let b = E::ScalarField::rand(rng);
            let mut blinded_key_shares = private_key_share.blind(b);
            blinded_key_shares.multiply_by_omega_inv(domain_inv);
            private_contexts.push(PrivateDecryptionContextFast::<E> {
                index,
                setup_params: SetupParams {
                    b,
                    b_inv: b.inverse().unwrap(),
                    g,
                    h_inv: E::G2Prepared::from(-h.into_group()),
                    g_inv: E::G1Prepared::from(-g.into_group()),
                    h,
                },
                private_key_share,
                public_decryption_contexts: vec![],
            });
            public_contexts.push(PublicDecryptionContextFast::<E> {
                domain: *domain,
                public_key: PublicKey::<E>(*public),
                blinded_key_share: blinded_key_shares,
                lagrange_n_0: *domain,
                h_inv: E::G2Prepared::from(-h.into_group()),
            });
        }
        for private in private_contexts.iter_mut() {
            private.public_decryption_contexts = public_contexts.clone();
        }

        (
            PublicKey(pubkey.into()),
            PrivateKeyShare(privkey.into()),
            private_contexts,
        )
    }

    pub fn setup_simple<E: Pairing>(
        threshold: usize,
        shares_num: usize,
        rng: &mut impl rand::Rng,
    ) -> (
        PublicKey<E>,
        PrivateKeyShare<E>,
        Vec<PrivateDecryptionContextSimple<E>>,
    ) {
        assert!(shares_num >= threshold);

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
        // `evals` are evaluations of the polynomial f over the domain, omega: f(ω_j) for ω_j in Ω
        let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

        let shares_x = fft_domain.elements().collect::<Vec<_>>();

        // A - public key shares of participants
        let pubkey_shares = fast_multiexp(&evals.evals, g.into_group());
        let pubkey_share = g.mul(evals.evals[0]);
        debug_assert!(pubkey_shares[0] == E::G1Affine::from(pubkey_share));

        // Y, but only when b = 1 - private key shares of participants
        let privkey_shares = fast_multiexp(&evals.evals, h.into_group());

        // a_0
        let x = threshold_poly.coeffs[0];
        // F_0
        let pubkey = g.mul(x);
        let privkey = h.mul(x);

        let secret = threshold_poly.evaluate(&E::ScalarField::zero());
        debug_assert!(secret == x);

        let mut private_contexts = vec![];
        let mut public_contexts = vec![];

        // (domain, A, Y)
        for (index, (domain, public, private)) in
            izip!(shares_x.iter(), pubkey_shares.iter(), privkey_shares.iter())
                .enumerate()
        {
            let private_key_share = PrivateKeyShare::<E>(*private);
            let b = E::ScalarField::rand(rng);
            let blinded_key_share = private_key_share.blind(b);
            private_contexts.push(PrivateDecryptionContextSimple::<E> {
                index,
                setup_params: SetupParams {
                    b,
                    b_inv: b.inverse().unwrap(),
                    g,
                    h_inv: E::G2Prepared::from(-h.into_group()),
                    g_inv: E::G1Prepared::from(-g.into_group()),
                    h,
                },
                private_key_share,
                public_decryption_contexts: vec![],
            });
            public_contexts.push(PublicDecryptionContextSimple::<E> {
                domain: *domain,
                public_key: PublicKey::<E>(*public),
                blinded_key_share,
                h,
                validator_public_key: h.mul(b),
            });
        }
        for private in private_contexts.iter_mut() {
            private.public_decryption_contexts = public_contexts.clone();
        }

        (
            PublicKey(pubkey.into()),
            PrivateKeyShare(privkey.into()),
            private_contexts,
        )
    }

    pub fn setup_precomputed<E: Pairing>(
        shares_num: usize,
        rng: &mut impl rand::Rng,
    ) -> (
        PublicKey<E>,
        PrivateKeyShare<E>,
        Vec<PrivateDecryptionContextSimple<E>>,
    ) {
        // In precomputed variant, the security threshold is equal to the number of shares
        setup_simple::<E>(shares_num, shares_num, rng)
    }

    pub fn create_shared_secret<E: Pairing>(
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

    use crate::test_common::{create_shared_secret, setup_simple, *};

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

        let (pubkey, _, _) = setup_fast::<E>(threshold, shares_num, rng);

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
    fn tdec_fast_variant_share_validation() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) = setup_fast::<E>(threshold, shares_num, rng);
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        let bad_aad = "bad aad".as_bytes();
        assert!(contexts[0].create_share(&ciphertext, bad_aad).is_err());
    }

    #[test]
    fn tdec_simple_variant_share_validation() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        let bad_aad = "bad aad".as_bytes();
        assert!(contexts[0]
            .create_share(&ciphertext.header().unwrap(), bad_aad)
            .is_err());
    }

    #[test]
    fn tdec_fast_variant_e2e() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_fast::<E>(threshold, shares_num, &mut rng);
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg.clone()), aad, &pubkey, rng)
                .unwrap();
        let g_inv = &contexts[0].setup_params.g_inv;

        let mut decryption_shares: Vec<DecryptionShareFast<E>> = vec![];
        for context in contexts.iter() {
            decryption_shares
                .push(context.create_share(&ciphertext, aad).unwrap());
        }

        // TODO: Verify and enable this check
        /*for pub_context in contexts[0].public_decryption_contexts.iter() {
            assert!(pub_context
                .blinded_key_shares
                .verify_blinding(&pub_context.public_key_shares, rng));
        }*/

        let prepared_blinded_key_shares = prepare_combine_fast(
            &contexts[0].public_decryption_contexts,
            &decryption_shares,
        );

        let shared_secret = share_combine_fast(
            &contexts[0].public_decryption_contexts,
            &ciphertext,
            &decryption_shares,
            &prepared_blinded_key_shares,
        )
        .unwrap();

        test_ciphertext_validation_fails(
            &msg,
            aad,
            &ciphertext,
            &shared_secret,
            g_inv,
        );
    }

    #[test]
    fn tdec_simple_variant_e2e() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, &mut rng);
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
        let pub_contexts =
            contexts[0].public_decryption_contexts[..threshold].to_vec();
        let shared_secret =
            create_shared_secret(&pub_contexts, &decryption_shares);

        test_ciphertext_validation_fails(
            &msg,
            aad,
            &ciphertext,
            &shared_secret,
            g_inv,
        );

        // If we use less than threshold shares, we should fail
        let decryption_shares = decryption_shares[..threshold - 1].to_vec();
        let pub_contexts = pub_contexts[..threshold - 1].to_vec();
        let shared_secret =
            create_shared_secret(&pub_contexts, &decryption_shares);

        let result =
            decrypt_with_shared_secret(&ciphertext, aad, &shared_secret, g_inv);
        assert!(result.is_err());
    }

    #[test]
    fn tdec_precomputed_variant_e2e() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_precomputed::<E>(shares_num, &mut rng);
        let g_inv = &contexts[0].setup_params.g_inv;
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg.clone()), aad, &pubkey, rng)
                .unwrap();

        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|context| {
                context
                    .create_share_precomputed(
                        &ciphertext.header().unwrap(),
                        aad,
                    )
                    .unwrap()
            })
            .collect();

        let shared_secret = share_combine_precomputed::<E>(&decryption_shares);

        test_ciphertext_validation_fails(
            &msg,
            aad,
            &ciphertext,
            &shared_secret,
            g_inv,
        );

        // Note that in this variant, if we use less than `share_num` shares, we will get a
        // decryption error.

        let not_enough_shares = &decryption_shares[0..shares_num - 1];
        let bad_shared_secret =
            share_combine_precomputed::<E>(not_enough_shares);
        assert!(decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &bad_shared_secret,
            g_inv,
        )
        .is_err());
    }

    #[test]
    fn tdec_simple_variant_share_verification() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, &mut rng);

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
