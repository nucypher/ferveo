#![warn(rust_2018_idioms)]

pub mod ciphertext;
pub mod combine;
pub mod context;
pub mod decryption;
pub mod hash_to_curve;
pub mod key_share;
pub mod refresh;
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
pub use refresh::*;
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
        E::G1Affine,
        E::G2Affine,
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
            ark_poly::Radix2EvaluationDomain::<E::ScalarField>::new(shares_num)
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
            point *= fft_domain.group_gen;
            domain_points_inv.push(point_inv);
            point_inv *= fft_domain.group_gen_inv;
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
            let private_key_share = PrivateKeyShare::<E> {
                private_key_share: *private,
            };
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
                public_key_share: PublicKeyShare::<E> {
                    public_key_share: *public,
                },
                blinded_key_share: blinded_key_shares,
                lagrange_n_0: *domain,
                h_inv: E::G2Prepared::from(-h.into_group()),
            });
        }
        for private in private_contexts.iter_mut() {
            private.public_decryption_contexts = public_contexts.clone();
        }

        (pubkey.into(), privkey.into(), private_contexts)
    }

    pub fn setup_simple<E: Pairing>(
        threshold: usize,
        shares_num: usize,
        rng: &mut impl rand::Rng,
    ) -> (
        E::G1Affine,
        E::G2Affine,
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
            ark_poly::Radix2EvaluationDomain::<E::ScalarField>::new(shares_num)
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
            let private_key_share = PrivateKeyShare::<E> {
                private_key_share: *private,
            };
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
                validator_private_key: b,
                public_decryption_contexts: vec![],
            });
            public_contexts.push(PublicDecryptionContextSimple::<E> {
                domain: *domain,
                public_key_share: PublicKeyShare::<E> {
                    public_key_share: *public,
                },
                blinded_key_share,
                h,
                validator_public_key: h.mul(b),
            });
        }
        for private in private_contexts.iter_mut() {
            private.public_decryption_contexts = public_contexts.clone();
        }

        (pubkey.into(), privkey.into(), private_contexts)
    }

    pub fn setup_precomputed<E: Pairing>(
        shares_num: usize,
        rng: &mut impl rand::Rng,
    ) -> (
        E::G1Affine,
        E::G2Affine,
        Vec<PrivateDecryptionContextSimple<E>>,
    ) {
        // In precomputed variant, the security threshold is equal to the number of shares
        setup_simple::<E>(shares_num, shares_num, rng)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, ops::Mul};

    use ark_bls12_381::Fr;
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::{Field, Zero};
    use ark_std::{test_rng, UniformRand};
    use ferveo_common::{FromBytes, ToBytes};
    use itertools::zip_eq;
    use rand_core::RngCore;

    use crate::{
        refresh::{
            make_random_polynomial_at, prepare_share_updates_for_recovery,
            recover_share_from_updated_private_shares,
            refresh_private_key_share, update_share_for_recovery,
        },
        test_common::{setup_simple, *},
    };

    type E = ark_bls12_381::Bls12_381;
    type TargetField = <E as Pairing>::TargetField;
    type ScalarField = <E as Pairing>::ScalarField;

    fn make_shared_secret_from_contexts<E: Pairing>(
        contexts: &[PrivateDecryptionContextSimple<E>],
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
    ) -> SharedSecret<E> {
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|c| c.create_share(ciphertext, aad).unwrap())
            .collect();
        make_shared_secret(
            &contexts[0].public_decryption_contexts,
            &decryption_shares,
        )
    }

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

    fn make_new_share_fragments<R: RngCore>(
        rng: &mut R,
        threshold: usize,
        x_r: &Fr,
        remaining_participants: &[PrivateDecryptionContextSimple<E>],
    ) -> Vec<PrivateKeyShare<E>> {
        // Each participant prepares an update for each other participant
        let domain_points = remaining_participants[0]
            .public_decryption_contexts
            .iter()
            .map(|c| c.domain)
            .collect::<Vec<_>>();
        let h = remaining_participants[0].public_decryption_contexts[0].h;
        let share_updates = remaining_participants
            .iter()
            .map(|p| {
                let deltas_i = prepare_share_updates_for_recovery::<E>(
                    &domain_points,
                    &h,
                    x_r,
                    threshold,
                    rng,
                );
                (p.index, deltas_i)
            })
            .collect::<HashMap<_, _>>();

        // Participants share updates and update their shares
        let new_share_fragments: Vec<_> = remaining_participants
            .iter()
            .map(|p| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| *updates.get(p.index).unwrap())
                    .collect();

                // And updates their share
                update_share_for_recovery::<E>(
                    &p.private_key_share,
                    &updates_for_participant,
                )
            })
            .collect();

        new_share_fragments
    }

    fn make_shared_secret<E: Pairing>(
        pub_contexts: &[PublicDecryptionContextSimple<E>],
        decryption_shares: &[DecryptionShareSimple<E>],
    ) -> SharedSecret<E> {
        let domain = pub_contexts.iter().map(|c| c.domain).collect::<Vec<_>>();
        let lagrange_coeffs = prepare_combine_simple::<E>(&domain);
        share_combine_simple::<E>(decryption_shares, &lagrange_coeffs)
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
        assert!(contexts[0].create_share(&ciphertext, bad_aad).is_err());
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
            .map(|c| c.create_share(&ciphertext, aad).unwrap())
            .take(threshold)
            .collect();
        let pub_contexts =
            contexts[0].public_decryption_contexts[..threshold].to_vec();
        let shared_secret =
            make_shared_secret(&pub_contexts, &decryption_shares);

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
            make_shared_secret(&pub_contexts, &decryption_shares);

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
                context.create_share_precomputed(&ciphertext, aad).unwrap()
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
            .map(|c| c.create_share(&ciphertext, aad).unwrap())
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

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is intended to restore a previously existing share, e.g., due to loss or corruption.
    #[test]
    fn tdec_simple_variant_share_recovery_at_selected_point() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;

        let (_, _, mut contexts) =
            setup_simple::<E>(threshold, shares_num, rng);

        // Prepare participants

        // First, save the soon-to-be-removed participant
        let selected_participant = contexts.pop().unwrap();
        let x_r = selected_participant
            .public_decryption_contexts
            .last()
            .unwrap()
            .domain;
        let original_private_key_share = selected_participant.private_key_share;

        // Remove one participant from the contexts and all nested structures
        let mut remaining_participants = contexts;
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop().unwrap();
        }

        // Each participant prepares an update for each other participant, and uses it to create a new share fragment
        let new_share_fragments = make_new_share_fragments(
            rng,
            threshold,
            &x_r,
            &remaining_participants,
        );

        // Now, we have to combine new share fragments into a new share
        let domain_points = &remaining_participants[0]
            .public_decryption_contexts
            .iter()
            .map(|ctxt| ctxt.domain)
            .collect::<Vec<_>>();
        let new_private_key_share = recover_share_from_updated_private_shares(
            &x_r,
            domain_points,
            &new_share_fragments,
        );

        assert_eq!(new_private_key_share, original_private_key_share);
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is independent from the previously existing shares. We can use this to on-board a new participant into an existing cohort.
    #[test]
    fn tdec_simple_variant_share_recovery_at_random_point() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let g_inv = &contexts[0].setup_params.g_inv;
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        // Create an initial shared secret
        let old_shared_secret =
            make_shared_secret_from_contexts(&contexts, &ciphertext, aad);

        // Now, we're going to recover a new share at a random point and check that the shared secret is still the same

        // Our random point
        let x_r = ScalarField::rand(rng);

        // Remove one participant from the contexts and all nested structures
        let mut remaining_participants = contexts.clone();
        remaining_participants.pop().unwrap();
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop().unwrap();
        }

        let new_share_fragments = make_new_share_fragments(
            rng,
            threshold,
            &x_r,
            &remaining_participants,
        );

        // Now, we have to combine new share fragments into a new share
        let domain_points = &remaining_participants[0]
            .public_decryption_contexts
            .iter()
            .map(|ctxt| ctxt.domain)
            .collect::<Vec<_>>();
        let new_private_key_share = recover_share_from_updated_private_shares(
            &x_r,
            domain_points,
            &new_share_fragments,
        );

        // Get decryption shares from remaining participants
        let mut decryption_shares: Vec<_> = remaining_participants
            .iter()
            .map(|c| c.create_share(&ciphertext, aad).unwrap())
            .collect();

        // Create a decryption share from a recovered private key share
        let new_validator_decryption_key = ScalarField::rand(rng);
        decryption_shares.push(
            DecryptionShareSimple::create(
                &new_validator_decryption_key,
                &new_private_key_share,
                &ciphertext,
                aad,
                g_inv,
            )
            .unwrap(),
        );

        // Creating a shared secret from remaining shares and the recovered one
        let new_shared_secret = make_shared_secret(
            &remaining_participants[0].public_decryption_contexts,
            &decryption_shares,
        );

        assert_eq!(old_shared_secret, new_shared_secret);
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share refresh" algorithm.
    /// The output is M new shares (with M <= Ñ), with each of the M new shares substituting the
    /// original share (i.e., the original share is deleted).
    #[test]
    fn tdec_simple_variant_share_refreshing() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let g_inv = &contexts[0].setup_params.g_inv;
        let pub_contexts = contexts[0].public_decryption_contexts.clone();
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        // Create an initial shared secret
        let old_shared_secret =
            make_shared_secret_from_contexts(&contexts, &ciphertext, aad);

        // Now, we're going to refresh the shares and check that the shared secret is the same

        // Dealer computes a new random polynomial with constant term x_r
        let polynomial = make_random_polynomial_at::<E>(
            threshold,
            &ScalarField::zero(),
            rng,
        );

        // Dealer shares the polynomial with participants

        // Participants computes new decryption shares
        let new_decryption_shares: Vec<_> = contexts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                // Participant computes share updates and update their private key shares
                let private_key_share = refresh_private_key_share::<E>(
                    &p.setup_params.h.into_group(),
                    &p.public_decryption_contexts[i].domain,
                    &polynomial,
                    &p.private_key_share,
                );
                DecryptionShareSimple::create(
                    &p.validator_private_key,
                    &private_key_share,
                    &ciphertext,
                    aad,
                    g_inv,
                )
                .unwrap()
            })
            .collect();

        let new_shared_secret =
            make_shared_secret(&pub_contexts, &new_decryption_shares);

        assert_eq!(old_shared_secret, new_shared_secret);
    }

    #[test]
    fn tdec_precomputed_variant_pessimistic_case() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts_precomputed) =
            setup_precomputed::<E>(shares_num, &mut rng);
        let g_inv = &contexts_precomputed[0].setup_params.g_inv;
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg.clone()), aad, &pubkey, rng)
                .unwrap();

        // Some nodes didn't respond
        let missing_node_n = 2;

        let decryption_shares_precomputed: Vec<_> = contexts_precomputed
            .iter()
            .map(|context| {
                context.create_share_precomputed(&ciphertext, aad).unwrap()
            })
            .take(shares_num - missing_node_n)
            .collect::<Vec<_>>();

        // We need to run another round of setup recreate missing shares
        let (_, _, contexts_simple) =
            setup_simple::<E>(missing_node_n, missing_node_n, &mut rng);

        let decryption_shares_simple: Vec<_> = contexts_simple
            .iter()
            .map(|context| context.create_share(&ciphertext, aad).unwrap())
            .collect::<Vec<_>>();

        // Ok, now we are back to `share_num` number of shares. We can proceed with decryption

        // First, we need to prepare the lagrange coefficients to update the shares
        // We need to combine the domain points from both contexts
        let precomputed_domain_points = contexts_precomputed[0]
            .public_decryption_contexts
            .iter()
            .map(|c| c.domain)
            .take(shares_num - missing_node_n)
            .collect::<Vec<_>>();
        let simple_domain_points = contexts_simple[0]
            .public_decryption_contexts
            .iter()
            .map(|c| c.domain)
            .take(missing_node_n)
            .collect::<Vec<_>>();
        let all_domain_points = precomputed_domain_points
            .iter()
            .cloned()
            .chain(simple_domain_points.iter().cloned())
            .collect::<Vec<_>>();

        // These are the old L coefficients, they correspond to the precomputed shares
        let precomputed_lagrange_coeffs =
            prepare_combine_simple::<E>(&precomputed_domain_points);

        // These are the new L' coefficients, they correspond to both the precomputed and the simple shares
        let new_lagrange_coeffs =
            prepare_combine_simple::<E>(&all_domain_points);

        // Now, we update our shares
        // We're going to calculate share updates for both the precomputed and the simple shares

        // Update coefficients for precomputed shares
        let updated_lagrange_coeffs_initial = zip_eq(
            precomputed_lagrange_coeffs,
            new_lagrange_coeffs[0..shares_num - missing_node_n].to_vec(),
        )
        // L' / L
        .map(|(initial, combined)| combined / initial)
        .collect::<Vec<_>>();

        // For the simple shares, we can just use the new coefficients
        let simple_share_updates =
            new_lagrange_coeffs[shares_num - missing_node_n..].to_vec();

        // Finally, we can update the shares

        let updated_precomputed_shares = zip_eq(
            decryption_shares_precomputed,
            updated_lagrange_coeffs_initial,
        )
        .map(|(share, updated_lagrange_coeff)| {
            let mut updated_share = share;
            updated_share.decryption_share =
                updated_share.decryption_share.pow(updated_lagrange_coeff.0);
            updated_share
        })
        .collect::<Vec<_>>();
        let updated_simple_shares =
            zip_eq(decryption_shares_simple, simple_share_updates)
                .map(|(share, updated_coeffs)| {
                    let mut updated_share = share;
                    updated_share.decryption_share =
                        updated_share.decryption_share.pow(updated_coeffs.0);
                    updated_share
                })
                .collect::<Vec<_>>();

        // Now, we can combine the share to get the shared secret
        // We're going to cast precomputed shares into simple shares
        let combined_shares = updated_precomputed_shares
            .iter()
            .map(|s| s.to_simple())
            .chain(updated_simple_shares.iter().cloned())
            .collect::<Vec<_>>();
        let shared_secret = share_combine_simple_updated::<E>(&combined_shares);

        test_ciphertext_validation_fails(
            &msg,
            aad,
            &ciphertext,
            &shared_secret,
            g_inv,
        );

        // TODO: Sort out this error case

        // Note that in this variant, if we use less than `share_num` shares, we will get a
        // decryption error.

        // let not_enough_shares =
        //     &decryption_shares_precomputed[0..shares_num - 1];
        // let bad_shared_secret =
        //     share_combine_precomputed::<E>(not_enough_shares);
        // assert!(decrypt_with_shared_secret(
        //     &ciphertext,
        //     aad,
        //     &bad_shared_secret,
        //     g_inv,
        // )
        //     .is_err());
    }
}
