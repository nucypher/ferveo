#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::hash_to_curve::htp_bls12381_g2;
use ark_ec::{msm::FixedBaseMSM, AffineCurve, PairingEngine};
use ark_ff::{Field, One, PrimeField, ToBytes, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use ark_poly::{EvaluationDomain, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::izip;
use subproductdomain::SubproductDomain;

use rand_core::RngCore;
use std::usize;
use thiserror::Error;

mod ciphertext;
mod hash_to_curve;

pub use ciphertext::*;

mod key_share;

pub use key_share::*;

mod decryption;

pub use decryption::*;

mod combine;

pub use combine::*;

mod context;

pub use context::*;

// TODO: Turn into a crate features
pub mod api;
pub mod serialization;

pub trait ThresholdEncryptionParameters {
    type E: PairingEngine;
}

#[derive(Debug, Error)]
pub enum ThresholdEncryptionError {
    /// Error
    #[error("ciphertext verification failed")]
    CiphertextVerificationFailed,

    /// Error
    #[error("Decryption share verification failed")]
    DecryptionShareVerificationFailed,

    /// Hashing to curve failed
    #[error("Could not hash to curve")]
    HashToCurveError,

    #[error("plaintext verification failed")]
    PlaintextVerificationFailed,
}

fn hash_to_g2<T: ark_serialize::CanonicalDeserialize>(message: &[u8]) -> T {
    let mut point_ser: Vec<u8> = Vec::new();
    let point = htp_bls12381_g2(message);
    point.serialize(&mut point_ser).unwrap();
    T::deserialize(&point_ser[..]).unwrap()
}

fn construct_tag_hash<E: PairingEngine>(
    u: E::G1Affine,
    stream_ciphertext: &[u8],
    aad: &[u8],
) -> E::G2Affine {
    let mut hash_input = Vec::<u8>::new();
    u.write(&mut hash_input).unwrap();
    hash_input.extend_from_slice(stream_ciphertext);
    hash_input.extend_from_slice(aad);

    hash_to_g2(&hash_input)
}

pub fn setup<E: PairingEngine>(
    threshold: usize,
    shares_num: usize,
    rng: &mut impl RngCore,
) -> (E::G1Affine, E::G2Affine, Vec<PrivateDecryptionContext<E>>) {
    assert!(shares_num >= threshold);

    // Generators G∈G1, H∈G2
    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    // The dealer chooses a uniformly random polynomial f of degree t-1
    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);
    // Domain, or omega Ω
    let fft_domain =
        ark_poly::Radix2EvaluationDomain::<E::Fr>::new(shares_num).unwrap();
    // `evals` are evaluations of the polynomial f over the domain, omega: f(ω_j) for ω_j in Ω
    let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

    let mut domain_points = Vec::with_capacity(shares_num);
    let mut point = E::Fr::one();
    let mut domain_points_inv = Vec::with_capacity(shares_num);
    let mut point_inv = E::Fr::one();

    // domain_points are the powers of the generator g
    // domain_points_inv are the powers of the inverse of the generator g
    // It seems like domain points are being used in "share partitioning"
    // https://nikkolasg.github.io/ferveo/dkginit.html#share-partitioning
    // There's also a mention of this operation here:
    // "DKG.PartitionDomain({ek_i, s_i}) -> {(ek_i, Omega_i)}"
    // https://nikkolasg.github.io/ferveo/tpke-concrete.html
    for _ in 0..shares_num {
        // domain_points is the share domain of the i-th participant (?)
        domain_points.push(point); // 1, t, t^2, t^3, ...; where t is a scalar generator fft_domain.group_gen
        point *= fft_domain.group_gen;
        domain_points_inv.push(point_inv);
        point_inv *= fft_domain.group_gen_inv;
    }

    let window_size = FixedBaseMSM::get_mul_window_size(100);
    let scalar_bits = E::Fr::size_in_bits();

    // A - public key shares of participants
    let pubkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, g.into_projective());
    let pubkey_share = g.mul(evals.evals[0]);
    assert!(pubkey_shares[0] == E::G1Affine::from(pubkey_share));

    // Y, but only when b = 1 - private key shares of participants
    let privkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, h.into_projective());
    // h^{f(omega)}

    // a_0
    let x = threshold_poly.coeffs[0];

    // F_0 - The commitment to the constant term, and is the public key output Y from PVDKG
    // TODO: It seems like the rest of the F_i are not computed?
    let pubkey = g.mul(x);
    let privkey = h.mul(x); // ek_i in PVSS?

    let mut private_contexts = vec![];
    let mut public_contexts = vec![];

    // (domain, domain_inv, A, Y)
    for (index, (domain, domain_inv, public, private)) in izip!(
        // Since we're assigning only one key share to one entity we can use chunks(1)
        // This is a quick workaround to avoid refactoring all related entities that assume there are multiple key shares
        // TODO: Refactor this code and all related code
        domain_points.chunks(1),
        domain_points_inv.chunks(1),
        pubkey_shares.chunks(1),
        privkey_shares.chunks(1)
    )
    .enumerate()
    {
        let private_key_share = PrivateKeyShare::<E> {
            private_key_shares: private.to_vec(),
        };
        let b = E::Fr::one(); // TODO: Not blinding for now
        let mut blinded_key_shares = private_key_share.blind(b);
        blinded_key_shares.multiply_by_omega_inv(domain_inv);
        // TODO: Is `blinded_key_shares` equal to [b]Z_{i,omega_i})?
        // Z_{i,omega_i}) = [dk_{i}^{-1}]*\hat{Y}_{i_omega_j}]
        /*blinded_key_shares.window_tables =
        blinded_key_shares.get_window_table(window_size, scalar_bits, domain_inv);*/
        private_contexts.push(PrivateDecryptionContext::<E> {
            index,
            b,
            b_inv: b.inverse().unwrap(),
            private_key_share,
            public_decryption_contexts: vec![],
            g,
            g_inv: E::G1Prepared::from(-g),
            h_inv: E::G2Prepared::from(-h),
            scalar_bits,
            window_size,
        });
        public_contexts.push(PublicDecryptionContext::<E> {
            domain: domain.to_vec(),
            public_key_shares: PublicKeyShares::<E> {
                public_key_shares: public.to_vec(),
            },
            blinded_key_shares,
            lagrange_n_0: domain.iter().product::<E::Fr>(),
        });
    }
    for private in private_contexts.iter_mut() {
        private.public_decryption_contexts = public_contexts.clone();
    }

    (pubkey.into(), privkey.into(), private_contexts)
}

pub fn setup_simple<E: PairingEngine>(
    threshold: usize,
    shares_num: usize,
    rng: &mut impl RngCore,
) -> (
    E::G1Affine,
    E::G2Affine,
    Vec<PrivateDecryptionContextSimple<E>>,
) {
    assert!(shares_num >= threshold);

    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    // The delear chooses a uniformly random polynomial f of degree t-1
    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);
    // Domain, or omega Ω
    let fft_domain =
        ark_poly::Radix2EvaluationDomain::<E::Fr>::new(shares_num).unwrap();
    // `evals` are evaluations of the polynomial f over the domain, omega: f(ω_j) for ω_j in Ω
    let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

    let shares_x = fft_domain.elements().collect::<Vec<_>>();

    // A - public key shares of participants
    let pubkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, g.into_projective());
    let pubkey_share = g.mul(evals.evals[0]);
    assert!(pubkey_shares[0] == E::G1Affine::from(pubkey_share));

    // Y, but only when b = 1 - private key shares of participants
    // Z_i = h^{f(omega)} ?
    let privkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, h.into_projective());

    // a_0
    let x = threshold_poly.coeffs[0];
    // F_0
    // TODO: It seems like the rest of the F_i are not computed?
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    let secret = threshold_poly.evaluate(&E::Fr::zero());
    assert_eq!(secret, x);

    let mut private_contexts = vec![];
    let mut public_contexts = vec![];

    // (domain, A, Y)
    for (index, (domain, public, private)) in izip!(
        // Since we're assigning only one key share to one entity we can use chunks(1)
        // This is a quick workaround to avoid refactoring all related entities that assume there are multiple key shares
        // TODO: Refactor this code and all related code
        shares_x.chunks(1),
        pubkey_shares.chunks(1),
        privkey_shares.chunks(1)
    )
    .enumerate()
    {
        let private_key_share = PrivateKeyShare::<E> {
            private_key_shares: private.to_vec(),
        };
        // let b = E::Fr::rand(rng);
        let b = E::Fr::one(); // TODO: Not blinding for now
        let blinded_key_shares = private_key_share.blind(b);
        private_contexts.push(PrivateDecryptionContextSimple::<E> {
            index,
            b,
            b_inv: b.inverse().unwrap(),
            private_key_share,
            public_decryption_contexts: vec![],
            g,
            g_inv: E::G1Prepared::from(-g),
            h_inv: E::G2Prepared::from(-h),
            h, // TODO: Remove this sensitive data here
        });
        public_contexts.push(PublicDecryptionContextSimple::<E> {
            domain: domain[0],
            public_key_shares: PublicKeyShares::<E> {
                public_key_shares: public.to_vec(),
            },
            blinded_key_shares,
        });
    }
    for private in private_contexts.iter_mut() {
        private.public_decryption_contexts = public_contexts.clone();
    }

    // TODO: Should we also be returning some sort of signed transcript?
    // "Post the signed message \(\tau, (F_0, \ldots, F_t), \hat{u}2, (\hat{Y}{i,\omega_j})\) to the blockchain"
    // \tau - unique session identifier
    // See: https://nikkolasg.github.io/ferveo/pvss.html#dealers-role

    (pubkey.into(), privkey.into(), private_contexts)
}

pub fn generate_random<R: RngCore, E: PairingEngine>(
    n: usize,
    rng: &mut R,
) -> Vec<E::Fr> {
    (0..n).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use crate::*;
    use ark_bls12_381::Fr;
    use ark_ec::ProjectiveCurve;
    use ark_std::test_rng;

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn ciphertext_serialization() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 8;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "aad".as_bytes();

        let (pubkey, _privkey, _) = setup::<E>(threshold, shares_num, &mut rng);

        let ciphertext = encrypt::<ark_std::rand::rngs::StdRng, E>(
            msg, aad, &pubkey, &mut rng,
        );

        let serialized = ciphertext.to_bytes();
        let deserialized: Ciphertext<E> = Ciphertext::from_bytes(&serialized);

        assert_eq!(serialized, deserialized.to_bytes())
    }

    #[test]
    fn decryption_share_serialization() {
        let decryption_share = DecryptionShare::<E> {
            decrypter_index: 1,
            decryption_share: ark_bls12_381::G1Affine::prime_subgroup_generator(
            ),
        };

        let serialized = decryption_share.to_bytes();
        let deserialized: DecryptionShare<E> =
            DecryptionShare::from_bytes(&serialized);
        assert_eq!(serialized, deserialized.to_bytes())
    }

    #[test]
    fn symmetric_encryption() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 8;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, _) = setup::<E>(threshold, shares_num, &mut rng);

        let ciphertext = encrypt::<ark_std::rand::rngs::StdRng, E>(
            msg, aad, &pubkey, &mut rng,
        );
        let plaintext = checked_decrypt(&ciphertext, aad, privkey);

        assert_eq!(msg, plaintext)
    }

    // Source: https://stackoverflow.com/questions/26469715/how-do-i-write-a-rust-unit-test-that-ensures-that-a-panic-has-occurred
    // TODO: Remove after adding proper error handling to the library
    use std::{
        collections::HashMap,
        ops::{Add, AddAssign},
        panic,
    };
    fn catch_unwind_silent<F: FnOnce() -> R + panic::UnwindSafe, R>(
        f: F,
    ) -> std::thread::Result<R> {
        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(f);
        panic::set_hook(prev_hook);
        result
    }

    #[test]
    fn threshold_encryption() {
        let mut rng = &mut test_rng();
        let threshold = 16 * 2 / 3;
        let shares_num = 16;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _privkey, contexts) =
            setup::<E>(threshold, shares_num, &mut rng);
        let mut ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        let mut shares: Vec<DecryptionShare<E>> = vec![];
        for context in contexts.iter() {
            shares.push(context.create_share(&ciphertext));
        }

        /*for pub_context in contexts[0].public_decryption_contexts.iter() {
            assert!(pub_context
                .blinded_key_shares
                .verify_blinding(&pub_context.public_key_shares, rng));
        }*/
        let prepared_blinded_key_shares =
            prepare_combine(&contexts[0].public_decryption_contexts, &shares);
        let shared_secret =
            share_combine(&shares, &prepared_blinded_key_shares);

        // So far, the ciphertext is valid
        let plaintext = checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
        );
        assert_eq!(plaintext, msg);

        // Malformed the ciphertext
        ciphertext.ciphertext[0] += 1;
        let result = std::panic::catch_unwind(|| {
            checked_decrypt_with_shared_secret(&ciphertext, aad, &shared_secret)
        });
        assert!(result.is_err());

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        let result = std::panic::catch_unwind(|| {
            checked_decrypt_with_shared_secret(&ciphertext, aad, &shared_secret)
        });
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_validity_check() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 8;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _privkey, _) = setup::<E>(threshold, shares_num, &mut rng);
        let mut ciphertext = encrypt::<ark_std::rand::rngs::StdRng, E>(
            msg, aad, &pubkey, &mut rng,
        );

        // So far, the ciphertext is valid
        assert!(check_ciphertext_validity(&ciphertext, aad));

        // Malformed the ciphertext
        ciphertext.ciphertext[0] += 1;
        assert!(!check_ciphertext_validity(&ciphertext, aad));

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        assert!(!check_ciphertext_validity(&ciphertext, aad));
    }

    #[test]
    fn simple_threshold_decryption() {
        let mut rng = &mut test_rng();
        let threshold = 16 * 2 / 3;
        let shares_num = 16;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        // To be updated
        let (pubkey, _privkey, private_decryption_contexts) =
            setup_simple::<E>(threshold, shares_num, &mut rng);

        // Stays the same
        // Ciphertext.commitment is already computed to match U
        let mut ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        // Creating decryption shares
        let decryption_shares = private_decryption_contexts
            .iter()
            .map(|context| {
                let u = ciphertext.commitment;
                let z_i = context.private_key_share.clone();
                // Simplifying to just one key share per node
                assert_eq!(z_i.private_key_shares.len(), 1);
                let z_i = z_i.private_key_shares[0];
                // Really want to call E::pairing here to avoid heavy computations on client side
                // C_i = e(U, Z_i)
                // TODO: Check whether blinded key share fits here
                E::pairing(u, z_i)
            })
            .collect::<Vec<_>>();

        let shares_x = &private_decryption_contexts[0]
            .public_decryption_contexts
            .iter()
            .map(|ctxt| ctxt.domain)
            .collect::<Vec<_>>();
        let lagrange = prepare_combine_simple::<E>(shares_x);

        let shared_secret =
            share_combine_simple::<E>(&decryption_shares, &lagrange);

        // So far, the ciphertext is valid
        let plaintext = checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
        );
        assert_eq!(plaintext, msg);

        // Malformed the ciphertext
        ciphertext.ciphertext[0] += 1;
        let result = std::panic::catch_unwind(|| {
            checked_decrypt_with_shared_secret(&ciphertext, aad, &shared_secret)
        });
        assert!(result.is_err());

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        let result = std::panic::catch_unwind(|| {
            checked_decrypt_with_shared_secret(&ciphertext, aad, &shared_secret)
        });
        assert!(result.is_err());
    }

    fn make_decryption_shares<E: PairingEngine>(
        private_decryption_contexts: &Vec<PrivateDecryptionContextSimple<E>>,
        ciphertext: &Ciphertext<E>,
    ) -> Vec<DecryptionShareSimple<E>> {
        private_decryption_contexts
            .iter()
            .map(|context| {
                let u = ciphertext.commitment;
                let i = context.index;
                let z_i = context.private_key_share.clone();
                // Simplifying to just one key share per node
                assert_eq!(z_i.private_key_shares.len(), 1);
                let z_i = z_i.private_key_shares[0];
                // Really want to call E::pairing here to avoid heavy computations on client side
                // C_i = e(U, Z_i)
                let c_i = E::pairing(u, z_i); // TODO: Check whether blinded key share fits here
                DecryptionShareSimple {
                    decrypter_index: i,
                    decryption_share: c_i,
                }
            })
            .collect::<Vec<_>>()
    }

    #[test]
    fn simple_threshold_decryption_with_share_recovery() {
        let mut rng = &mut test_rng();
        let threshold = 16 * 2 / 3;
        let shares_num = 16;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _privkey, private_decryption_contexts, dealer_lagrange) =
            setup_simple::<E>(threshold, shares_num, &mut rng);

        let ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        let shares =
            make_decryption_shares(&private_decryption_contexts, &ciphertext);
        let lagrange = prepare_combine_simple(
            &private_decryption_contexts[0].public_decryption_contexts,
        );
        let s = share_combine_simple::<E>(&shares, &lagrange);

        let plaintext =
            checked_decrypt_with_shared_secret(&ciphertext, aad, &s);
        assert_eq!(plaintext, msg);

        // Refresh the shares

        // `private_decryption_contexts` represents set A of participants
        // B set of participants contains one participant
        // D = A\B
        let x_r = Fr::one();
        let original_y_r = &private_decryption_contexts[0].private_key_share;

        let remaining_participants = private_decryption_contexts[1..].to_vec();
        let new_shares = refresh_decryption_shares::<E>(
            &remaining_participants,
            &x_r,
            threshold,
            rng,
        );

        // TODO: Refresh lagrange coefficeints here?
        // let lagrange = prepare_combine_simple(
        //     &private_decryption_contexts[0].public_decryption_contexts,
        // );

        let s = share_combine_simple::<E>(&new_shares, &lagrange);

        // So far, the ciphertext is valid
        let plaintext =
            checked_decrypt_with_shared_secret(&ciphertext, aad, &s);
        assert_eq!(plaintext, msg);


    }

    fn refresh_decryption_shares<E: PairingEngine>(
        participants: &[PrivateDecryptionContextSimple<E>],
        x_r: &E::Fr,
        threshold: usize,
        rng: &mut impl RngCore,
    ) -> Vec<DecryptionShareSimple<E>> {
        let mut deltas: HashMap<usize, HashMap<usize, E::Fr>> = HashMap::new();
        for p1 in participants {
            let i = p1.index;
            let d_i = make_random_polynomial::<E>(threshold, x_r, rng);
            for p2 in participants {
                let j = p2.index;
                let x_j = p2.public_decryption_contexts[j].domain;
                if !deltas.contains_key(&i) {
                    deltas.insert(i, HashMap::new());
                }
                let eval = evaluate_polynomial::<E>(&d_i, &x_j);
                // TODO: Find a more efficient way keep track of those values
                let mut d = deltas.get(&i).unwrap().clone();
                d.insert(j, eval);
                deltas.insert(i, d);
            }
        }

        let mut new_shares: Vec<DecryptionShareSimple<E>> = Vec::new();
        for p in participants {
            let h_g2 = E::G2Projective::from(p.h);

            assert_eq!(p.private_key_share.private_key_shares.len(), 1);
            let i = p.index;
            let mut y_prime_i = E::G2Projective::from(
                p.private_key_share.private_key_shares[0],
            );
            for j in deltas.keys() {
                let delta_g2 = h_g2.mul(deltas[j][&i].into_repr());
                y_prime_i += delta_g2;
            }

            new_shares.push(DecryptionShareSimple {
                decrypter_index: i,
                // TODO: Is this a correct method to convert new y_prime_i to E::Fr?
                decryption_share: E::pairing(p.g, y_prime_i),
            });
        }
        new_shares
    }

    fn make_random_polynomial<E: PairingEngine>(
        threshold: usize,
        x_r: &E::Fr,
        rng: &mut impl RngCore,
    ) -> Vec<E::Fr> {
        let mut d_i = (0..threshold).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>();
        d_i.insert(0, E::Fr::zero());

        let d_i_at_x_r: E::Fr = evaluate_polynomial::<E>(&d_i, x_r);
        assert_eq!(d_i_at_x_r, E::Fr::zero());

        let d_i_0 = E::Fr::zero() - d_i_at_x_r;
        d_i[0] = d_i_0;
        d_i
    }

    fn evaluate_polynomial<E: PairingEngine>(
        polynomial: &[E::Fr],
        x: &E::Fr,
    ) -> E::Fr {
        let mut result = E::Fr::zero();
        let mut x_power = E::Fr::one();
        for coeff in polynomial {
            result += *coeff * x_power;
            x_power *= x;
        }
        result
    }
}
