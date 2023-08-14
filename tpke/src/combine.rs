use std::ops::Mul;

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{Field, One, PrimeField, Zero};
use ferveo_common::serialization;
use itertools::izip;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use subproductdomain::SubproductDomain;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    verify_decryption_shares_fast, Ciphertext, DecryptionShareFast,
    DecryptionSharePrecomputed, DecryptionShareSimple, Error,
    PublicDecryptionContextFast, Result,
};

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct SharedSecret<E: Pairing>(
    #[serde_as(as = "serialization::SerdeAs")] pub(crate) E::TargetField,
);

pub fn prepare_combine_fast<E: Pairing>(
    public_decryption_contexts: &[PublicDecryptionContextFast<E>],
    shares: &[DecryptionShareFast<E>],
) -> Vec<E::G2Prepared> {
    let mut domain = vec![]; // omega_i, vector of domain points
    let mut n_0 = E::ScalarField::one();
    for d_i in shares.iter() {
        domain.push(public_decryption_contexts[d_i.decrypter_index].domain);
        // n_0_i = 1 * t^1 * t^2 ...
        n_0 *= public_decryption_contexts[d_i.decrypter_index].lagrange_n_0;
    }
    let s = SubproductDomain::<E::ScalarField>::new(domain);
    let mut lagrange = s.inverse_lagrange_coefficients(); // 1/L_i

    // Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}
    ark_ff::batch_inversion_and_mul(&mut lagrange, &n_0); // n_0 * L_i

    // L_i * [b]Z_i
    izip!(shares.iter(), lagrange.iter())
        .map(|(d_i, lambda)| {
            let decrypter = &public_decryption_contexts[d_i.decrypter_index];
            let blinded_key_share =
                decrypter.blinded_key_share.blinded_key_share;
            E::G2Prepared::from(
                // [b]Z_i * L_i
                blinded_key_share.mul(*lambda).into_affine(),
            )
        })
        .collect::<Vec<_>>()
}

pub fn prepare_combine_simple<E: Pairing>(
    domain: &[E::ScalarField],
) -> Vec<E::ScalarField> {
    // In this formula x_i = 0, hence numerator is x_m
    // See https://en.wikipedia.org/wiki/Lagrange_polynomial#Optimal_algorithm
    lagrange_basis_at::<E>(domain, &E::ScalarField::zero())
}

/// Calculate lagrange coefficients using optimized formula
pub fn lagrange_basis_at<E: Pairing>(
    shares_x: &[E::ScalarField],
    x_i: &E::ScalarField,
) -> Vec<<E>::ScalarField> {
    let mut lagrange_coeffs = vec![];
    for x_j in shares_x {
        let mut prod = E::ScalarField::one();
        for x_m in shares_x {
            if x_j != x_m {
                prod *= (*x_m - x_i) / (*x_m - *x_j);
            }
        }
        lagrange_coeffs.push(prod);
    }
    lagrange_coeffs
}

// TODO: Hide this from external users. Currently blocked by usage in benchmarks.
pub fn share_combine_fast_unchecked<E: Pairing>(
    shares: &[DecryptionShareFast<E>],
    prepared_key_shares: &[E::G2Prepared],
) -> SharedSecret<E> {
    let mut pairing_a = vec![];
    let mut pairing_b = vec![];

    for (d_i, prepared_key_share) in izip!(shares, prepared_key_shares.iter()) {
        pairing_a.push(
            // D_i
            E::G1Prepared::from(d_i.decryption_share),
        );
        pairing_b.push(
            // Z_{i,omega_i}) = [dk_{i}^{-1}]*\hat{Y}_{i_omega_j}]
            // Reference: https://nikkolasg.github.io/ferveo/pvss.html#validator-decryption-of-private-key-shares
            // Prepared key share is a sum of L_i * [b]Z_i
            prepared_key_share.clone(),
        );
    }
    // e(D_i, [b*omega_i^-1] Z_{i,omega_i})
    let shared_secret = E::multi_pairing(pairing_a, pairing_b).0;
    SharedSecret(shared_secret)
}

pub fn share_combine_fast<E: Pairing>(
    pub_contexts: &[PublicDecryptionContextFast<E>],
    ciphertext: &Ciphertext<E>,
    decryption_shares: &[DecryptionShareFast<E>],
    prepared_key_shares: &[E::G2Prepared],
) -> Result<SharedSecret<E>> {
    let is_valid_shares = verify_decryption_shares_fast(
        pub_contexts,
        ciphertext,
        decryption_shares,
    );
    if !is_valid_shares {
        return Err(Error::DecryptionShareVerificationFailed);
    }
    Ok(share_combine_fast_unchecked(
        decryption_shares,
        prepared_key_shares,
    ))
}

pub fn share_combine_simple<E: Pairing>(
    decryption_shares: &[DecryptionShareSimple<E>],
    lagrange_coeffs: &[E::ScalarField],
) -> SharedSecret<E> {
    // Sum of C_i^{L_i}z
    let shared_secret = izip!(decryption_shares, lagrange_coeffs).fold(
        E::TargetField::one(),
        |acc, (c_i, alpha_i)| {
            acc * c_i.decryption_share.pow(alpha_i.into_bigint())
        },
    );
    SharedSecret(shared_secret)
}

pub fn share_combine_simple_updated<E: Pairing>(
    decryption_shares: &[DecryptionShareSimple<E>],
) -> SharedSecret<E> {
    let shared_secret = decryption_shares
        .iter()
        .fold(E::TargetField::one(), |acc, c_i| acc * c_i.decryption_share);
    SharedSecret(shared_secret)
}

pub fn share_combine_precomputed<E: Pairing>(
    shares: &[DecryptionSharePrecomputed<E>],
) -> SharedSecret<E> {
    // s = ∏ C_{λ_i}, where λ_i is the Lagrange coefficient for i
    let shared_secret = shares
        .iter()
        .fold(E::TargetField::one(), |acc, c_i| acc * c_i.decryption_share);
    SharedSecret(shared_secret)
}

#[cfg(test)]
mod tests {
    type ScalarField =
        <ark_bls12_381::Bls12_381 as ark_ec::pairing::Pairing>::ScalarField;

    #[test]
    fn test_lagrange() {
        use ark_poly::EvaluationDomain;
        use ark_std::One;
        let fft_domain =
            ark_poly::GeneralEvaluationDomain::<ScalarField>::new(500).unwrap();

        let mut domain = Vec::with_capacity(500);
        let mut point = ScalarField::one();
        for _ in 0..500 {
            domain.push(point);
            point *= fft_domain.group_gen();
        }

        let mut lagrange_n_0 = domain.iter().product::<ScalarField>();
        if domain.len() % 2 == 1 {
            lagrange_n_0 = -lagrange_n_0;
        }
        let s = subproductdomain::SubproductDomain::<ScalarField>::new(domain);
        let mut lagrange = s.inverse_lagrange_coefficients();
        ark_ff::batch_inversion_and_mul(&mut lagrange, &lagrange_n_0);
    }
}
