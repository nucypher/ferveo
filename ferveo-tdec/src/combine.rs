#![allow(non_snake_case)]

use ark_ec::pairing::Pairing;
use ark_ff::{Field, One, PrimeField, Zero};
use ferveo_common::serialization;
use itertools::izip;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct SharedSecret<E: Pairing>(
    #[serde_as(as = "serialization::SerdeAs")] pub(crate) E::TargetField,
);

use crate::{DecryptionSharePrecomputed, DecryptionShareSimple};

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

        // TODO: #197
        let mut lagrange_n_0 = domain.iter().product::<ScalarField>();
        if domain.len() % 2 == 1 {
            lagrange_n_0 = -lagrange_n_0;
        }
        let s = subproductdomain::SubproductDomain::<ScalarField>::new(domain);
        let mut lagrange = s.inverse_lagrange_coefficients();
        ark_ff::batch_inversion_and_mul(&mut lagrange, &lagrange_n_0);
    }
}
