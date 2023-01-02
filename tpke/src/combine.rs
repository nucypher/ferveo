#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::*;
use ark_ec::ProjectiveCurve;

pub fn prepare_combine<E: PairingEngine>(
    public_decryption_contexts: &[PublicDecryptionContext<E>],
    shares: &[DecryptionShare<E>],
) -> Vec<E::G2Prepared> {
    let mut domain = vec![]; // omega_i, vector of domain points
    let mut n_0 = E::Fr::one();
    for d_i in shares.iter() {
        // There's just one domain point per participant, TODO: Refactor underlying data structures
        assert_eq!(
            public_decryption_contexts[d_i.decrypter_index].domain.len(),
            1
        );
        domain.push(public_decryption_contexts[d_i.decrypter_index].domain[0]);
        n_0 *= public_decryption_contexts[d_i.decrypter_index].lagrange_n_0; // n_0_i = 1 * t^1 * t^2 ...
    }
    let s = SubproductDomain::<E::Fr>::new(domain);
    let mut lagrange = s.inverse_lagrange_coefficients(); // 1/L_i
                                                          // TODO: If this is really 1/L_i can I just return here and use it directly? Or is 1/L_i somehow different from L_i(0)?
                                                          // Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}
    ark_ff::batch_inversion_and_mul(&mut lagrange, &n_0); // n_0 * L_i
                                                          // L_i * [b]Z_i
    izip!(shares.iter(), lagrange.iter())
        .map(|(d_i, lambda)| {
            let decrypter = &public_decryption_contexts[d_i.decrypter_index];
            // There's just one share per participant, TODO: Refactor underlying data structures
            assert_eq!(
                decrypter.blinded_key_shares.blinded_key_shares.len(),
                1
            );
            let blinded_key_share =
                decrypter.blinded_key_shares.blinded_key_shares[0];
            E::G2Prepared::from(
                // [b]Z_i * L_i
                blinded_key_share.mul(*lambda).into_affine(),
            )
        })
        .collect::<Vec<_>>()
}

pub fn prepare_combine_simple<E: PairingEngine>(
    shares_x: &[E::Fr],
) -> Vec<E::Fr> {
    // Calculate lagrange coefficients using optimized formula, see https://en.wikipedia.org/wiki/Lagrange_polynomial#Optimal_algorithm
    // In this formula x_i = 0, hence numerator is x_m
    lagrange_basis_at::<E>(shares_x, &E::Fr::zero())
}

/// Calculates Lagrange coefficients for a given x_i
pub fn lagrange_basis_at<E: PairingEngine>(
    shares_x: &[E::Fr],
    x_i: &E::Fr,
) -> Vec<E::Fr> {
    shares_x
        .iter()
        .map(|x_j| {
            let mut prod = E::Fr::one();
            shares_x.iter().for_each(|x_m| {
                if x_j != x_m {
                    prod *= (*x_m - x_i) / (*x_m - *x_j);
                }
            });
            prod
        })
        .collect()
}

pub fn share_combine<E: PairingEngine>(
    shares: &[DecryptionShare<E>],
    prepared_key_shares: &[E::G2Prepared],
) -> E::Fqk {
    let mut pairing_product: Vec<(E::G1Prepared, E::G2Prepared)> = vec![];

    for (d_i, prepared_key_share) in izip!(shares, prepared_key_shares.iter()) {
        // e(D_i, [b*omega_i^-1] Z_{i,omega_i}), TODO: Is this formula correct?
        pairing_product.push((
            // D_i
            E::G1Prepared::from(d_i.decryption_share),
            // Z_{i,omega_i}) = [dk_{i}^{-1}]*\hat{Y}_{i_omega_j}]
            // Reference: https://nikkolasg.github.io/ferveo/pvss.html#validator-decryption-of-private-key-shares
            // Prepared key share is a sum of L_i * [b]Z_i
            prepared_key_share.clone(),
        ));
    }
    E::product_of_pairings(&pairing_product)
}

pub fn share_combine_simple<E: PairingEngine>(
    shares: &[E::Fqk],
    lagrange_coeffs: &[E::Fr],
) -> E::Fqk {
    let mut product_of_shares = E::Fqk::one();

    // Sum of C_i^{L_i}z
    for (c_i, alpha_i) in izip!(shares, lagrange_coeffs) {
        // Exponentiation by alpha_i
        let ss = c_i.pow(alpha_i.into_repr());
        product_of_shares *= ss;
    }

    product_of_shares
}

#[cfg(test)]
mod tests {
    type Fr = <ark_bls12_381::Bls12_381 as ark_ec::PairingEngine>::Fr;

    #[test]
    fn test_lagrange() {
        use ark_poly::EvaluationDomain;
        use ark_std::One;
        let fft_domain =
            ark_poly::Radix2EvaluationDomain::<Fr>::new(500).unwrap();

        let mut domain = Vec::with_capacity(500);
        let mut point = Fr::one();
        for _ in 0..500 {
            domain.push(point);
            point *= fft_domain.group_gen;
        }

        let mut lagrange_n_0 = domain.iter().product::<Fr>();
        if domain.len() % 2 == 1 {
            lagrange_n_0 = -lagrange_n_0;
        }
        let s = subproductdomain::SubproductDomain::<Fr>::new(domain);
        let mut lagrange = s.inverse_lagrange_coefficients();
        ark_ff::batch_inversion_and_mul(&mut lagrange, &lagrange_n_0);
    }
}
