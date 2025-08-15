use std::{collections::HashMap, ops::Mul};

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Field;
use ferveo_common::{serialization, Keypair};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    prepare_combine_simple, CiphertextHeader, DecryptionSharePrecomputed,
    DecryptionShareSimple, DomainPoint, Result,
};

#[serde_as]
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DkgPublicKey<E: Pairing>(
    #[serde_as(as = "serialization::SerdeAs")] pub E::G1Affine,
);

#[serde_as]
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareCommitment<E: Pairing>(
    #[serde_as(as = "serialization::SerdeAs")] pub E::G1Affine, // A_{i, \omega_i}
);

// TODO: Improve by adding share commitment here
// TODO: Is this a test utility perhaps?
#[derive(Debug, Copy, Clone)]
pub struct BlindedKeyShare<E: Pairing> {
    pub validator_public_key: E::G2Affine, // [b] H
    pub blinded_key_share: E::G2Affine,    // [b] Z_{i, \omega_i}
}

impl<E: Pairing> BlindedKeyShare<E> {
    // TODO: Salvage and cleanup - #197
    // pub fn verify_blinding<R: RngCore>(
    //     &self,
    //     public_key: &PublicKey<E>,
    //     rng: &mut R,
    // ) -> bool {
    //     let g = E::G1Affine::generator();
    //     let alpha = E::ScalarField::rand(rng);

    //     let alpha_a =
    //         E::G1Prepared::from(g + public_key.0.mul(alpha).into_affine());

    //     // \sum_i(Y_i)
    //     let alpha_z = E::G2Prepared::from(
    //         self.blinding_key + self.blinded_key_share.mul(alpha).into_affine(),
    //     );

    //     // e(g, Yi) == e(Ai, [b] H)
    //     let g_inv = E::G1Prepared::from(-g.into_group());
    //     E::multi_pairing([g_inv, alpha_a], [alpha_z, self.blinding_key.into()])
    //         .0
    //         == E::TargetField::one()
    // }

    // pub fn multiply_by_omega_inv(&mut self, omega_inv: &E::ScalarField) {
    //     self.blinded_key_share =
    //         self.blinded_key_share.mul(-*omega_inv).into_affine();
    // }
    pub fn unblind(
        &self,
        validator_keypair: &Keypair<E>,
    ) -> Result<PrivateKeyShare<E>> {
        let unblinding_factor = validator_keypair
            .decryption_key
            .inverse()
            .expect("Validator decryption key must have an inverse");
        Ok(PrivateKeyShare::<E>(
            self.blinded_key_share.mul(unblinding_factor).into_affine(),
        ))
    }

    pub fn create_decryption_share_simple(
        &self,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        validator_keypair: &Keypair<E>,
    ) -> Result<DecryptionShareSimple<E>> {
        DecryptionShareSimple::create(
            &validator_keypair.decryption_key,
            &self.unblind(validator_keypair)?,
            ciphertext_header,
            aad,
        )
    }

    /// In precomputed variant, we offload some of the decryption related computation to the server-side:
    /// We use the `prepare_combine_simple` function to precompute the lagrange coefficients
    pub fn create_decryption_share_precomputed(
        &self,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        validator_keypair: &Keypair<E>,
        share_index: u32,
        domain_points_map: &HashMap<u32, DomainPoint<E>>,
    ) -> Result<DecryptionSharePrecomputed<E>> {
        // We need to turn the domain points into a vector, and sort it by share index
        let mut domain_points = domain_points_map
            .iter()
            .map(|(share_index, domain_point)| (*share_index, *domain_point))
            .collect::<Vec<_>>();
        domain_points.sort_by_key(|(share_index, _)| *share_index);

        // Now, we have to pass the domain points to the `prepare_combine_simple` function
        // and use the resulting lagrange coefficients to create the decryption share

        let only_domain_points = domain_points
            .iter()
            .map(|(_, domain_point)| *domain_point)
            .collect::<Vec<_>>();
        let lagrange_coeffs = prepare_combine_simple::<E>(&only_domain_points);

        // Before we pick the lagrange coefficient for the current share index, we need
        // to map the share index to the index in the domain points vector
        // Given that we sorted the domain points by share index, the first element in the vector
        // will correspond to the smallest share index, second to the second smallest, and so on

        let sorted_share_indices = domain_points
            .iter()
            .enumerate()
            .map(|(adjusted_share_index, (share_index, _))| {
                (*share_index, adjusted_share_index)
            })
            .collect::<HashMap<u32, usize>>();
        let adjusted_share_index =
            *sorted_share_indices.get(&share_index).unwrap();

        // Finally, pick the lagrange coefficient for the current share index
        let lagrange_coeff = &lagrange_coeffs[adjusted_share_index];
        let private_key_share = self.unblind(validator_keypair);
        DecryptionSharePrecomputed::create(
            share_index as usize,
            &validator_keypair.decryption_key,
            &private_key_share.unwrap(),
            ciphertext_header,
            aad,
            lagrange_coeff,
        )
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct PrivateKeyShare<E: Pairing>(
    #[serde_as(as = "serialization::SerdeAs")] pub E::G2Affine,
);
