use std::ops::Mul;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ferveo_common::serialization;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[serde_as]
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKey<E: Pairing>(
    #[serde_as(as = "serialization::SerdeAs")] pub E::G1Affine,
);

#[serde_as]
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareCommitment<E: Pairing>(
    #[serde_as(as = "serialization::SerdeAs")] pub E::G1Affine, // A_{i, \omega_i}
);

#[derive(Debug, Copy, Clone)]
pub struct BlindedKeyShare<E: Pairing> {
    pub validator_public_key: E::G2Affine, // [b] H
    pub blinded_key_share: E::G2Affine,    // [b] Z_{i, \omega_i}
}

impl<E: Pairing> BlindedKeyShare<E> {
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
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct PrivateKeyShare<E: Pairing>(
    #[serde_as(as = "serialization::SerdeAs")] pub E::G2Affine,
);

// TODO: Check if we use it in test only, consider adding #[cfg(test)]
// #[cfg(test)]
impl<E: Pairing> PrivateKeyShare<E> {
    pub fn blind(&self, b: E::ScalarField) -> BlindedKeyShare<E> {
        let validator_public_key =
            E::G2Affine::generator().mul(b).into_affine();
        BlindedKeyShare::<E> {
            validator_public_key,
            blinded_key_share: self.0.mul(b).into_affine(),
        }
    }
}
