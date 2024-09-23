use std::ops::Mul;

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Field;
use ferveo_common::{serialization, Keypair};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    // TODO: Salvage and cleanup
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
    ) -> PrivateKeyShare<E> {
        let unblinding_factor = validator_keypair
            .decryption_key
            .inverse()
            .expect("Validator decryption key must have an inverse");
        PrivateKeyShare::<E>(
            self.blinded_key_share.mul(unblinding_factor).into_affine(),
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
