use ark_ec::pairing::Pairing;

use crate::{
    prepare_combine_simple, BlindedKeyShare, CiphertextHeader,
    DecryptionSharePrecomputed, DecryptionShareSimple, PrivateKeyShare, Result,
    ShareCommitment,
};

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextFast<E: Pairing> {
    pub domain: E::ScalarField,
    pub public_key: ShareCommitment<E>, // FIXME
    pub blinded_key_share: BlindedKeyShare<E>,
    // This decrypter's contribution to N(0), namely (-1)^|domain| * \prod_i omega_i
    pub lagrange_n_0: E::ScalarField, // TODO: Unused field - #197
    pub h_inv: E::G2Prepared,
}

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextSimple<E: Pairing> {
    pub domain: E::ScalarField,
    pub share_commitment: ShareCommitment<E>,
    pub blinded_key_share: BlindedKeyShare<E>,
    pub h: E::G2Affine,
    pub validator_public_key: ferveo_common::PublicKey<E>,
}

// TODO: Mark for removal
#[derive(Clone, Debug)]
pub struct SetupParams<E: Pairing> {
    pub b: E::ScalarField, // Validator private key
    pub b_inv: E::ScalarField,
    pub g: E::G1Affine,
    pub g_inv: E::G1Prepared,
    pub h_inv: E::G2Prepared,
    pub h: E::G2Affine,
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContextSimple<E: Pairing> {
    pub index: usize,
    pub setup_params: SetupParams<E>,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextSimple<E>>,
}

impl<E: Pairing> PrivateDecryptionContextSimple<E> {
    pub fn create_share(
        &self,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
    ) -> Result<DecryptionShareSimple<E>> {
        DecryptionShareSimple::create(
            &self.setup_params.b,
            &self.private_key_share,
            ciphertext_header,
            aad,
            &self.setup_params.g_inv,
        )
    }

    pub fn create_share_precomputed(
        &self,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        selected_participants: &[usize],
    ) -> Result<DecryptionSharePrecomputed<E>> {
        let selected_domain_points = selected_participants
            .iter()
            .map(|i| self.public_decryption_contexts[*i].domain)
            .collect::<Vec<_>>();
        let lagrange_coeffs =
            prepare_combine_simple::<E>(&selected_domain_points);

        DecryptionSharePrecomputed::create(
            self.index,
            &self.setup_params.b,
            &self.private_key_share,
            ciphertext_header,
            aad,
            &lagrange_coeffs[self.index],
            &self.setup_params.g_inv,
        )
    }
}
