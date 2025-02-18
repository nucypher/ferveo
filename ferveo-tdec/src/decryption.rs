use std::ops::Mul;

use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_ff::Field;
use ferveo_common::serialization;
use itertools::izip;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    Ciphertext, CiphertextHeader, PrivateKeyShare,
    PublicDecryptionContextSimple, Result,
};

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidatorShareChecksum<E: Pairing> {
    #[serde_as(as = "serialization::SerdeAs")]
    pub checksum: E::G1Affine,
}

impl<E: Pairing> ValidatorShareChecksum<E> {
    pub fn new(
        validator_decryption_key: &E::ScalarField,
        ciphertext_header: &CiphertextHeader<E>,
    ) -> Result<Self> {
        // C_i = dk_i^{-1} * U
        let checksum = ciphertext_header
            .commitment
            .mul(
                validator_decryption_key
                    .inverse()
                    .expect("Inverse of this key doesn't exist"),
            )
            .into_affine();
        Ok(Self { checksum })
    }

    pub fn verify(
        &self,
        decryption_share: &E::TargetField,
        share_aggregate: &E::G2Affine,
        validator_public_key: &E::G2Affine,
        ciphertext: &Ciphertext<E>,
    ) -> bool {
        // See https://github.com/nucypher/ferveo/issues/42#issuecomment-1398953777
        // D_i == e(C_i, Y_i)
        if *decryption_share != E::pairing(self.checksum, *share_aggregate).0 {
            return false;
        }

        // TODO: use multipairing here (h_inv) - Issue #192
        // e(C_i, ek_i) == e(U, H)
        if E::pairing(self.checksum, *validator_public_key)
            != E::pairing(ciphertext.commitment, E::G2::generator())
        {
            return false;
        }

        true
    }
}

/// A decryption share for a simple variant of the threshold decryption scheme.
/// In this variant, the decryption share require additional computation on the
/// client side int order to be combined.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionShareSimple<E: Pairing> {
    #[serde_as(as = "serialization::SerdeAs")]
    pub decryption_share: E::TargetField,
    #[serde(bound(
        serialize = "ValidatorShareChecksum<E>: Serialize",
        deserialize = "ValidatorShareChecksum<E>: DeserializeOwned"
    ))]
    pub validator_checksum: ValidatorShareChecksum<E>,
}

impl<E: Pairing> DecryptionShareSimple<E> {
    /// Create a decryption share from the given parameters.
    /// This function checks that the ciphertext is valid.
    pub fn create(
        validator_decryption_key: &E::ScalarField,
        private_key_share: &PrivateKeyShare<E>,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        g_inv: &E::G1Prepared,
    ) -> Result<Self> {
        ciphertext_header.check(aad, g_inv)?;
        Self::create_unchecked(
            validator_decryption_key,
            private_key_share,
            ciphertext_header,
        )
    }

    /// Create a decryption share from the given parameters.
    /// This function does not check that the ciphertext is valid.
    pub fn create_unchecked(
        validator_decryption_key: &E::ScalarField,
        private_key_share: &PrivateKeyShare<E>,
        ciphertext_header: &CiphertextHeader<E>,
    ) -> Result<Self> {
        // D_i = e(U, Z_i)
        let decryption_share =
            E::pairing(ciphertext_header.commitment, private_key_share.0).0;

        let validator_checksum = ValidatorShareChecksum::new(
            validator_decryption_key,
            ciphertext_header,
        )?;

        Ok(Self {
            decryption_share,
            validator_checksum,
        })
    }
    /// Verify that the decryption share is valid.
    pub fn verify(
        &self,
        share_aggregate: &E::G2Affine,
        validator_public_key: &E::G2Affine,
        ciphertext: &Ciphertext<E>,
    ) -> bool {
        self.validator_checksum.verify(
            &self.decryption_share,
            share_aggregate,
            validator_public_key,
            ciphertext,
        )
    }
}

/// A decryption share for a precomputed variant of the threshold decryption scheme.
/// In this variant, the decryption share is precomputed and can be combined
/// without additional computation on the client side.
/// The downside is that the threshold of decryption shares required to decrypt
/// is equal to the number of private key shares in the scheme.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionSharePrecomputed<E: Pairing> {
    pub decrypter_index: usize,
    #[serde_as(as = "serialization::SerdeAs")]
    pub decryption_share: E::TargetField,
    #[serde(bound(
        serialize = "ValidatorShareChecksum<E>: Serialize",
        deserialize = "ValidatorShareChecksum<E>: DeserializeOwned"
    ))]
    pub validator_checksum: ValidatorShareChecksum<E>,
}

impl<E: Pairing> DecryptionSharePrecomputed<E> {
    /// Create a decryption share from the given parameters.
    /// This function checks that the ciphertext is valid.
    pub fn create(
        validator_index: usize,
        validator_decryption_key: &E::ScalarField,
        private_key_share: &PrivateKeyShare<E>,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        lagrange_coeff: &E::ScalarField,
        g_inv: &E::G1Prepared,
    ) -> Result<Self> {
        ciphertext_header.check(aad, g_inv)?;
        Self::create_unchecked(
            validator_index,
            validator_decryption_key,
            private_key_share,
            ciphertext_header,
            lagrange_coeff,
        )
    }

    /// Create a decryption share from the given parameters.
    /// This function does not check that the ciphertext is valid.
    pub fn create_unchecked(
        validator_index: usize,
        validator_decryption_key: &E::ScalarField,
        private_key_share: &PrivateKeyShare<E>,
        ciphertext_header: &CiphertextHeader<E>,
        lagrange_coeff: &E::ScalarField,
    ) -> Result<Self> {
        // U_{λ_i} = [λ_{i}(0)] U
        let u_to_lagrange_coeff =
            ciphertext_header.commitment.mul(lagrange_coeff);
        // C_{λ_i} = e(U_{λ_i}, Z_i)
        let decryption_share =
            E::pairing(u_to_lagrange_coeff, private_key_share.0).0;

        let validator_checksum = ValidatorShareChecksum::new(
            validator_decryption_key,
            ciphertext_header,
        )?;

        Ok(Self {
            decrypter_index: validator_index,
            decryption_share,
            validator_checksum,
        })
    }

    /// Verify that the decryption share is valid.
    pub fn verify(
        &self,
        share_aggregate: &E::G2Affine,
        validator_public_key: &E::G2Affine,
        ciphertext: &Ciphertext<E>,
    ) -> bool {
        self.validator_checksum.verify(
            &self.decryption_share,
            share_aggregate,
            validator_public_key,
            ciphertext,
        )
    }
}

pub fn verify_decryption_shares_simple<E: Pairing>(
    pub_contexts: &Vec<PublicDecryptionContextSimple<E>>,
    ciphertext: &Ciphertext<E>,
    decryption_shares: &Vec<DecryptionShareSimple<E>>,
) -> bool {
    let blinded_key_shares = &pub_contexts
        .iter()
        .map(|c| &c.blinded_key_share.blinded_key_share)
        .collect::<Vec<_>>();
    for (decryption_share, y_i, pub_context) in
        izip!(decryption_shares, blinded_key_shares, pub_contexts)
    {
        let is_valid = decryption_share.verify(
            y_i,
            &pub_context.validator_public_key.encryption_key,
            ciphertext,
        );
        if !is_valid {
            return false;
        }
    }
    true
}
