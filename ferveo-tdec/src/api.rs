//! Contains the public API of the library.

pub type E = ark_bls12_381::Bls12_381;
pub type G1Prepared = <E as ark_ec::pairing::Pairing>::G1Prepared;
pub type G1Affine = <E as ark_ec::pairing::Pairing>::G1Affine;
pub type G2Affine = <E as ark_ec::pairing::Pairing>::G2Affine;
pub type Fr = ark_bls12_381::Fr;
pub type PrivateKey = ark_bls12_381::G2Affine;
pub type Result<T> = crate::Result<T>;
pub type PrivateDecryptionContextSimple =
    crate::PrivateDecryptionContextSimple<E>;
pub type DecryptionSharePrecomputed = crate::DecryptionSharePrecomputed<E>;
pub type DecryptionShareSimple = crate::DecryptionShareSimple<E>;
pub type Ciphertext = crate::Ciphertext<E>;

pub type CiphertextHeader = crate::CiphertextHeader<E>;
pub type TargetField = <E as ark_ec::pairing::Pairing>::TargetField;

pub use crate::{
    decrypt_symmetric, decrypt_with_shared_secret, encrypt,
    prepare_combine_simple, share_combine_precomputed, share_combine_simple,
    SharedSecret,
};
