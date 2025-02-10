use std::ops::Mul;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{One, UniformRand};
use ark_serialize::CanonicalSerialize;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use ferveo_common::serialization;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::{digest::Digest, Sha256};
use zeroize::ZeroizeOnDrop;

use crate::{
    htp_bls12381_g2, DkgPublicKey, Error, PrivateKeyShare, Result, SecretBox,
    SharedSecret,
};

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext<E: Pairing> {
    // U
    #[serde_as(as = "serialization::SerdeAs")]
    pub commitment: E::G1Affine,

    // W
    #[serde_as(as = "serialization::SerdeAs")]
    pub auth_tag: E::G2Affine,

    // V
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl<E: Pairing> Ciphertext<E> {
    pub fn check(&self, aad: &[u8], g_inv: &E::G1Prepared) -> Result<bool> {
        self.header()?.check(aad, g_inv)
    }

    pub fn ciphertext_hash(&self) -> [u8; 32] {
        sha256(&self.ciphertext)
    }

    pub fn header(&self) -> Result<CiphertextHeader<E>> {
        Ok(CiphertextHeader {
            commitment: self.commitment,
            auth_tag: self.auth_tag,
            ciphertext_hash: self.ciphertext_hash(),
        })
    }
    pub fn payload(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextHeader<E: Pairing> {
    #[serde_as(as = "serialization::SerdeAs")]
    pub commitment: E::G1Affine,
    #[serde_as(as = "serialization::SerdeAs")]
    pub auth_tag: E::G2Affine,
    pub ciphertext_hash: [u8; 32],
}

impl<E: Pairing> CiphertextHeader<E> {
    pub fn check(&self, aad: &[u8], g_inv: &E::G1Prepared) -> Result<bool> {
        // Implements a variant of the check in section 4.4.2 of the Ferveo paper:
        // 'TPKE.CheckCiphertextValidity(U,W,aad)'
        // See: https://eprint.iacr.org/2022/898.pdf
        // See: https://nikkolasg.github.io/ferveo/tpke.html#to-validate-ciphertext-for-ind-cca2-security

        // H_G2(U, sym_ctxt_digest, aad)
        let hash_g2 = E::G2Prepared::from(construct_tag_hash::<E>(
            self.commitment,
            &self.ciphertext_hash,
            aad,
        )?);

        let is_ciphertext_valid = E::multi_pairing(
            // e(U, H_G2(U, sym_ctxt_digest, aad)) == e(G, W) ==>
            // e(U, H_G2(U, sym_ctxt_digest, aad)) * e(G_inv, W) == 1
            [self.commitment.into(), g_inv.to_owned()],
            [hash_g2, self.auth_tag.into()],
        )
        .0 == E::TargetField::one();

        if is_ciphertext_valid {
            Ok(true)
        } else {
            Err(Error::CiphertextVerificationFailed)
        }
    }
}

pub fn encrypt<E: Pairing>(
    message: SecretBox<Vec<u8>>,
    aad: &[u8],
    pubkey: &DkgPublicKey<E>,
    rng: &mut impl rand::Rng,
) -> Result<Ciphertext<E>> {
    // r
    let rand_element = E::ScalarField::rand(rng);
    // g
    let g_gen = E::G1Affine::generator();
    // h
    let h_gen = E::G2Affine::generator();

    let ry_prep = E::G1Prepared::from(pubkey.0.mul(rand_element).into());
    // s
    let product = E::pairing(ry_prep, h_gen).0;
    // u
    let commitment = g_gen.mul(rand_element).into();

    let nonce = Nonce::from_commitment::<E>(commitment)?;
    let shared_secret = SharedSecret::<E>(product);

    let payload = Payload {
        msg: message.as_secret().as_ref(),
        aad,
    };
    let ciphertext = shared_secret_to_chacha(&shared_secret)?
        .encrypt(&nonce.0, payload) // TODO: Consider encrypt_in_place (#196)
        .map_err(Error::SymmetricEncryptionError)?
        .to_vec();
    let ciphertext_hash = sha256(&ciphertext);

    // w
    let auth_tag = construct_tag_hash::<E>(commitment, &ciphertext_hash, aad)?
        .mul(rand_element)
        .into();

    // TODO: Consider adding aad to the Ciphertext struct
    Ok(Ciphertext::<E> {
        commitment,
        ciphertext,
        auth_tag,
    })
}

pub fn decrypt_symmetric<E: Pairing>(
    ciphertext: &Ciphertext<E>,
    aad: &[u8],
    private_key: &PrivateKeyShare<E>,
    g_inv: &E::G1Prepared,
) -> Result<Vec<u8>> {
    ciphertext.check(aad, g_inv)?;
    let shared_secret = E::pairing(
        E::G1Prepared::from(ciphertext.commitment),
        E::G2Prepared::from(private_key.0),
    )
    .0;
    let shared_secret = SharedSecret(shared_secret);
    decrypt_with_shared_secret_unchecked(ciphertext, aad, &shared_secret)
}

fn decrypt_with_shared_secret_unchecked<E: Pairing>(
    ciphertext: &Ciphertext<E>,
    aad: &[u8],
    shared_secret: &SharedSecret<E>,
) -> Result<Vec<u8>> {
    let nonce = Nonce::from_commitment::<E>(ciphertext.commitment)?;
    let ctxt = ciphertext.ciphertext.to_vec();
    let payload = Payload {
        msg: ctxt.as_ref(),
        aad,
    };
    let plaintext = shared_secret_to_chacha(shared_secret)?
        .decrypt(&nonce.0, payload)
        .map_err(|_| Error::CiphertextVerificationFailed)?
        .to_vec();

    Ok(plaintext)
}

pub fn decrypt_with_shared_secret<E: Pairing>(
    ciphertext: &Ciphertext<E>,
    aad: &[u8],
    shared_secret: &SharedSecret<E>,
    g_inv: &E::G1Prepared,
) -> Result<Vec<u8>> {
    ciphertext.check(aad, g_inv)?;
    decrypt_with_shared_secret_unchecked(ciphertext, aad, shared_secret)
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    result.into()
}

pub fn shared_secret_to_chacha<E: Pairing>(
    shared_secret: &SharedSecret<E>,
) -> Result<ChaCha20Poly1305> {
    let mut prf_key = SecretBox::new(Vec::new());
    shared_secret
        .0
        .serialize_compressed(prf_key.as_mut_secret())?;
    Ok(ChaCha20Poly1305::new(GenericArray::from_slice(&sha256(
        prf_key.as_secret(),
    ))))
}

/// Wrapper around the Nonce implementation from the `chacha20poly1305` crate.
/// This wrapper implements `ZeroizeOnDrop` to ensure that the key is zeroed when the
/// `Nonce` struct is dropped.
#[derive(ZeroizeOnDrop)]
pub struct Nonce(pub(crate) chacha20poly1305::Nonce);

impl Nonce {
    pub fn from_commitment<E: Pairing>(
        commitment: E::G1Affine,
    ) -> Result<Self> {
        let mut commitment_bytes = Vec::new();
        commitment.serialize_compressed(&mut commitment_bytes)?;
        let commitment_hash = sha256(&commitment_bytes);
        Ok(Nonce(*chacha20poly1305::Nonce::from_slice(
            &commitment_hash[..12],
        )))
    }
}

fn hash_to_g2<T: ark_serialize::CanonicalDeserialize>(
    message: &[u8],
) -> Result<T> {
    let point = htp_bls12381_g2(message);
    let mut point_ser: Vec<u8> = Vec::new();
    point.serialize_compressed(&mut point_ser)?;
    T::deserialize_compressed(&point_ser[..]).map_err(Error::ArkSerializeError)
}

fn construct_tag_hash<E: Pairing>(
    commitment: E::G1Affine,
    ciphertext_hash: &[u8],
    aad: &[u8],
) -> Result<E::G2Affine> {
    let mut hash_input = Vec::<u8>::new();
    commitment.serialize_compressed(&mut hash_input)?;
    hash_input.extend_from_slice(ciphertext_hash);
    hash_input.extend_from_slice(aad);
    hash_to_g2(&hash_input)
}

#[cfg(test)]
mod tests {
    use ark_std::test_rng;

    use crate::{test_common::*, *};

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn symmetric_encryption() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let g_inv = &contexts[0].setup_params.g_inv;

        let ciphertext =
            encrypt::<E>(SecretBox::new(msg.clone()), aad, &pubkey, rng)
                .unwrap();

        let plaintext =
            decrypt_symmetric(&ciphertext, aad, &privkey, g_inv).unwrap();

        assert_eq!(msg, plaintext);

        let bad: &[u8] = "bad-aad".as_bytes();

        assert!(decrypt_symmetric(&ciphertext, bad, &privkey, g_inv).is_err());
    }

    #[test]
    fn ciphertext_validity_check() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();
        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let g_inv = contexts[0].setup_params.g_inv.clone();
        let mut ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        // So far, the ciphertext is valid
        assert!(ciphertext.check(aad, &g_inv).is_ok());

        // Malformed the ciphertext
        ciphertext.ciphertext[0] += 1;
        assert!(ciphertext.check(aad, &g_inv).is_err());

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        assert!(ciphertext.check(aad, &g_inv).is_err());
    }
}
