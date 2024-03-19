use std::{
    convert::{TryFrom, TryInto},
    fmt,
    str::FromStr,
};

use ferveo_common::{FromBytes, ToBytes};
use ferveo_tdec::SecretBox;
use js_sys::Error;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_derive::TryFromJsValue;

use crate::api;

pub type JsResult<T> = Result<T, Error>;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub fn map_js_err<T: fmt::Display>(err: T) -> Error {
    Error::new(&format!("{err}"))
}

pub fn to_js_bytes<T: ToBytes>(t: &T) -> Result<Vec<u8>, Error> {
    t.to_bytes().map_err(map_js_err)
}

pub fn from_js_bytes<T: FromBytes>(bytes: &[u8]) -> Result<T, Error> {
    T::from_bytes(bytes).map_err(map_js_err)
}

/// Tries to convert a JS array from `JsValue` to a vector of Rust type elements.
// This is necessary since wasm-bindgen does not support having a parameter of `Vec<&T>`
// (see https://github.com/rustwasm/wasm-bindgen/issues/111).
pub fn try_from_js_array<T>(value: impl AsRef<JsValue>) -> JsResult<Vec<T>>
where
    for<'a> T: TryFrom<&'a JsValue>,
    for<'a> <T as TryFrom<&'a JsValue>>::Error: fmt::Display,
{
    let array: &js_sys::Array = value.as_ref().dyn_ref().ok_or_else(|| {
        Error::new("Got a non-array argument where an array was expected")
    })?;
    let length: usize = array.length().try_into().map_err(map_js_err)?;
    let mut result = Vec::<T>::with_capacity(length);
    for js in array.iter() {
        let typed_elem = T::try_from(&js).map_err(map_js_err)?;
        result.push(typed_elem);
    }
    Ok(result)
}

pub fn into_js_array<T, U>(value: impl IntoIterator<Item = U>) -> T
where
    JsValue: From<U>,
    T: JsCast,
{
    value
        .into_iter()
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<T>()
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ValidatorMessage[]")]
    pub type ValidatorMessageArray;

    #[wasm_bindgen(typescript_type = "Validator[]")]
    pub type ValidatorArray;

    #[wasm_bindgen(typescript_type = "DecryptionShareSimple[]")]
    pub type DecryptionShareSimpleArray;

    #[wasm_bindgen(typescript_type = "DecryptionSharePrecomputed[]")]
    pub type DecryptionSharePrecomputedArray;
}

fn unwrap_messages_js(
    messages: &ValidatorMessageArray,
) -> JsResult<Vec<(api::Validator, api::Transcript)>> {
    let messages = try_from_js_array::<ValidatorMessage>(messages)?;
    let messages = messages
        .iter()
        .map(|m| m.to_inner())
        .collect::<JsResult<Vec<_>>>()?;
    Ok(messages)
}

macro_rules! generate_equals {
    ($struct_name:ident) => {
        #[wasm_bindgen]
        impl $struct_name {
            #[wasm_bindgen]
            pub fn equals(&self, other: &$struct_name) -> bool {
                self.0 == other.0
            }
        }
    };
}

macro_rules! generate_bytes_serialization {
    ($struct_name:ident) => {
        #[wasm_bindgen]
        impl $struct_name {
            #[wasm_bindgen(js_name = "fromBytes")]
            pub fn from_bytes(bytes: &[u8]) -> JsResult<$struct_name> {
                from_js_bytes(bytes).map(Self)
            }

            #[wasm_bindgen(js_name = "toBytes")]
            pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
                to_js_bytes(&self.0)
            }
        }
    };
}

macro_rules! generate_boxed_bytes_serialization {
    ($struct_name:ident, $inner_struct_name:ident) => {
        #[wasm_bindgen]
        impl $struct_name {
            #[wasm_bindgen(js_name = "fromBytes")]
            pub fn from_bytes(bytes: &[u8]) -> JsResult<$struct_name> {
                $inner_struct_name::from_bytes(bytes)
                    .map_err(map_js_err)
                    .map(Self)
            }

            #[wasm_bindgen(js_name = "toBytes")]
            pub fn to_bytes(&self) -> JsResult<Box<[u8]>> {
                let bytes = self.0.to_bytes().map_err(map_js_err)?;
                let bytes: Box<[u8]> = bytes.as_slice().into();
                Ok(bytes)
            }

            #[wasm_bindgen(js_name = "serializedSize")]
            pub fn serialized_size() -> usize {
                $inner_struct_name::serialized_size()
            }
        }
    };
}

macro_rules! generate_common_methods {
    ($struct_name:ident) => {
        generate_equals!($struct_name);
        generate_bytes_serialization!($struct_name);
    };
}

#[wasm_bindgen]
#[derive(Clone, Debug, derive_more::AsRef, derive_more::From)]
pub struct FerveoVariant(pub(crate) api::FerveoVariant);

impl fmt::Display for FerveoVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

generate_common_methods!(FerveoVariant);

#[wasm_bindgen]
impl FerveoVariant {
    #[wasm_bindgen(js_name = "precomputed", getter)]
    pub fn precomputed() -> FerveoVariant {
        FerveoVariant(api::FerveoVariant::Precomputed)
    }

    #[wasm_bindgen(js_name = "simple", getter)]
    pub fn simple() -> FerveoVariant {
        FerveoVariant(api::FerveoVariant::Simple)
    }

    #[allow(clippy::inherent_to_string_shadow_display)]
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, Debug, derive_more::AsRef, derive_more::From)]
pub struct DecryptionShareSimple(api::DecryptionShareSimple);

generate_common_methods!(DecryptionShareSimple);

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, Debug, derive_more::AsRef, derive_more::From)]
pub struct DecryptionSharePrecomputed(
    ferveo_tdec::api::DecryptionSharePrecomputed,
);

generate_common_methods!(DecryptionSharePrecomputed);

type InnerPublicKey = api::PublicKey;

#[wasm_bindgen]
#[derive(
    Clone, Debug, derive_more::AsRef, derive_more::From, derive_more::Into,
)]
pub struct FerveoPublicKey(InnerPublicKey);

generate_equals!(FerveoPublicKey);
generate_boxed_bytes_serialization!(FerveoPublicKey, InnerPublicKey);

#[wasm_bindgen]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    derive_more::From,
    derive_more::AsRef,
    derive_more::Into,
)]
pub struct Ciphertext(api::Ciphertext);

#[wasm_bindgen]
impl Ciphertext {
    #[wasm_bindgen(js_name = "header", getter)]
    pub fn header(&self) -> JsResult<CiphertextHeader> {
        let header = self.0.header().map_err(map_js_err)?;
        Ok(CiphertextHeader(header))
    }

    #[wasm_bindgen(js_name = "payload", getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.0.payload()
    }
}

generate_common_methods!(Ciphertext);

#[wasm_bindgen]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    derive_more::From,
    derive_more::AsRef,
    derive_more::Into,
)]
pub struct CiphertextHeader(api::CiphertextHeader);

generate_common_methods!(CiphertextHeader);

#[wasm_bindgen(js_name = "ferveoEncrypt")]
pub fn ferveo_encrypt(
    message: &[u8],
    aad: &[u8],
    dkg_public_key: &DkgPublicKey,
) -> JsResult<Ciphertext> {
    set_panic_hook();
    let ciphertext =
        api::encrypt(SecretBox::new(message.to_vec()), aad, &dkg_public_key.0)
            .map_err(map_js_err)?;
    Ok(Ciphertext(ciphertext))
}

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize, derive_more::AsRef)]
pub struct SharedSecret(api::SharedSecret);

generate_common_methods!(SharedSecret);

#[wasm_bindgen(js_name = "combineDecryptionSharesSimple")]
pub fn combine_decryption_shares_simple(
    decryption_shares_js: &DecryptionShareSimpleArray,
) -> JsResult<SharedSecret> {
    let shares =
        try_from_js_array::<DecryptionShareSimple>(decryption_shares_js)?;
    let shares: Vec<_> = shares.iter().map(|share| share.0.clone()).collect();
    let shared_secret = api::combine_shares_simple(&shares[..]);
    Ok(SharedSecret(shared_secret))
}

#[wasm_bindgen(js_name = "combineDecryptionSharesPrecomputed")]
pub fn combine_decryption_shares_precomputed(
    decryption_shares_js: &DecryptionSharePrecomputedArray,
) -> JsResult<SharedSecret> {
    let shares =
        try_from_js_array::<DecryptionSharePrecomputed>(decryption_shares_js)?;
    let shares = shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    let shared_secret = api::share_combine_precomputed(&shares[..]);
    Ok(SharedSecret(api::SharedSecret(shared_secret)))
}

#[wasm_bindgen(js_name = "decryptWithSharedSecret")]
pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
) -> JsResult<Vec<u8>> {
    set_panic_hook();
    api::decrypt_with_shared_secret(&ciphertext.0, aad, &shared_secret.0)
        .map_err(map_js_err)
}

type InnerDkgPublicKey = api::DkgPublicKey;

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct DkgPublicKey(InnerDkgPublicKey);

generate_equals!(DkgPublicKey);
generate_boxed_bytes_serialization!(DkgPublicKey, InnerDkgPublicKey);

#[wasm_bindgen]
impl DkgPublicKey {
    #[wasm_bindgen]
    pub fn random() -> DkgPublicKey {
        Self(api::DkgPublicKey::random())
    }
}

#[wasm_bindgen]
pub struct Dkg(api::Dkg);

#[wasm_bindgen]
impl Dkg {
    #[wasm_bindgen(constructor)]
    pub fn new(
        tau: u32,
        shares_num: u32,
        security_threshold: u32,
        validators_js: &ValidatorArray,
        me: &Validator,
    ) -> JsResult<Dkg> {
        let validators = try_from_js_array::<Validator>(validators_js)?;
        let validators = validators
            .into_iter()
            .map(|v| v.to_inner())
            .collect::<JsResult<Vec<_>>>()?;
        let dkg = api::Dkg::new(
            tau,
            shares_num,
            security_threshold,
            &validators,
            &me.to_inner()?,
        )
        .map_err(map_js_err)?;
        Ok(Self(dkg))
    }

    #[wasm_bindgen(js_name = "generateTranscript")]
    pub fn generate_transcript(&mut self) -> JsResult<Transcript> {
        let rng = &mut thread_rng();
        let transcript = self.0.generate_transcript(rng).map_err(map_js_err)?;
        Ok(Transcript(transcript))
    }

    #[wasm_bindgen(js_name = "aggregateTranscript")]
    pub fn aggregate_transcripts(
        &mut self,
        messages_js: &ValidatorMessageArray,
    ) -> JsResult<AggregatedTranscript> {
        let messages = unwrap_messages_js(messages_js)?;
        let aggregated_transcript = self
            .0
            .aggregate_transcripts(&messages)
            .map_err(map_js_err)?;
        Ok(AggregatedTranscript(aggregated_transcript))
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transcript(pub(crate) api::Transcript);

generate_common_methods!(Transcript);

#[wasm_bindgen(js_name = EthereumAddress)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumAddress(api::EthereumAddress);

#[wasm_bindgen]
impl EthereumAddress {
    #[wasm_bindgen(js_name = "fromString")]
    pub fn from_string(address: &str) -> JsResult<EthereumAddress> {
        set_panic_hook();
        Ok(Self(
            api::EthereumAddress::from_str(address).map_err(map_js_err)?,
        ))
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> JsResult<String> {
        set_panic_hook();
        Ok(self.0.to_string())
    }
}

// Using a separate Validator struct for WASM bindings to avoid issues with serialization of
// `ark_ec::models::bls12::Bls12<ark_bls12_381::curves::Config>`, i.e. G2Affine public key
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, Debug, derive_more::AsRef, derive_more::From)]
pub struct Validator {
    address: EthereumAddress,
    public_key: FerveoPublicKey,
    share_index: u32,
}

#[wasm_bindgen]
impl Validator {
    #[wasm_bindgen(constructor)]
    pub fn new(
        address: &EthereumAddress,
        public_key: &FerveoPublicKey,
        share_index: u32,
    ) -> JsResult<Validator> {
        set_panic_hook();
        Ok(Self {
            address: address.clone(),
            public_key: public_key.clone(),
            share_index,
        })
    }

    pub(crate) fn to_inner(&self) -> JsResult<api::Validator> {
        set_panic_hook();
        Ok(api::Validator {
            address: self.address.0.clone(),
            public_key: self.public_key.0,
            share_index: self.share_index,
        })
    }

    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> FerveoPublicKey {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> EthereumAddress {
        self.address.clone()
    }
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, Debug, derive_more::AsRef, derive_more::From)]
pub struct ValidatorMessage(Validator, Transcript);

#[wasm_bindgen]
impl ValidatorMessage {
    #[wasm_bindgen(constructor)]
    pub fn new(
        validator: &Validator,
        transcript: &Transcript,
    ) -> JsResult<ValidatorMessage> {
        Ok(Self(validator.clone(), transcript.clone()))
    }

    pub(crate) fn to_inner(
        &self,
    ) -> JsResult<(api::Validator, api::Transcript)> {
        Ok((self.0.to_inner()?, self.1 .0.clone()))
    }

    #[wasm_bindgen(getter)]
    pub fn validator(&self) -> Validator {
        self.0.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn transcript(&self) -> Transcript {
        self.1.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedTranscript(api::AggregatedTranscript);

#[wasm_bindgen]
impl AggregatedTranscript {
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.public_key())
    }
}

generate_common_methods!(AggregatedTranscript);

#[wasm_bindgen]
impl AggregatedTranscript {
    #[wasm_bindgen(constructor)]
    pub fn new(
        messages: &ValidatorMessageArray,
    ) -> JsResult<AggregatedTranscript> {
        set_panic_hook();
        let messages = unwrap_messages_js(messages)?;
        let aggregated_transcript =
            api::AggregatedTranscript::new(&messages).unwrap();
        Ok(AggregatedTranscript(aggregated_transcript))
    }

    #[wasm_bindgen]
    pub fn verify(
        &self,
        validators_num: u32,
        messages: &ValidatorMessageArray,
    ) -> JsResult<bool> {
        set_panic_hook();
        let messages = unwrap_messages_js(messages)?;
        let is_valid = self
            .0
            .verify(validators_num, &messages)
            .map_err(map_js_err)?;
        Ok(is_valid)
    }

    #[wasm_bindgen(js_name = "createDecryptionSharePrecomputed")]
    pub fn create_decryption_share_precomputed(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> JsResult<DecryptionSharePrecomputed> {
        set_panic_hook();
        let decryption_share = self
            .0
            .create_decryption_share_precomputed(
                &dkg.0,
                &ciphertext_header.0,
                aad,
                &validator_keypair.0,
            )
            .map_err(map_js_err)?;
        Ok(DecryptionSharePrecomputed(decryption_share))
    }

    #[wasm_bindgen(js_name = "createDecryptionShareSimple")]
    pub fn create_decryption_share_simple(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> JsResult<DecryptionShareSimple> {
        set_panic_hook();
        let decryption_share = self
            .0
            .create_decryption_share_simple(
                &dkg.0,
                &ciphertext_header.0,
                aad,
                &validator_keypair.0,
            )
            .map_err(map_js_err)?;
        Ok(DecryptionShareSimple(decryption_share))
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Keypair(api::Keypair);

generate_common_methods!(Keypair);

#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen(getter, js_name = "secureRandomnessSize")]
    pub fn secure_randomness_size() -> usize {
        api::Keypair::secure_randomness_size()
    }

    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> FerveoPublicKey {
        FerveoPublicKey(self.0.public_key())
    }

    #[wasm_bindgen]
    pub fn random() -> Self {
        Self(api::Keypair::new(&mut thread_rng()))
    }

    #[wasm_bindgen(js_name = "fromSecureRandomness")]
    pub fn from_secure_randomness(bytes: &[u8]) -> JsResult<Keypair> {
        set_panic_hook();
        let keypair =
            api::Keypair::from_secure_randomness(bytes).map_err(map_js_err)?;
        Ok(Self(keypair))
    }
}

pub mod test_common {
    use crate::bindings_wasm::*;

    pub fn gen_keypair(i: usize) -> Keypair {
        Keypair::from_secure_randomness(&[i as u8; 32]).unwrap()
    }

    pub fn gen_address(i: usize) -> EthereumAddress {
        EthereumAddress::from_string(&format!("0x{i:040}")).unwrap()
    }

    pub fn gen_validator(i: usize, keypair: &Keypair) -> Validator {
        Validator {
            address: gen_address(i),
            public_key: keypair.public_key(),
            share_index: i as u32,
        }
    }
}
