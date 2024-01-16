use std::{
    fmt,
    fmt::{Debug, Formatter},
};

use ferveo_common::serialization::{FromBytes, ToBytes};
use pyo3::{
    basic::CompareOp,
    create_exception,
    exceptions::{PyException, PyRuntimeError, PyValueError},
    prelude::*,
    types::{PyBytes, PyUnicode},
    PyClass,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::{api, Error};

#[derive(thiserror::Error)]
pub enum FerveoPythonError {
    #[error(transparent)]
    FerveoError(#[from] Error),

    /// Any other errors that are too trivial to be put here explicitly.
    #[error("{0}")]
    Other(String),
}

impl From<FerveoPythonError> for PyErr {
    fn from(err: FerveoPythonError) -> PyErr {
        let default = || PyRuntimeError::new_err(format!("{:?}", &err));

        use FerveoPythonError::*;
        match &err {
            FerveoError(err) => match err {
                Error::ThresholdEncryptionError(err) => {
                    ThresholdEncryptionError::new_err(err.to_string())
                }
                Error::InvalidDkgStateToDeal => {
                    InvalidDkgStateToDeal::new_err("")
                }
                Error::InvalidDkgStateToAggregate => {
                    InvalidDkgStateToAggregate::new_err("")
                }
                Error::InvalidDkgStateToVerify => {
                    InvalidDkgStateToVerify::new_err("")
                }
                Error::InvalidDkgStateToIngest => {
                    InvalidDkgStateToIngest::new_err("")
                }
                Error::DealerNotInValidatorSet(dealer) => {
                    DealerNotInValidatorSet::new_err(dealer.to_string())
                }
                Error::UnknownDealer(dealer) => {
                    UnknownDealer::new_err(dealer.to_string())
                }
                Error::DuplicateDealer(dealer) => {
                    DuplicateDealer::new_err(dealer.to_string())
                }
                Error::InvalidPvssTranscript => {
                    InvalidPvssTranscript::new_err("")
                }
                Error::InsufficientTranscriptsForAggregate(
                    expected,
                    actual,
                ) => InsufficientTranscriptsForAggregate::new_err(format!(
                    "expected: {expected}, actual: {actual}"
                )),
                Error::InvalidDkgPublicKey => InvalidDkgPublicKey::new_err(""),
                Error::InsufficientValidators(expected, actual) => {
                    InsufficientValidators::new_err(format!(
                        "expected: {expected}, actual: {actual}"
                    ))
                }
                Error::InvalidTranscriptAggregate => {
                    InvalidTranscriptAggregate::new_err("")
                }
                Error::ValidatorsNotSorted => ValidatorsNotSorted::new_err(""),
                Error::ValidatorPublicKeyMismatch => {
                    ValidatorPublicKeyMismatch::new_err("")
                }
                Error::BincodeError(err) => {
                    SerializationError::new_err(err.to_string())
                }
                Error::ArkSerializeError(err) => {
                    SerializationError::new_err(err.to_string())
                }
                Error::InvalidByteLength(expected, actual) => {
                    InvalidByteLength::new_err(format!(
                        "expected: {expected}, actual: {actual}"
                    ))
                }
                Error::InvalidVariant(variant) => {
                    InvalidVariant::new_err(variant.to_string())
                },
                Error::InvalidDkgParameters(num_shares, security_threshold) => {
                    InvalidDkgParameters::new_err(format!(
                        "num_shares: {num_shares}, security_threshold: {security_threshold}"
                    ))
                },
                Error::InvalidShareIndex(index) => {
                    InvalidShareIndex::new_err(format!(
                        "{index}"
                    ))
                },
            },
            _ => default(),
        }
    }
}

impl Debug for FerveoPythonError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use FerveoPythonError::*;
        match self {
            FerveoError(err) => write!(f, "FerveoError: {err:?}"),
            Other(err) => write!(f, "Other: {err:?}"),
        }
    }
}

create_exception!(exceptions, ThresholdEncryptionError, PyException);
create_exception!(exceptions, InvalidDkgStateToDeal, PyRuntimeError);
create_exception!(exceptions, InvalidDkgStateToAggregate, PyRuntimeError);
create_exception!(exceptions, InvalidDkgStateToVerify, PyRuntimeError);
create_exception!(exceptions, InvalidDkgStateToIngest, PyRuntimeError);
create_exception!(exceptions, DealerNotInValidatorSet, PyValueError);
create_exception!(exceptions, UnknownDealer, PyValueError);
create_exception!(exceptions, DuplicateDealer, PyValueError);
create_exception!(exceptions, InvalidPvssTranscript, PyValueError);
create_exception!(exceptions, InsufficientTranscriptsForAggregate, PyException);
create_exception!(exceptions, InvalidDkgPublicKey, PyValueError);
create_exception!(exceptions, InsufficientValidators, PyValueError);
create_exception!(exceptions, InvalidTranscriptAggregate, PyValueError);
create_exception!(exceptions, ValidatorsNotSorted, PyValueError);
create_exception!(exceptions, ValidatorPublicKeyMismatch, PyValueError);
create_exception!(exceptions, SerializationError, PyValueError);
create_exception!(exceptions, InvalidByteLength, PyValueError);
create_exception!(exceptions, InvalidVariant, PyValueError);
create_exception!(exceptions, InvalidDkgParameters, PyValueError);
create_exception!(exceptions, InvalidShareIndex, PyValueError);

fn from_py_bytes<T: FromBytes>(bytes: &[u8]) -> PyResult<T> {
    T::from_bytes(bytes)
        .map_err(|err| FerveoPythonError::FerveoError(err.into()).into())
}

fn to_py_bytes<T: ToBytes>(t: &T) -> PyResult<PyObject> {
    let bytes = t
        .to_bytes()
        .map_err(|err| FerveoPythonError::FerveoError(err.into()))?;
    as_py_bytes(&bytes)
}

fn as_py_bytes(bytes: &[u8]) -> PyResult<PyObject> {
    Ok(Python::with_gil(|py| -> PyObject {
        PyBytes::new(py, bytes).into()
    }))
}

// TODO: Not using generics here since some of the types don't implement AsRef<[u8]>
fn hash(type_name: &str, bytes: &[u8]) -> PyResult<isize> {
    // call `hash((class_name, bytes(obj)))`
    Python::with_gil(|py| {
        let builtins = PyModule::import(py, "builtins")?;
        let arg1 = PyUnicode::new(py, type_name);
        let arg2: PyObject = PyBytes::new(py, bytes).into();
        builtins.getattr("hash")?.call1(((arg1, arg2),))?.extract()
    })
}

fn richcmp<T>(obj: &T, other: &T, op: CompareOp) -> PyResult<bool>
where
    T: PyClass + PartialEq + PartialOrd,
{
    match op {
        CompareOp::Eq => Ok(obj == other),
        CompareOp::Ne => Ok(obj != other),
        CompareOp::Lt => Ok(obj < other),
        CompareOp::Le => Ok(obj <= other),
        CompareOp::Gt => Ok(obj > other),
        CompareOp::Ge => Ok(obj >= other),
    }
}

macro_rules! generate_bytes_serialization {
    ($struct_name:ident) => {
        #[pymethods]
        impl $struct_name {
            #[staticmethod]
            #[pyo3(signature = (data))]
            pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
                from_py_bytes(data).map(Self)
            }

            fn __bytes__(&self) -> PyResult<PyObject> {
                to_py_bytes(&self.0)
            }
        }
    };
}

macro_rules! generate_boxed_bytes_serialization {
    ($struct_name:ident, $inner_struct_name:ident) => {
        #[pymethods]
        impl $struct_name {
            #[staticmethod]
            #[pyo3(signature = (data))]
            pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
                Ok($struct_name($inner_struct_name::from_bytes(data).map_err(
                    |err| FerveoPythonError::Other(err.to_string()),
                )?))
            }

            fn __bytes__(&self) -> PyResult<PyObject> {
                let bytes = self
                    .0
                    .to_bytes()
                    .map_err(|err| FerveoPythonError::Other(err.to_string()))?;
                as_py_bytes(&bytes)
            }

            #[staticmethod]
            pub fn serialized_size() -> usize {
                $inner_struct_name::serialized_size()
            }
        }
    };
}

#[pyfunction]
pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    dkg_public_key: &DkgPublicKey,
) -> PyResult<Ciphertext> {
    let ciphertext = api::encrypt(
        // TODO: Avoid double-allocation here. `SecretBox` already allocates for its contents.
        api::SecretBox::new(message.to_vec()),
        aad,
        &dkg_public_key.0,
    )
    .map_err(FerveoPythonError::FerveoError)?;
    Ok(Ciphertext(ciphertext))
}

#[pyfunction]
pub fn combine_decryption_shares_simple(
    decryption_shares: Vec<DecryptionShareSimple>,
) -> SharedSecret {
    let shares = decryption_shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    let shared_secret = api::combine_shares_simple(&shares[..]);
    SharedSecret(shared_secret)
}

#[pyfunction]
pub fn combine_decryption_shares_precomputed(
    decryption_shares: Vec<DecryptionSharePrecomputed>,
) -> SharedSecret {
    let shares = decryption_shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    let shared_secret = api::share_combine_precomputed(&shares[..]);
    SharedSecret(api::SharedSecret(shared_secret))
}

#[pyfunction]
pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
) -> PyResult<Vec<u8>> {
    api::decrypt_with_shared_secret(&ciphertext.0, aad, &shared_secret.0)
        .map_err(|err| FerveoPythonError::FerveoError(err).into())
}

#[pyclass(module = "ferveo")]
#[derive(
    Clone, PartialEq, PartialOrd, Eq, derive_more::From, derive_more::AsRef,
)]
pub struct FerveoVariant(pub(crate) api::FerveoVariant);

#[pymethods]
impl FerveoVariant {
    #[classattr]
    #[pyo3(name = "Precomputed")]
    fn precomputed() -> FerveoVariant {
        api::FerveoVariant::Precomputed.into()
    }

    #[classattr]
    #[pyo3(name = "Simple")]
    fn simple() -> FerveoVariant {
        api::FerveoVariant::Simple.into()
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        let bytes = self
            .0
            .to_bytes()
            .map_err(|err| FerveoPythonError::Other(err.to_string()))?;
        hash("FerveoVariant", &bytes)
    }
}

impl fmt::Display for FerveoVariant {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[pyclass(module = "ferveo")]
#[derive(derive_more::AsRef)]
pub struct SharedSecret(api::SharedSecret);

generate_bytes_serialization!(SharedSecret);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct Keypair(api::Keypair);

generate_bytes_serialization!(Keypair);

#[pymethods]
impl Keypair {
    #[staticmethod]
    pub fn random() -> Self {
        Self(api::Keypair::random())
    }

    #[staticmethod]
    pub fn from_secure_randomness(secure_randomness: &[u8]) -> PyResult<Self> {
        let keypair =
            api::Keypair::from_secure_randomness(secure_randomness)
                .map_err(|err| FerveoPythonError::Other(err.to_string()))?;
        Ok(Self(keypair))
    }

    #[staticmethod]
    pub fn secure_randomness_size() -> usize {
        api::Keypair::secure_randomness_size()
    }

    pub fn public_key(&self) -> FerveoPublicKey {
        FerveoPublicKey(self.0.public_key())
    }
}

type InnerPublicKey = api::PublicKey;

#[pyclass(module = "ferveo")]
#[derive(
    Clone, PartialEq, PartialOrd, Eq, derive_more::From, derive_more::AsRef,
)]
pub struct FerveoPublicKey(InnerPublicKey);

generate_boxed_bytes_serialization!(FerveoPublicKey, InnerPublicKey);

#[pymethods]
impl FerveoPublicKey {
    // We implement `__richcmp__` because FerveoPublicKeys must be sortable in some cases
    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        let bytes = self
            .0
            .to_bytes()
            .map_err(|err| FerveoPythonError::Other(err.to_string()))?;
        hash("FerveoPublicKey", &bytes)
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct Validator(api::Validator);

#[pymethods]
impl Validator {
    #[new]
    pub fn new(
        address: String,
        public_key: &FerveoPublicKey,
    ) -> PyResult<Self> {
        let validator = api::Validator::new(address, public_key.0)
            .map_err(|err| FerveoPythonError::Other(err.to_string()))?;
        Ok(Self(validator))
    }

    #[getter]
    pub fn address(&self) -> String {
        self.0.address.to_string()
    }

    #[getter]
    pub fn public_key(&self) -> FerveoPublicKey {
        FerveoPublicKey(self.0.public_key)
    }
}

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct Transcript(api::Transcript);

generate_bytes_serialization!(Transcript);

type InnerDkgPublicKey = api::DkgPublicKey;

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct DkgPublicKey(InnerDkgPublicKey);

generate_boxed_bytes_serialization!(DkgPublicKey, InnerDkgPublicKey);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef, Clone)]
pub struct ValidatorMessage(api::ValidatorMessage);

#[pymethods]
impl ValidatorMessage {
    #[new]
    pub fn new(validator: &Validator, transcript: &Transcript) -> Self {
        Self((validator.0.clone(), transcript.0.clone()))
    }

    #[getter]
    pub fn validator(&self) -> Validator {
        Validator(self.0 .0.clone())
    }

    #[getter]
    pub fn transcript(&self) -> Transcript {
        Transcript(self.0 .1.clone())
    }
}

impl ValidatorMessage {
    pub(crate) fn to_inner(&self) -> api::ValidatorMessage {
        self.0.clone()
    }
}

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct Dkg(api::Dkg);

#[pymethods]
impl Dkg {
    #[new]
    pub fn new(
        tau: u32,
        shares_num: u32,
        security_threshold: u32,
        validators: Vec<Validator>,
        me: &Validator,
    ) -> PyResult<Self> {
        let validators: Vec<_> = validators.into_iter().map(|v| v.0).collect();
        let dkg = api::Dkg::new(
            tau,
            shares_num,
            security_threshold,
            &validators,
            &me.0,
        )
        .map_err(FerveoPythonError::from)?;
        Ok(Self(dkg))
    }

    #[getter]
    pub fn public_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.public_key())
    }

    pub fn generate_transcript(&self) -> PyResult<Transcript> {
        let rng = &mut thread_rng();
        let transcript = self
            .0
            .generate_transcript(rng)
            .map_err(FerveoPythonError::FerveoError)?;
        Ok(Transcript(transcript))
    }

    pub fn aggregate_transcripts(
        &mut self,
        messages: Vec<ValidatorMessage>,
    ) -> PyResult<AggregatedTranscript> {
        let messages: Vec<_> = messages.iter().map(|m| m.to_inner()).collect();
        let aggregated_transcript = self
            .0
            .aggregate_transcripts(&messages)
            .map_err(FerveoPythonError::FerveoError)?;
        Ok(AggregatedTranscript(aggregated_transcript))
    }
}

#[pyclass(module = "ferveo")]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    derive_more::From,
    derive_more::AsRef,
    derive_more::Into,
)]
pub struct Ciphertext(api::Ciphertext);

#[pymethods]
impl Ciphertext {
    #[getter]
    pub fn header(&self) -> PyResult<CiphertextHeader> {
        let header = self.0.header().map_err(FerveoPythonError::from)?;
        Ok(CiphertextHeader(header))
    }

    #[getter]
    pub fn payload(&self) -> Vec<u8> {
        self.0.payload().to_vec()
    }
}

generate_bytes_serialization!(Ciphertext);

#[pyclass(module = "ferveo")]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    derive_more::From,
    derive_more::AsRef,
    derive_more::Into,
)]
pub struct CiphertextHeader(api::CiphertextHeader);

generate_bytes_serialization!(CiphertextHeader);

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::AsRef, derive_more::From)]
pub struct DecryptionShareSimple(api::DecryptionShareSimple);

generate_bytes_serialization!(DecryptionShareSimple);

#[pyclass(module = "ferveo")]
#[derive(Clone, derive_more::AsRef, derive_more::From)]
pub struct DecryptionSharePrecomputed(api::DecryptionSharePrecomputed);

generate_bytes_serialization!(DecryptionSharePrecomputed);

#[pyclass(module = "ferveo")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct AggregatedTranscript(api::AggregatedTranscript);

generate_bytes_serialization!(AggregatedTranscript);

#[pymethods]
impl AggregatedTranscript {
    #[new]
    pub fn new(messages: Vec<ValidatorMessage>) -> Self {
        let messages: Vec<_> =
            messages.into_iter().map(|vm| vm.to_inner()).collect();
        Self(api::AggregatedTranscript::new(&messages))
    }

    pub fn verify(
        &self,
        shares_num: u32,
        messages: Vec<ValidatorMessage>,
    ) -> PyResult<bool> {
        let messages: Vec<_> =
            messages.into_iter().map(|vm| vm.to_inner()).collect();
        let is_valid = self
            .0
            .verify(shares_num, &messages)
            .map_err(FerveoPythonError::FerveoError)?;
        Ok(is_valid)
    }

    pub fn create_decryption_share_precomputed(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> PyResult<DecryptionSharePrecomputed> {
        let decryption_share = self
            .0
            .create_decryption_share_precomputed(
                &dkg.0,
                &ciphertext_header.0,
                aad,
                &validator_keypair.0,
            )
            .map_err(FerveoPythonError::FerveoError)?;
        Ok(DecryptionSharePrecomputed(decryption_share))
    }

    pub fn create_decryption_share_simple(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> PyResult<DecryptionShareSimple> {
        let decryption_share = self
            .0
            .create_decryption_share_simple(
                &dkg.0,
                &ciphertext_header.0,
                aad,
                &validator_keypair.0,
            )
            .map_err(FerveoPythonError::FerveoError)?;
        Ok(DecryptionShareSimple(decryption_share))
    }
}

// Since adding functions in pyo3 requires a two-step process
// (`#[pyfunction]` + `wrap_pyfunction!`), and `wrap_pyfunction`
// needs `#[pyfunction]` in the same module, we need these trampolines
// to build modules externally.

pub fn register_decrypt_with_shared_secret(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(decrypt_with_shared_secret, m)?)
}

pub fn register_combine_decryption_shares_precomputed(
    m: &PyModule,
) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(combine_decryption_shares_precomputed, m)?)
}

pub fn register_combine_decryption_shares_simple(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(combine_decryption_shares_simple, m)?)
}

pub fn register_encrypt(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)
}

pub fn make_ferveo_py_module(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    // Functions
    register_encrypt(m)?;
    register_combine_decryption_shares_simple(m)?;
    register_combine_decryption_shares_precomputed(m)?;
    register_decrypt_with_shared_secret(m)?;

    // Classes
    m.add_class::<Keypair>()?;
    m.add_class::<FerveoPublicKey>()?;
    m.add_class::<Validator>()?;
    m.add_class::<Transcript>()?;
    m.add_class::<Dkg>()?;
    m.add_class::<Ciphertext>()?;
    m.add_class::<CiphertextHeader>()?;
    m.add_class::<DecryptionShareSimple>()?;
    m.add_class::<DecryptionSharePrecomputed>()?;
    m.add_class::<AggregatedTranscript>()?;
    m.add_class::<DkgPublicKey>()?;
    m.add_class::<SharedSecret>()?;
    m.add_class::<ValidatorMessage>()?;
    m.add_class::<FerveoVariant>()?;

    // Exceptions
    m.add(
        "ThresholdEncryptionError",
        py.get_type::<ThresholdEncryptionError>(),
    )?;
    m.add(
        "InvalidDkgStateToDeal",
        py.get_type::<InvalidDkgStateToDeal>(),
    )?;
    m.add(
        "InvalidDkgStateToAggregate",
        py.get_type::<InvalidDkgStateToAggregate>(),
    )?;
    m.add(
        "InvalidDkgStateToVerify",
        py.get_type::<InvalidDkgStateToVerify>(),
    )?;
    m.add(
        "InvalidDkgStateToIngest",
        py.get_type::<InvalidDkgStateToIngest>(),
    )?;
    m.add(
        "DealerNotInValidatorSet",
        py.get_type::<DealerNotInValidatorSet>(),
    )?;
    m.add("UnknownDealer", py.get_type::<UnknownDealer>())?;
    m.add("DuplicateDealer", py.get_type::<DuplicateDealer>())?;
    m.add(
        "InvalidPvssTranscript",
        py.get_type::<InvalidPvssTranscript>(),
    )?;
    m.add(
        "InsufficientTranscriptsForAggregate",
        py.get_type::<InsufficientTranscriptsForAggregate>(),
    )?;
    m.add("InvalidDkgPublicKey", py.get_type::<InvalidDkgPublicKey>())?;
    m.add(
        "InsufficientValidators",
        py.get_type::<InsufficientValidators>(),
    )?;
    m.add(
        "InvalidTranscriptAggregate",
        py.get_type::<InvalidTranscriptAggregate>(),
    )?;
    m.add("ValidatorsNotSorted", py.get_type::<ValidatorsNotSorted>())?;
    m.add(
        "ValidatorPublicKeyMismatch",
        py.get_type::<ValidatorPublicKeyMismatch>(),
    )?;
    m.add("SerializationError", py.get_type::<SerializationError>())?;
    m.add("InvalidVariant", py.get_type::<InvalidVariant>())?;

    Ok(())
}

// TODO: Consider adding remaining ferveo/api.rs tests here
#[cfg(test)]
mod test_ferveo_python {
    use itertools::izip;

    use crate::bindings_python::*;

    type TestInputs = (Vec<ValidatorMessage>, Vec<Validator>, Vec<Keypair>);

    fn make_test_inputs(
        tau: u32,
        security_threshold: u32,
        shares_num: u32,
    ) -> TestInputs {
        let validator_keypairs = (0..shares_num)
            .map(|_| Keypair::random())
            .collect::<Vec<_>>();
        let validators: Vec<_> = validator_keypairs
            .iter()
            .enumerate()
            .map(|(i, keypair)| {
                Validator::new(format!("0x{i:040}"), &keypair.public_key())
                    .unwrap()
            })
            .collect();

        // Each validator holds their own DKG instance and generates a transcript every
        // every validator, including themselves
        let messages: Vec<_> = validators
            .iter()
            .cloned()
            .map(|sender| {
                let dkg = Dkg::new(
                    tau,
                    shares_num,
                    security_threshold,
                    validators.clone(),
                    &sender,
                )
                .unwrap();
                ValidatorMessage::new(
                    &sender,
                    &dkg.generate_transcript().unwrap(),
                )
            })
            .collect();
        (messages, validators, validator_keypairs)
    }

    #[test]
    fn test_server_api_tdec_precomputed() {
        let tau = 1;
        let shares_num = 4;
        // In precomputed variant, the security threshold is equal to the number of shares
        let security_threshold = shares_num;

        let (messages, validators, validator_keypairs) =
            make_test_inputs(tau, security_threshold, shares_num);

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts

        let me = validators[0].clone();
        let mut dkg = Dkg::new(
            tau,
            shares_num,
            security_threshold,
            validators.clone(),
            &me,
        )
        .unwrap();

        // Lets say that we've only receives `security_threshold` transcripts
        let messages = messages[..security_threshold as usize].to_vec();
        let pvss_aggregated =
            dkg.aggregate_transcripts(messages.clone()).unwrap();
        assert!(pvss_aggregated
            .verify(shares_num, messages.clone())
            .unwrap());

        // At this point, any given validator should be able to provide a DKG public key
        let dkg_public_key = dkg.public_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let msg: &[u8] = "my-msg".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let ciphertext = encrypt(msg, aad, &dkg_public_key).unwrap();

        // Having aggregated the transcripts, the validators can now create decryption shares
        let decryption_shares: Vec<_> = izip!(&validators, &validator_keypairs)
            .map(|(validator, validator_keypair)| {
                // Each validator holds their own instance of DKG and creates their own aggregate
                let mut dkg = Dkg::new(
                    tau,
                    shares_num,
                    security_threshold,
                    validators.clone(),
                    validator,
                )
                .unwrap();
                let aggregate =
                    dkg.aggregate_transcripts(messages.clone()).unwrap();
                assert!(pvss_aggregated
                    .verify(shares_num, messages.clone())
                    .is_ok());
                aggregate
                    .create_decryption_share_precomputed(
                        &dkg,
                        &ciphertext.header().unwrap(),
                        aad,
                        validator_keypair,
                    )
                    .unwrap()
            })
            .collect();

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API

        let shared_secret =
            combine_decryption_shares_precomputed(decryption_shares);

        let plaintext =
            decrypt_with_shared_secret(&ciphertext, aad, &shared_secret)
                .unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_server_api_tdec_simple() {
        let tau = 1;
        let shares_num = 4;
        let security_threshold = 3;

        let (messages, validators, validator_keypairs) =
            make_test_inputs(tau, security_threshold, shares_num);

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg = Dkg::new(
            tau,
            shares_num,
            security_threshold,
            validators.clone(),
            &me,
        )
        .unwrap();

        // Lets say that we've only receives `security_threshold` transcripts
        let messages = messages[..security_threshold as usize].to_vec();
        let pvss_aggregated =
            dkg.aggregate_transcripts(messages.clone()).unwrap();
        assert!(pvss_aggregated
            .verify(shares_num, messages.clone())
            .unwrap());

        // At this point, any given validator should be able to provide a DKG public key
        let dkg_public_key = dkg.public_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let msg: &[u8] = "my-msg".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let ciphertext = encrypt(msg, aad, &dkg_public_key).unwrap();

        // Having aggregated the transcripts, the validators can now create decryption shares
        let decryption_shares: Vec<_> = izip!(&validators, &validator_keypairs)
            .map(|(validator, validator_keypair)| {
                // Each validator holds their own instance of DKG and creates their own aggregate
                let mut dkg = Dkg::new(
                    tau,
                    shares_num,
                    security_threshold,
                    validators.clone(),
                    validator,
                )
                .unwrap();
                let aggregate =
                    dkg.aggregate_transcripts(messages.clone()).unwrap();
                assert!(aggregate
                    .verify(shares_num, messages.clone())
                    .unwrap());
                aggregate
                    .create_decryption_share_simple(
                        &dkg,
                        &ciphertext.header().unwrap(),
                        aad,
                        validator_keypair,
                    )
                    .unwrap()
            })
            .collect();

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API

        let shared_secret = combine_decryption_shares_simple(decryption_shares);

        let plaintext =
            decrypt_with_shared_secret(&ciphertext, aad, &shared_secret)
                .unwrap();
        assert_eq!(plaintext, msg);
    }
}
