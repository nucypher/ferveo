use std::{fmt, io};

use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use bincode;
use ferveo_common::serialization;
pub use ferveo_tdec::api::{
    prepare_combine_simple, share_combine_precomputed, share_combine_simple,
    Fr, G1Affine, G1Prepared, G2Affine, SecretBox, E,
};
use generic_array::{typenum::U48, GenericArray};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub type PublicKey = ferveo_common::PublicKey<E>;
pub type Keypair = ferveo_common::Keypair<E>;
pub type Validator = crate::Validator<E>;
pub type Transcript = PubliclyVerifiableSS<E>;
pub type ValidatorMessage = (Validator, Transcript);

#[cfg(feature = "bindings-python")]
use crate::bindings_python;
#[cfg(feature = "bindings-wasm")]
use crate::bindings_wasm;
pub use crate::EthereumAddress;
use crate::{
    do_verify_aggregation, DkgValidator, Error, PVSSMap,
    PubliclyVerifiableParams, PubliclyVerifiableSS, Result, ValidatorsMap,
};

pub type DecryptionSharePrecomputed =
    ferveo_tdec::api::DecryptionSharePrecomputed;

// Normally, we would use a custom trait for this, but we can't because
// the arkworks will not let us create a blanket implementation for G1Affine
// and Fr types. So instead, we're using this shared utility function:
pub fn to_bytes<T: CanonicalSerialize>(item: &T) -> Result<Vec<u8>> {
    let mut writer = Vec::new();
    item.serialize_compressed(&mut writer)?;
    Ok(writer)
}

pub fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    let mut reader = io::Cursor::new(bytes);
    let item = T::deserialize_compressed(&mut reader)?;
    Ok(item)
}

pub fn encrypt(
    message: SecretBox<Vec<u8>>,
    aad: &[u8],
    pubkey: &DkgPublicKey,
) -> Result<Ciphertext> {
    let mut rng = rand::thread_rng();
    let ciphertext =
        ferveo_tdec::api::encrypt(message, aad, &pubkey.0, &mut rng)?;
    Ok(Ciphertext(ciphertext))
}

pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
) -> Result<Vec<u8>> {
    let dkg_public_params = DkgPublicParameters::default();
    ferveo_tdec::api::decrypt_with_shared_secret(
        &ciphertext.0,
        aad,
        &shared_secret.0,
        &dkg_public_params.g1_inv,
    )
    .map_err(Error::from)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct Ciphertext(ferveo_tdec::api::Ciphertext);

impl Ciphertext {
    pub fn header(&self) -> Result<CiphertextHeader> {
        Ok(CiphertextHeader(self.0.header()?))
    }

    pub fn payload(&self) -> Vec<u8> {
        self.0.payload()
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextHeader(ferveo_tdec::api::CiphertextHeader);

/// The ferveo variant to use for the decryption share derivation.
#[derive(
    PartialEq, Eq, Debug, Serialize, Deserialize, Copy, Clone, PartialOrd,
)]
pub enum FerveoVariant {
    /// The simple variant requires m of n shares to decrypt
    Simple,
    /// The precomputed variant requires n of n shares to decrypt
    Precomputed,
}

impl fmt::Display for FerveoVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FerveoVariant {
    pub fn as_str(&self) -> &'static str {
        match self {
            FerveoVariant::Simple => "FerveoVariant::Simple",
            FerveoVariant::Precomputed => "FerveoVariant::Precomputed",
        }
    }

    pub fn from_string(s: &str) -> Result<Self> {
        match s {
            "FerveoVariant::Simple" => Ok(FerveoVariant::Simple),
            "FerveoVariant::Precomputed" => Ok(FerveoVariant::Precomputed),
            _ => Err(Error::InvalidVariant(s.to_string())),
        }
    }
}

#[cfg(feature = "bindings-python")]
impl From<bindings_python::FerveoVariant> for FerveoVariant {
    fn from(variant: bindings_python::FerveoVariant) -> Self {
        variant.0
    }
}

#[cfg(feature = "bindings-wasm")]
impl From<bindings_wasm::FerveoVariant> for FerveoVariant {
    fn from(variant: bindings_wasm::FerveoVariant) -> Self {
        variant.0
    }
}

#[serde_as]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DkgPublicKey(
    #[serde_as(as = "serialization::SerdeAs")] pub(crate) G1Affine,
);

impl DkgPublicKey {
    pub fn to_bytes(&self) -> Result<GenericArray<u8, U48>> {
        let as_bytes = to_bytes(&self.0)?;
        Ok(GenericArray::<u8, U48>::from_slice(&as_bytes).to_owned())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<DkgPublicKey> {
        let bytes =
            GenericArray::<u8, U48>::from_exact_iter(bytes.iter().cloned())
                .ok_or_else(|| {
                    Error::InvalidByteLength(
                        Self::serialized_size(),
                        bytes.len(),
                    )
                })?;
        from_bytes(&bytes).map(DkgPublicKey)
    }

    pub fn serialized_size() -> usize {
        48
    }

    /// Generate a random DKG public key.
    /// Use this for testing only.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let g1 = G1Affine::rand(&mut rng);
        Self(g1)
    }
}

pub type UnblindingKey = FieldPoint;

#[serde_as]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldPoint(#[serde_as(as = "serialization::SerdeAs")] pub Fr);

impl FieldPoint {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_bytes(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<FieldPoint> {
        from_bytes(bytes).map(FieldPoint)
    }
}

#[derive(Clone)]
pub struct Dkg(crate::PubliclyVerifiableDkg<E>);

impl Dkg {
    pub fn new(
        tau: u32,
        shares_num: u32,
        security_threshold: u32,
        validators: &[Validator],
        me: &Validator,
    ) -> Result<Self> {
        let dkg_params =
            crate::DkgParams::new(tau, security_threshold, shares_num)?;
        let dkg = crate::PubliclyVerifiableDkg::<E>::new(
            validators,
            &dkg_params,
            me,
        )?;
        Ok(Self(dkg))
    }

    pub fn public_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.public_key())
    }

    pub fn generate_transcript<R: RngCore>(
        &self,
        rng: &mut R,
    ) -> Result<Transcript> {
        self.0.create_share(rng)
    }

    pub fn aggregate_transcripts(
        &mut self,
        messages: &[ValidatorMessage],
    ) -> Result<AggregatedTranscript> {
        // We must use `deal` here instead of to produce AggregatedTranscript instead of simply
        // creating an AggregatedTranscript from the messages, because `deal` also updates the
        // internal state of the DKG.
        // If we didn't do that, that would cause the DKG to produce incorrect decryption shares
        // in the future.
        // TODO: Remove this dependency on DKG state
        // TODO: Avoid mutating current state here
        for (validator, transcript) in messages {
            self.0.deal(validator, transcript)?;
        }
        Ok(AggregatedTranscript(crate::pvss::aggregate(&self.0.vss)))
    }

    pub fn public_params(&self) -> DkgPublicParameters {
        DkgPublicParameters {
            g1_inv: self.0.pvss_params.g_inv(),
        }
    }
}

fn make_pvss_map(messages: &[ValidatorMessage]) -> PVSSMap<E> {
    let mut pvss_map: PVSSMap<E> = PVSSMap::new();
    messages.iter().for_each(|(validator, transcript)| {
        pvss_map.insert(validator.address.clone(), transcript.clone());
    });
    pvss_map
}

fn make_validator_map(messages: &[ValidatorMessage]) -> ValidatorsMap<E> {
    let mut validator_map = ValidatorsMap::new();
    // TODO: Don't use enumerate here. Instead, add `share_index` to `ValidatorMessage`
    messages.iter().enumerate().for_each(
        |(share_index, (validator, _transcript))| {
            let dkg_validator = DkgValidator {
                share_index,
                validator: Validator {
                    address: validator.address.clone(),
                    public_key: validator.public_key,
                },
            };
            validator_map.insert(validator.address.clone(), dkg_validator);
        },
    );
    validator_map
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedTranscript(PubliclyVerifiableSS<E, crate::Aggregated>);

impl AggregatedTranscript {
    pub fn new(messages: &[ValidatorMessage]) -> Self {
        let pvss_map = make_pvss_map(messages);
        AggregatedTranscript(crate::pvss::aggregate(&pvss_map))
    }

    pub fn verify(
        &self,
        shares_num: u32,
        messages: &[ValidatorMessage],
    ) -> Result<bool> {
        let pvss_params = PubliclyVerifiableParams::<E>::default();
        let domain = GeneralEvaluationDomain::<Fr>::new(shares_num as usize)
            .expect("Unable to construct an evaluation domain");

        let is_valid_optimistic = self.0.verify_optimistic();
        if !is_valid_optimistic {
            return Err(Error::InvalidTranscriptAggregate);
        }

        // TODO: Can we simplify this? Do we need another map?
        // TODO: See if do_verify_aggregation can be simplified in terms of parameters
        let pvss_map = make_pvss_map(messages);
        let validators = make_validator_map(messages);

        // This check also includes `verify_full`. See impl. for details.
        let is_valid = do_verify_aggregation(
            &self.0.coeffs,
            &self.0.shares,
            &pvss_params,
            &validators,
            &domain,
            &pvss_map,
        )?;
        Ok(is_valid)
    }

    pub fn create_decryption_share_precomputed(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> Result<DecryptionSharePrecomputed> {
        let domain_points: Vec<_> = dkg
            .0
            .domain
            .elements()
            .take(dkg.0.dkg_params.shares_num() as usize)
            .collect();
        self.0.make_decryption_share_simple_precomputed(
            &ciphertext_header.0,
            aad,
            &validator_keypair.decryption_key,
            dkg.0.me.share_index,
            &domain_points,
            &dkg.0.pvss_params.g_inv(),
        )
    }

    pub fn create_decryption_share_simple(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> Result<DecryptionShareSimple> {
        let share = self.0.make_decryption_share_simple(
            &ciphertext_header.0,
            aad,
            &validator_keypair.decryption_key,
            dkg.0.me.share_index,
            &dkg.0.pvss_params.g_inv(),
        )?;
        Ok(DecryptionShareSimple {
            share,
            domain_point: dkg.0.domain.element(dkg.0.me.share_index),
        })
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionShareSimple {
    share: ferveo_tdec::api::DecryptionShareSimple,
    #[serde_as(as = "serialization::SerdeAs")]
    domain_point: Fr,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DkgPublicParameters {
    #[serde_as(as = "serialization::SerdeAs")]
    pub(crate) g1_inv: G1Prepared,
}

impl Default for DkgPublicParameters {
    fn default() -> Self {
        DkgPublicParameters {
            g1_inv: PubliclyVerifiableParams::<E>::default().g_inv(),
        }
    }
}

impl DkgPublicParameters {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| e.into())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }
}

pub fn combine_shares_simple(shares: &[DecryptionShareSimple]) -> SharedSecret {
    // Pick domain points that are corresponding to the shares we have.
    let domain_points: Vec<_> = shares.iter().map(|s| s.domain_point).collect();
    let lagrange_coefficients = prepare_combine_simple::<E>(&domain_points);

    let shares: Vec<_> = shares.iter().cloned().map(|s| s.share).collect();
    let shared_secret =
        share_combine_simple(&shares, &lagrange_coefficients[..]);
    SharedSecret(shared_secret)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedSecret(pub ferveo_tdec::api::SharedSecret<E>);

#[cfg(test)]
mod test_ferveo_api {
    use ferveo_tdec::SecretBox;
    use itertools::izip;
    use rand::{prelude::StdRng, SeedableRng};

    use crate::{api::*, dkg::test_common::*};

    type TestInputs = (Vec<ValidatorMessage>, Vec<Validator>, Vec<Keypair>);

    fn make_test_inputs(
        rng: &mut StdRng,
        tau: u32,
        security_threshold: u32,
        shares_num: u32,
    ) -> TestInputs {
        let validator_keypairs = gen_keypairs(shares_num);
        let validators = validator_keypairs
            .iter()
            .enumerate()
            .map(|(i, keypair)| Validator {
                address: gen_address(i),
                public_key: keypair.public_key(),
            })
            .collect::<Vec<_>>();

        // Each validator holds their own DKG instance and generates a transcript every
        // every validator, including themselves
        let messages: Vec<_> = validators
            .iter()
            .map(|sender| {
                let dkg = Dkg::new(
                    tau,
                    shares_num,
                    security_threshold,
                    &validators,
                    sender,
                )
                .unwrap();
                (sender.clone(), dkg.generate_transcript(rng).unwrap())
            })
            .collect();
        (messages, validators, validator_keypairs)
    }

    #[test]
    fn test_dkg_pk_serialization() {
        let dkg_pk = DkgPublicKey::random();
        let serialized = dkg_pk.to_bytes().unwrap();
        let deserialized = DkgPublicKey::from_bytes(&serialized).unwrap();
        assert_eq!(dkg_pk, deserialized);
    }

    #[test]
    fn test_server_api_tdec_precomputed() {
        let rng = &mut StdRng::seed_from_u64(0);

        // Works for both power of 2 and non-power of 2
        for shares_num in [4, 7] {
            let tau = 1;
            // In precomputed variant, the security threshold is equal to the number of shares
            // TODO: Refactor DKG constructor to not require security threshold or this case.
            //  Or figure out a different way to simplify the precomputed variant API.
            let security_threshold = shares_num;

            let (messages, validators, validator_keypairs) =
                make_test_inputs(rng, tau, security_threshold, shares_num);

            // Now that every validator holds a dkg instance and a transcript for every other validator,
            // every validator can aggregate the transcripts
            let me = validators[0].clone();
            let mut dkg =
                Dkg::new(tau, shares_num, security_threshold, &validators, &me)
                    .unwrap();

            let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();
            assert!(pvss_aggregated.verify(shares_num, &messages).unwrap());

            // At this point, any given validator should be able to provide a DKG public key
            let dkg_public_key = dkg.public_key();

            // In the meantime, the client creates a ciphertext and decryption request
            let msg = "my-msg".as_bytes().to_vec();
            let aad: &[u8] = "my-aad".as_bytes();
            let ciphertext =
                encrypt(SecretBox::new(msg.clone()), aad, &dkg_public_key)
                    .unwrap();

            // Having aggregated the transcripts, the validators can now create decryption shares
            let decryption_shares: Vec<_> =
                izip!(&validators, &validator_keypairs)
                    .map(|(validator, validator_keypair)| {
                        // Each validator holds their own instance of DKG and creates their own aggregate
                        let mut dkg = Dkg::new(
                            tau,
                            shares_num,
                            security_threshold,
                            &validators,
                            validator,
                        )
                        .unwrap();
                        let aggregate =
                            dkg.aggregate_transcripts(&messages).unwrap();
                        assert!(pvss_aggregated
                            .verify(shares_num, &messages)
                            .unwrap());

                        // And then each validator creates their own decryption share
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

            let shared_secret = share_combine_precomputed(&decryption_shares);
            let plaintext = decrypt_with_shared_secret(
                &ciphertext,
                aad,
                &SharedSecret(shared_secret),
            )
            .unwrap();
            assert_eq!(plaintext, msg);

            // Since we're using a precomputed variant, we need all the shares to be able to decrypt
            // So if we remove one share, we should not be able to decrypt
            let decryption_shares =
                decryption_shares[..shares_num as usize - 1].to_vec();

            let shared_secret = share_combine_precomputed(&decryption_shares);
            let result = decrypt_with_shared_secret(
                &ciphertext,
                aad,
                &SharedSecret(shared_secret),
            );
            assert!(result.is_err());
        }
    }

    #[test]

    fn test_server_api_tdec_simple() {
        let rng = &mut StdRng::seed_from_u64(0);

        // Works for both power of 2 and non-power of 2
        for shares_num in [4, 7] {
            let tau = 1;
            let security_threshold = shares_num / 2 + 1;

            let (messages, validators, validator_keypairs) =
                make_test_inputs(rng, tau, security_threshold, shares_num);

            // Now that every validator holds a dkg instance and a transcript for every other validator,
            // every validator can aggregate the transcripts
            let mut dkg = Dkg::new(
                tau,
                shares_num,
                security_threshold,
                &validators,
                &validators[0],
            )
            .unwrap();

            let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();
            assert!(pvss_aggregated.verify(shares_num, &messages).unwrap());

            // At this point, any given validator should be able to provide a DKG public key
            let public_key = dkg.public_key();

            // In the meantime, the client creates a ciphertext and decryption request
            let msg = "my-msg".as_bytes().to_vec();
            let aad: &[u8] = "my-aad".as_bytes();
            let ciphertext =
                encrypt(SecretBox::new(msg.clone()), aad, &public_key).unwrap();

            // Having aggregated the transcripts, the validators can now create decryption shares
            let decryption_shares: Vec<_> =
                izip!(&validators, &validator_keypairs)
                    .map(|(validator, validator_keypair)| {
                        // Each validator holds their own instance of DKG and creates their own aggregate
                        let mut dkg = Dkg::new(
                            tau,
                            shares_num,
                            security_threshold,
                            &validators,
                            validator,
                        )
                        .unwrap();
                        let aggregate =
                            dkg.aggregate_transcripts(&messages).unwrap();
                        assert!(aggregate
                            .verify(shares_num, &messages)
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

            // In simple variant, we only need `security_threshold` shares to be able to decrypt
            let decryption_shares =
                decryption_shares[..security_threshold as usize].to_vec();

            let shared_secret = combine_shares_simple(&decryption_shares);
            let plaintext =
                decrypt_with_shared_secret(&ciphertext, aad, &shared_secret)
                    .unwrap();
            assert_eq!(plaintext, msg);

            // Let's say that we've only received `security_threshold - 1` shares
            // In this case, we should not be able to decrypt
            let decryption_shares =
                decryption_shares[..security_threshold as usize - 1].to_vec();

            let shared_secret = combine_shares_simple(&decryption_shares);
            let result =
                decrypt_with_shared_secret(&ciphertext, aad, &shared_secret);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_server_api_tdec_simple_with_min_shares() {
        let rng = &mut StdRng::seed_from_u64(0);

        // Works for both power of 2 and non-power of 2
        for shares_num in [4, 7] {
            let tau = 1;
            let security_threshold = shares_num - 1;

            let (messages, validators, validator_keypairs) =
                make_test_inputs(rng, tau, security_threshold, shares_num);

            // Now that every validator holds a dkg instance and a transcript for every other validator,
            // every validator can aggregate the transcripts
            let mut dkg = Dkg::new(
                tau,
                shares_num,
                security_threshold,
                &validators,
                &validators[0],
            )
            .unwrap();

            let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();
            assert!(pvss_aggregated.verify(shares_num, &messages).unwrap());

            // At this point, any given validator should be able to provide a DKG public key
            let public_key = dkg.public_key();

            // In the meantime, the client creates a ciphertext and decryption request
            let msg = "my-msg".as_bytes().to_vec();
            let aad: &[u8] = "my-aad".as_bytes();
            let ciphertext =
                encrypt(SecretBox::new(msg.clone()), aad, &public_key).unwrap();

            // Having aggregated the transcripts, the validators can now create decryption shares
            let decryption_shares: Vec<_> =
                izip!(&validators, &validator_keypairs)
                    .map(|(validator, validator_keypair)| {
                        // Each validator holds their own instance of DKG and creates their own aggregate
                        let mut dkg = Dkg::new(
                            tau,
                            shares_num,
                            security_threshold,
                            &validators,
                            validator,
                        )
                        .unwrap();
                        let aggregate =
                            dkg.aggregate_transcripts(&messages).unwrap();
                        assert!(aggregate
                            .verify(shares_num, &messages)
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

            // In simple variant, we only need `security_threshold` shares to be able to decrypt
            let decryption_shares =
                decryption_shares[..security_threshold as usize].to_vec();

            let shared_secret = combine_shares_simple(&decryption_shares);
            let plaintext =
                decrypt_with_shared_secret(&ciphertext, aad, &shared_secret)
                    .unwrap();
            assert_eq!(plaintext, msg);

            // Let's say that we've only received `security_threshold - 1` shares
            // In this case, we should not be able to decrypt
            let decryption_shares =
                decryption_shares[..security_threshold as usize - 1].to_vec();

            let shared_secret = combine_shares_simple(&decryption_shares);
            let result =
                decrypt_with_shared_secret(&ciphertext, aad, &shared_secret);
            assert!(result.is_err());
        }
    }

    #[test]
    fn server_side_local_verification() {
        let rng = &mut StdRng::seed_from_u64(0);

        let tau = 1;
        let security_threshold = 3;
        let shares_num = 4;

        let (messages, validators, _) =
            make_test_inputs(rng, tau, security_threshold, shares_num);

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg =
            Dkg::new(tau, shares_num, security_threshold, &validators, &me)
                .unwrap();

        let local_aggregate = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(local_aggregate
            .verify(dkg.0.dkg_params.shares_num(), &messages)
            .is_ok());
    }

    #[test]
    fn client_side_local_verification() {
        let rng = &mut StdRng::seed_from_u64(0);

        let tau = 1;
        let security_threshold = 3;
        let shares_num = 4;

        let (messages, _, _) =
            make_test_inputs(rng, tau, security_threshold, shares_num);

        // We only need `security_threshold` transcripts to aggregate
        let messages = &messages[..security_threshold as usize];

        // Create an aggregated transcript on the client side
        let aggregated_transcript = AggregatedTranscript::new(messages);

        // We are separating the verification from the aggregation since the client may fetch
        // the aggregate from a side-channel or decide to persist it and verify it later

        // Now, the client can verify the aggregated transcript
        let result = aggregated_transcript.verify(shares_num, messages);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test negative cases

        // Not enough transcripts
        let not_enough_messages = &messages[..2];
        assert!(not_enough_messages.len() < security_threshold as usize);
        let insufficient_aggregate =
            AggregatedTranscript::new(not_enough_messages);
        let result = insufficient_aggregate.verify(shares_num, messages);
        assert!(result.is_err());

        // Unexpected transcripts in the aggregate or transcripts from a different ritual
        // Using same DKG parameters, but different DKG instances and validators
        let (bad_messages, _, _) =
            make_test_inputs(rng, tau, security_threshold, shares_num);
        let mixed_messages = [&messages[..2], &bad_messages[..1]].concat();
        let bad_aggregate = AggregatedTranscript::new(&mixed_messages);
        let result = bad_aggregate.verify(shares_num, messages);
        assert!(result.is_err());
    }
}
