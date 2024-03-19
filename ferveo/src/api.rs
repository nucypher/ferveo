use std::{fmt, io};

use ark_ec::CurveGroup;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use bincode;
use ferveo_common::serialization;
pub use ferveo_tdec::api::{
    prepare_combine_simple, share_combine_precomputed, share_combine_simple,
    DecryptionSharePrecomputed, Fr, G1Affine, G1Prepared, G2Affine, SecretBox,
    E,
};
use ferveo_tdec::PublicKeyShare;
use generic_array::{
    typenum::{Unsigned, U48},
    GenericArray,
};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[cfg(feature = "bindings-python")]
use crate::bindings_python;
#[cfg(feature = "bindings-wasm")]
use crate::bindings_wasm;
pub use crate::EthereumAddress;
use crate::{
    do_verify_aggregation, DomainPoint, Error, Message, PVSSMap,
    PubliclyVerifiableParams, PubliclyVerifiableSS, Result,
};

pub type PublicKey = ferveo_common::PublicKey<E>;
pub type Keypair = ferveo_common::Keypair<E>;
pub type Validator = crate::Validator<E>;
pub type Transcript = PubliclyVerifiableSS<E>;
pub type ValidatorMessage = (Validator, Transcript);

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
    let ciphertext = ferveo_tdec::api::encrypt(
        message,
        aad,
        &PublicKeyShare {
            public_key_share: pubkey.0,
        },
        &mut rng,
    )?;
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
    // TODO: Consider not using G1Affine directly here
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
        U48::to_usize()
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
        DkgPublicKey(self.0.public_key().public_key_share)
    }

    pub fn generate_transcript<R: RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<Transcript> {
        match self.0.share(rng) {
            Ok(Message::Deal(transcript)) => Ok(transcript),
            Err(e) => Err(e),
            _ => Err(Error::InvalidDkgStateToDeal),
        }
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
        let pvss = messages
            .iter()
            .map(|(_, t)| t)
            .cloned()
            .collect::<Vec<PubliclyVerifiableSS<E>>>();
        Ok(AggregatedTranscript(crate::pvss::aggregate(&pvss)?))
    }

    pub fn public_params(&self) -> DkgPublicParameters {
        DkgPublicParameters {
            g1_inv: self.0.pvss_params.g_inv(),
        }
    }

    pub fn me(&self) -> &Validator {
        &self.0.me
    }

    pub fn domain_points(&self) -> Vec<DomainPoint<E>> {
        self.0.domain_points()
    }
}

fn make_pvss_map(messages: &[ValidatorMessage]) -> PVSSMap<E> {
    let mut pvss_map: PVSSMap<E> = PVSSMap::new();
    messages.iter().for_each(|(validator, transcript)| {
        pvss_map.insert(validator.address.clone(), transcript.clone());
    });
    pvss_map
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedTranscript(
    pub(crate) PubliclyVerifiableSS<E, crate::Aggregated>,
);

impl AggregatedTranscript {
    pub fn new(messages: &[ValidatorMessage]) -> Result<Self> {
        let pvss_list = messages
            .iter()
            .map(|(_, t)| t)
            .cloned()
            .collect::<Vec<PubliclyVerifiableSS<E>>>();
        Ok(AggregatedTranscript(crate::pvss::aggregate(&pvss_list)?))
    }

    pub fn verify(
        &self,
        validators_num: u32,
        messages: &[ValidatorMessage],
    ) -> Result<bool> {
        if validators_num < messages.len() as u32 {
            return Err(Error::InvalidAggregateVerificationParameters(
                validators_num,
                messages.len() as u32,
            ));
        }

        let pvss_params = PubliclyVerifiableParams::<E>::default();
        let domain =
            GeneralEvaluationDomain::<Fr>::new(validators_num as usize)
                .expect("Unable to construct an evaluation domain");

        let is_valid_optimistic = self.0.verify_optimistic();
        if !is_valid_optimistic {
            return Err(Error::InvalidTranscriptAggregate);
        }

        let pvss_map = make_pvss_map(messages);
        let validators: Vec<_> = messages
            .iter()
            .map(|(validator, _)| validator)
            .cloned()
            .collect();

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

    // TODO: Consider deprecating in favor of PrivateKeyShare::create_decryption_share_simple
    pub fn create_decryption_share_precomputed(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> Result<DecryptionSharePrecomputed> {
        // Prevent users from using the precomputed variant with improper DKG parameters
        if dkg.0.dkg_params.shares_num()
            != dkg.0.dkg_params.security_threshold()
        {
            return Err(Error::InvalidDkgParametersForPrecomputedVariant(
                dkg.0.dkg_params.shares_num(),
                dkg.0.dkg_params.security_threshold(),
            ));
        }
        self.0.create_decryption_share_simple_precomputed(
            &ciphertext_header.0,
            aad,
            validator_keypair,
            dkg.0.me.share_index,
            &dkg.0.domain_points(),
            &dkg.0.pvss_params.g_inv(),
        )
    }

    // TODO: Consider deprecating in favor of PrivateKeyShare::create_decryption_share_simple
    pub fn create_decryption_share_simple(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> Result<DecryptionShareSimple> {
        let share = self.0.create_decryption_share_simple(
            &ciphertext_header.0,
            aad,
            validator_keypair,
            dkg.0.me.share_index,
            &dkg.0.pvss_params.g_inv(),
        )?;
        let domain_point = dkg.0.get_domain_point(dkg.0.me.share_index)?;
        Ok(DecryptionShareSimple {
            share,
            domain_point,
        })
    }

    pub fn get_private_key_share(
        &self,
        validator_keypair: &Keypair,
        share_index: u32,
    ) -> Result<PrivateKeyShare> {
        Ok(PrivateKeyShare(
            self.0
                .decrypt_private_key_share(validator_keypair, share_index)?
                .0
                .clone(),
        ))
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionShareSimple {
    share: ferveo_tdec::api::DecryptionShareSimple,
    #[serde_as(as = "serialization::SerdeAs")]
    domain_point: Fr,
}

// TODO: Deprecate?
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// TODO: serde is failing to serialize E = ark_bls12_381::Bls12_381
// pub struct ShareRecoveryUpdate(pub crate::refresh::ShareRecoveryUpdate<E>);
pub struct ShareRecoveryUpdate(pub ferveo_tdec::PrivateKeyShare<E>);

impl ShareRecoveryUpdate {
    // TODO: There are two recovery scenarios: at random and at a specific point. Do we ever want
    // to recover at a specific point? What scenario would that be? Validator rotation?
    pub fn create_share_updates(
        // TODO: Decouple from Dkg? We don't need any specific Dkg instance here, just some params etc
        dkg: &Dkg,
        x_r: &DomainPoint<E>,
    ) -> Result<Vec<ShareRecoveryUpdate>> {
        let rng = &mut thread_rng();
        let updates =
            crate::refresh::ShareRecoveryUpdate::create_share_updates(
                &dkg.0.domain_points(),
                &dkg.0.pvss_params.h.into_affine(),
                x_r,
                dkg.0.dkg_params.security_threshold(),
                rng,
            )
            .iter()
            .map(|update| ShareRecoveryUpdate(update.0.clone()))
            .collect();
        Ok(updates)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| e.into())
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRefreshUpdate(pub ferveo_tdec::PrivateKeyShare<E>);

impl ShareRefreshUpdate {
    pub fn create_share_updates(dkg: &Dkg) -> Result<Vec<ShareRefreshUpdate>> {
        let rng = &mut thread_rng();
        let updates = crate::refresh::ShareRefreshUpdate::create_share_updates(
            &dkg.0.domain_points(),
            &dkg.0.pvss_params.h.into_affine(),
            dkg.0.dkg_params.security_threshold(),
            rng,
        )
        .iter()
        .map(|update| ShareRefreshUpdate(update.0.clone()))
        .collect();
        Ok(updates)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| e.into())
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatedPrivateKeyShare(pub ferveo_tdec::PrivateKeyShare<E>);

impl UpdatedPrivateKeyShare {
    pub fn into_private_key_share(self) -> PrivateKeyShare {
        PrivateKeyShare(self.0)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| e.into())
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKeyShare(pub ferveo_tdec::PrivateKeyShare<E>);

impl PrivateKeyShare {
    pub fn create_updated_private_key_share_for_recovery(
        &self,
        share_updates: &[ShareRecoveryUpdate],
    ) -> Result<UpdatedPrivateKeyShare> {
        let share_updates: Vec<_> = share_updates
            .iter()
            .map(|update| crate::refresh::ShareRecoveryUpdate(update.0.clone()))
            .collect();
        // TODO: Remove this wrapping after figuring out serde_as
        let updated_key_share = crate::PrivateKeyShare(self.0.clone())
            .create_updated_key_share(&share_updates);
        Ok(UpdatedPrivateKeyShare(updated_key_share.0.clone()))
    }

    pub fn create_updated_private_key_share_for_refresh(
        &self,
        share_updates: &[ShareRefreshUpdate],
    ) -> Result<UpdatedPrivateKeyShare> {
        let share_updates: Vec<_> = share_updates
            .iter()
            .map(|update| crate::refresh::ShareRefreshUpdate(update.0.clone()))
            .collect();
        let updated_key_share = crate::PrivateKeyShare(self.0.clone())
            .create_updated_key_share(&share_updates);
        Ok(UpdatedPrivateKeyShare(updated_key_share.0.clone()))
    }

    /// Recover a private key share from updated private key shares
    pub fn recover_share_from_updated_private_shares(
        x_r: &DomainPoint<E>,
        domain_points: &[DomainPoint<E>],
        updated_shares: &[UpdatedPrivateKeyShare],
    ) -> Result<PrivateKeyShare> {
        let updated_shares: Vec<_> = updated_shares
            .iter()
            // TODO: Remove this wrapping after figuring out serde_as
            .map(|s| crate::refresh::UpdatedPrivateKeyShare(s.0.clone()))
            .collect();
        let share =
            crate::PrivateKeyShare::recover_share_from_updated_private_shares(
                x_r,
                domain_points,
                &updated_shares[..],
            );
        Ok(PrivateKeyShare(share.0.clone()))
    }

    /// Make a decryption share (simple variant) for a given ciphertext
    pub fn create_decryption_share_simple(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        validator_keypair: &Keypair,
        aad: &[u8],
    ) -> Result<DecryptionShareSimple> {
        let share = crate::PrivateKeyShare(self.0.clone())
            .create_decryption_share_simple(
                &ciphertext_header.0,
                aad,
                validator_keypair,
                &dkg.public_params().g1_inv,
            )?;
        let domain_point = dkg.0.get_domain_point(dkg.0.me.share_index)?;
        Ok(DecryptionShareSimple {
            share,
            domain_point,
        })
    }

    /// Make a decryption share (precomputed variant) for a given ciphertext
    pub fn create_decryption_share_simple_precomputed(
        &self,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
        share_index: u32,
        domain_points: &[DomainPoint<E>],
    ) -> Result<DecryptionSharePrecomputed> {
        let dkg_public_params = DkgPublicParameters::default();
        let share = crate::PrivateKeyShare(self.0.clone())
            .create_decryption_share_simple_precomputed(
                &ciphertext_header.0,
                aad,
                validator_keypair,
                share_index,
                domain_points,
                &dkg_public_params.g1_inv,
            )?;
        Ok(share)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test_ferveo_api {
    use std::collections::HashMap;

    use ark_std::iterable::Iterable;
    use ferveo_tdec::SecretBox;
    use itertools::{izip, Itertools};
    use rand::{
        prelude::{SliceRandom, StdRng},
        SeedableRng,
    };
    use test_case::test_case;

    use crate::{
        api::*,
        test_common::{gen_address, gen_keypairs, AAD, MSG, TAU},
    };

    type TestInputs = (Vec<ValidatorMessage>, Vec<Validator>, Vec<Keypair>);

    fn make_test_inputs(
        rng: &mut StdRng,
        tau: u32,
        security_threshold: u32,
        shares_num: u32,
        validators_num: u32,
    ) -> TestInputs {
        let validator_keypairs = gen_keypairs(validators_num);
        let validators = validator_keypairs
            .iter()
            .enumerate()
            .map(|(i, keypair)| Validator {
                address: gen_address(i),
                public_key: keypair.public_key(),
                share_index: i as u32,
            })
            .collect::<Vec<_>>();

        // Each validator holds their own DKG instance and generates a transcript every
        // validator, including themselves
        let messages: Vec<_> = validators
            .iter()
            .map(|sender| {
                let mut dkg = Dkg::new(
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
        assert_eq!(serialized.len(), 48_usize);
        assert_eq!(dkg_pk, deserialized);
    }

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn test_server_api_tdec_precomputed(shares_num: u32, validators_num: u32) {
        let rng = &mut StdRng::seed_from_u64(0);

        // In precomputed variant, the security threshold is equal to the number of shares
        let security_threshold = shares_num;

        let (messages, validators, validator_keypairs) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();

        let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(pvss_aggregated.verify(validators_num, &messages).unwrap());

        // At this point, any given validator should be able to provide a DKG public key
        let dkg_public_key = dkg.public_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let ciphertext =
            encrypt(SecretBox::new(MSG.to_vec()), AAD, &dkg_public_key)
                .unwrap();

        // Having aggregated the transcripts, the validators can now create decryption shares
        let mut decryption_shares: Vec<_> =
            izip!(&validators, &validator_keypairs)
                .map(|(validator, validator_keypair)| {
                    // Each validator holds their own instance of DKG and creates their own aggregate
                    let mut dkg = Dkg::new(
                        TAU,
                        shares_num,
                        security_threshold,
                        &validators,
                        validator,
                    )
                    .unwrap();
                    let aggregate =
                        dkg.aggregate_transcripts(&messages).unwrap();
                    assert!(pvss_aggregated
                        .verify(validators_num, &messages)
                        .unwrap());

                    // And then each validator creates their own decryption share
                    aggregate
                        .create_decryption_share_precomputed(
                            &dkg,
                            &ciphertext.header().unwrap(),
                            AAD,
                            validator_keypair,
                        )
                        .unwrap()
                })
                .collect();
        decryption_shares.shuffle(rng);

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API

        let shared_secret = share_combine_precomputed(&decryption_shares);
        let plaintext = decrypt_with_shared_secret(
            &ciphertext,
            AAD,
            &SharedSecret(shared_secret),
        )
        .unwrap();
        assert_eq!(plaintext, MSG);

        // Since we're using a precomputed variant, we need all the shares to be able to decrypt
        // So if we remove one share, we should not be able to decrypt

        let decryption_shares =
            decryption_shares[..shares_num as usize - 1].to_vec();
        let shared_secret = share_combine_precomputed(&decryption_shares);
        let result = decrypt_with_shared_secret(
            &ciphertext,
            AAD,
            &SharedSecret(shared_secret),
        );
        assert!(result.is_err());
    }

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn test_server_api_tdec_simple(shares_num: u32, validators_num: u32) {
        let rng = &mut StdRng::seed_from_u64(0);
        let security_threshold = shares_num / 2 + 1;

        let (messages, validators, validator_keypairs) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let mut dkg = Dkg::new(
            TAU,
            shares_num,
            security_threshold,
            &validators,
            &validators[0],
        )
        .unwrap();

        let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(pvss_aggregated.verify(validators_num, &messages).unwrap());

        // At this point, any given validator should be able to provide a DKG public key
        let public_key = dkg.public_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let ciphertext =
            encrypt(SecretBox::new(MSG.to_vec()), AAD, &public_key).unwrap();

        // Having aggregated the transcripts, the validators can now create decryption shares
        let mut decryption_shares: Vec<_> =
            izip!(&validators, &validator_keypairs)
                .map(|(validator, validator_keypair)| {
                    // Each validator holds their own instance of DKG and creates their own aggregate
                    let mut dkg = Dkg::new(
                        TAU,
                        shares_num,
                        security_threshold,
                        &validators,
                        validator,
                    )
                    .unwrap();
                    let aggregate =
                        dkg.aggregate_transcripts(&messages).unwrap();
                    assert!(aggregate
                        .verify(validators_num, &messages)
                        .unwrap());
                    aggregate
                        .create_decryption_share_simple(
                            &dkg,
                            &ciphertext.header().unwrap(),
                            AAD,
                            validator_keypair,
                        )
                        .unwrap()
                })
                .collect();
        decryption_shares.shuffle(rng);

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API

        // In simple variant, we only need `security_threshold` shares to be able to decrypt
        let decryption_shares =
            decryption_shares[..security_threshold as usize].to_vec();

        let shared_secret = combine_shares_simple(&decryption_shares);
        let plaintext =
            decrypt_with_shared_secret(&ciphertext, AAD, &shared_secret)
                .unwrap();
        assert_eq!(plaintext, MSG);

        // Let's say that we've only received `security_threshold - 1` shares
        // In this case, we should not be able to decrypt
        let decryption_shares =
            decryption_shares[..security_threshold as usize - 1].to_vec();

        let shared_secret = combine_shares_simple(&decryption_shares);
        let result =
            decrypt_with_shared_secret(&ciphertext, AAD, &shared_secret);
        assert!(result.is_err());
    }

    // Note that the server and client code are using the same underlying
    // implementation for aggregation and aggregate verification.
    // Here, we focus on testing user-facing APIs for server and client users.

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn server_side_local_verification(shares_num: u32, validators_num: u32) {
        let rng = &mut StdRng::seed_from_u64(0);
        let security_threshold = shares_num / 2 + 1;

        let (messages, validators, _) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();

        let good_aggregate = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(good_aggregate.verify(validators_num, &messages).is_ok());

        // Test negative cases

        // Notice that the dkg instance is mutable, so we need to get a fresh one
        // for every test case

        // Should fail if the number of validators is less than the number of messages
        assert!(matches!(
            good_aggregate.verify(messages.len() as u32 - 1, &messages),
            Err(Error::InvalidAggregateVerificationParameters(_, _))
        ));

        // Should fail if no transcripts are provided
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();
        assert!(matches!(
            dkg.aggregate_transcripts(&[]),
            Err(Error::NoTranscriptsToAggregate)
        ));

        // Not enough transcripts
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();
        let not_enough_messages = &messages[..security_threshold as usize - 1];
        assert!(not_enough_messages.len() < security_threshold as usize);
        let insufficient_aggregate =
            dkg.aggregate_transcripts(not_enough_messages).unwrap();
        assert!(matches!(
            insufficient_aggregate.verify(validators_num, &messages),
            Err(Error::InvalidTranscriptAggregate)
        ));

        // Unexpected transcripts in the aggregate or transcripts from a different ritual
        // Using same DKG parameters, but different DKG instances and validators
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();
        let (bad_messages, _, _) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );
        let mixed_messages = [&messages[..2], &bad_messages[..1]].concat();
        let bad_aggregate = dkg.aggregate_transcripts(&mixed_messages).unwrap();
        assert!(matches!(
            bad_aggregate.verify(validators_num, &messages),
            Err(Error::InvalidTranscriptAggregate)
        ));
    }

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn client_side_local_verification(shares_num: u32, validators_num: u32) {
        let rng = &mut StdRng::seed_from_u64(0);
        let security_threshold = shares_num / 2 + 1;

        let (messages, _, _) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );

        // We only need `security_threshold` transcripts to aggregate
        let messages = &messages[..security_threshold as usize];

        // Create an aggregated transcript on the client side
        let good_aggregate = AggregatedTranscript::new(messages).unwrap();

        // We are separating the verification from the aggregation since the client may fetch
        // the aggregate from a side-channel or decide to persist it and verify it later

        // Now, the client can verify the aggregated transcript
        let result = good_aggregate.verify(validators_num, messages);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test negative cases

        // Should fail if the number of validators is less than the number of messages
        assert!(matches!(
            good_aggregate.verify(messages.len() as u32 - 1, messages),
            Err(Error::InvalidAggregateVerificationParameters(_, _))
        ));

        // Should fail if no transcripts are provided
        assert!(matches!(
            AggregatedTranscript::new(&[]),
            Err(Error::NoTranscriptsToAggregate)
        ));

        // Not enough transcripts
        let not_enough_messages = &messages[..security_threshold as usize - 1];
        assert!(not_enough_messages.len() < security_threshold as usize);
        let insufficient_aggregate =
            AggregatedTranscript::new(not_enough_messages).unwrap();
        let _result = insufficient_aggregate.verify(validators_num, messages);
        assert!(matches!(
            insufficient_aggregate.verify(validators_num, messages),
            Err(Error::InvalidTranscriptAggregate)
        ));

        // Unexpected transcripts in the aggregate or transcripts from a different ritual
        // Using same DKG parameters, but different DKG instances and validators
        let (bad_messages, _, _) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );
        let mixed_messages = [&messages[..2], &bad_messages[..1]].concat();
        let bad_aggregate = AggregatedTranscript::new(&mixed_messages).unwrap();
        assert!(matches!(
            bad_aggregate.verify(validators_num, messages),
            Err(Error::InvalidTranscriptAggregate)
        ));
    }

    fn make_share_update_test_inputs(
        shares_num: u32,
        validators_num: u32,
        rng: &mut StdRng,
        security_threshold: u32,
    ) -> (
        Vec<ValidatorMessage>,
        Vec<Validator>,
        Vec<Keypair>,
        Vec<Dkg>,
        CiphertextHeader,
        SharedSecret,
    ) {
        let (messages, validators, validator_keypairs) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );
        let mut dkgs = validators
            .iter()
            .map(|validator| {
                Dkg::new(
                    TAU,
                    shares_num,
                    security_threshold,
                    &validators,
                    validator,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let pvss_aggregated = dkgs[0].aggregate_transcripts(&messages).unwrap();
        assert!(pvss_aggregated.verify(validators_num, &messages).unwrap());

        // Create an initial shared secret for testing purposes
        let public_key = &dkgs[0].public_key();
        let ciphertext =
            encrypt(SecretBox::new(MSG.to_vec()), AAD, public_key).unwrap();
        let ciphertext_header = ciphertext.header().unwrap();
        let (_, _, old_shared_secret) =
            crate::test_dkg_full::create_shared_secret_simple_tdec(
                &dkgs[0].0,
                AAD,
                &ciphertext_header.0,
                validator_keypairs.as_slice(),
            );

        (
            messages,
            validators,
            validator_keypairs,
            dkgs,
            ciphertext_header,
            SharedSecret(old_shared_secret),
        )
    }

    #[test_case(4, 4, true; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7, true; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6, true; "number of validators greater than the number of shares")]
    #[test_case(4, 6, false; "recovery at a specific point")]
    fn test_dkg_simple_tdec_share_recovery(
        shares_num: u32,
        validators_num: u32,
        recover_at_random_point: bool,
    ) {
        let rng = &mut StdRng::seed_from_u64(0);
        let security_threshold = shares_num / 2 + 1;

        let (
            mut messages,
            mut validators,
            mut validator_keypairs,
            mut dkgs,
            ciphertext_header,
            old_shared_secret,
        ) = make_share_update_test_inputs(
            shares_num,
            validators_num,
            rng,
            security_threshold,
        );

        // We assume that all participants have the same aggregate, and that participants created
        // their own aggregates before the off-boarding of the validator
        // If we didn't create this aggregate here, we risk having a "dangling validator message"
        // later when we off-board the validator
        let aggregated_transcript =
            dkgs[0].clone().aggregate_transcripts(&messages).unwrap();
        assert!(aggregated_transcript
            .verify(validators_num, &messages)
            .unwrap());

        // We need to save this domain point to be user in the recovery testing scenario
        let mut domain_points = dkgs[0].domain_points();
        let removed_domain_point = domain_points.pop().unwrap();

        // Remove one participant from the contexts and all nested structure
        // to simulate off-boarding a validator
        messages.pop().unwrap();
        dkgs.pop();
        validator_keypairs.pop().unwrap();

        let removed_validator = validators.pop().unwrap();
        for dkg in dkgs.iter_mut() {
            dkg.0
                .offboard_validator(&removed_validator.address)
                .expect("Unable to off-board a validator from the DKG context");
        }

        // Now, we're going to recover a new share at a random point or at a specific point
        // and check that the shared secret is still the same.
        let x_r = if recover_at_random_point {
            // Onboarding a validator with a completely new private key share
            DomainPoint::<E>::rand(rng)
        } else {
            // Onboarding a validator with a private key share recovered from the removed validator
            removed_domain_point
        };

        // Each participant prepares an update for each other participant
        let share_updates = dkgs
            .iter()
            .map(|validator_dkg| {
                let share_update = ShareRecoveryUpdate::create_share_updates(
                    validator_dkg,
                    &x_r,
                )
                .unwrap();
                (validator_dkg.me().address.clone(), share_update)
            })
            .collect::<HashMap<_, _>>();

        // Participants share updates and update their shares

        // Now, every participant separately:
        let updated_shares: Vec<_> = dkgs
            .iter()
            .map(|validator_dkg| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| {
                        updates
                            .get(validator_dkg.me().share_index as usize)
                            .unwrap()
                    })
                    .cloned()
                    .collect();

                // Each validator uses their decryption key to update their share
                let validator_keypair = validator_keypairs
                    .get(validator_dkg.me().share_index as usize)
                    .unwrap();

                // And creates updated private key shares
                aggregated_transcript
                    .get_private_key_share(
                        validator_keypair,
                        validator_dkg.me().share_index,
                    )
                    .unwrap()
                    .create_updated_private_key_share_for_recovery(
                        &updates_for_participant,
                    )
                    .unwrap()
            })
            .collect();

        // Now, we have to combine new share fragments into a new share
        let recovered_key_share =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &x_r,
                &domain_points,
                &updated_shares,
            )
            .unwrap();

        // Get decryption shares from remaining participants
        let mut decryption_shares: Vec<DecryptionShareSimple> =
            validator_keypairs
                .iter()
                .zip_eq(dkgs.iter())
                .map(|(validator_keypair, validator_dkg)| {
                    aggregated_transcript
                        .create_decryption_share_simple(
                            validator_dkg,
                            &ciphertext_header,
                            AAD,
                            validator_keypair,
                        )
                        .unwrap()
                })
                .collect();
        decryption_shares.shuffle(rng);

        // In order to test the recovery, we need to create a new decryption share from the recovered
        // private key share. To do that, we need a new validator

        // Let's create and onboard a new validator
        // TODO: Add test scenarios for onboarding and offboarding validators
        let new_validator_keypair = Keypair::random();
        // Normally, we would get these from the Coordinator:
        let new_validator_share_index = removed_validator.share_index;
        let new_validator = Validator {
            address: gen_address(new_validator_share_index as usize),
            public_key: new_validator_keypair.public_key(),
            share_index: new_validator_share_index,
        };
        validators.push(new_validator.clone());
        let new_validator_dkg = Dkg::new(
            TAU,
            shares_num,
            security_threshold,
            &validators,
            &new_validator,
        )
        .unwrap();

        let new_decryption_share = recovered_key_share
            .create_decryption_share_simple(
                &new_validator_dkg,
                &ciphertext_header,
                &new_validator_keypair,
                AAD,
            )
            .unwrap();
        decryption_shares.push(new_decryption_share);
        domain_points.push(x_r);
        assert_eq!(domain_points.len(), validators_num as usize);
        assert_eq!(decryption_shares.len(), validators_num as usize);

        let domain_points = &domain_points[..security_threshold as usize];
        let decryption_shares =
            &decryption_shares[..security_threshold as usize];
        assert_eq!(domain_points.len(), security_threshold as usize);
        assert_eq!(decryption_shares.len(), security_threshold as usize);

        let new_shared_secret = combine_shares_simple(decryption_shares);
        assert_eq!(
            old_shared_secret, new_shared_secret,
            "Shared secret reconstruction failed"
        );
    }

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn test_dkg_simple_tdec_share_refresh(
        shares_num: u32,
        validators_num: u32,
    ) {
        let rng = &mut StdRng::seed_from_u64(0);
        let security_threshold = shares_num / 2 + 1;

        let (
            messages,
            _validators,
            validator_keypairs,
            dkgs,
            ciphertext_header,
            old_shared_secret,
        ) = make_share_update_test_inputs(
            shares_num,
            validators_num,
            rng,
            security_threshold,
        );

        // Each participant prepares an update for each other participant
        let share_updates = dkgs
            .iter()
            .map(|validator_dkg| {
                let share_update =
                    ShareRefreshUpdate::create_share_updates(validator_dkg)
                        .unwrap();
                (validator_dkg.me().address.clone(), share_update)
            })
            .collect::<HashMap<_, _>>();

        // Participants share updates and update their shares

        // Now, every participant separately:
        let updated_shares: Vec<_> = dkgs
            .iter()
            .map(|validator_dkg| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| {
                        updates
                            .get(validator_dkg.me().share_index as usize)
                            .unwrap()
                    })
                    .cloned()
                    .collect();

                // Each validator uses their decryption key to update their share
                let validator_keypair = validator_keypairs
                    .get(validator_dkg.me().share_index as usize)
                    .unwrap();

                // And creates updated private key shares
                // We need an aggregate for that
                let aggregate = validator_dkg
                    .clone()
                    .aggregate_transcripts(&messages)
                    .unwrap();
                assert!(aggregate.verify(validators_num, &messages).unwrap());

                aggregate
                    .get_private_key_share(
                        validator_keypair,
                        validator_dkg.me().share_index,
                    )
                    .unwrap()
                    .create_updated_private_key_share_for_refresh(
                        &updates_for_participant,
                    )
                    .unwrap()
            })
            .collect();

        // Participants create decryption shares
        let mut decryption_shares: Vec<DecryptionShareSimple> =
            validator_keypairs
                .iter()
                .zip_eq(dkgs.iter())
                .map(|(validator_keypair, validator_dkg)| {
                    let pks = updated_shares
                        .get(validator_dkg.me().share_index as usize)
                        .unwrap()
                        .clone()
                        .into_private_key_share();
                    pks.create_decryption_share_simple(
                        validator_dkg,
                        &ciphertext_header,
                        validator_keypair,
                        AAD,
                    )
                    .unwrap()
                })
                .collect();
        decryption_shares.shuffle(rng);

        let decryption_shares =
            &decryption_shares[..security_threshold as usize];
        assert_eq!(decryption_shares.len(), security_threshold as usize);

        let new_shared_secret = combine_shares_simple(decryption_shares);
        assert_eq!(
            old_shared_secret, new_shared_secret,
            "Shared secret reconstruction failed"
        );
    }
}
