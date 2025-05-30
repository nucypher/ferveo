use std::collections::{BTreeMap, HashMap, HashSet};

use ark_ec::pairing::Pairing;
use ark_poly::EvaluationDomain;
use ark_std::UniformRand;
use ferveo_common::PublicKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    assert_no_share_duplicates, refresh, AggregatedTranscript, Error,
    EthereumAddress, PubliclyVerifiableSS, Result, UpdateTranscript, Validator,
};

pub type DomainPoint<E> = <E as Pairing>::ScalarField;
pub type ValidatorMessage<E> = (Validator<E>, PubliclyVerifiableSS<E>);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct DkgParams {
    tau: u32,
    security_threshold: u32,
    shares_num: u32,
}

impl DkgParams {
    /// Create new DKG parameters
    /// `tau` is a unique identifier for the DKG (ritual id)
    /// `security_threshold` is the minimum number of shares required to reconstruct the key
    /// `shares_num` is the total number of shares to be generated
    /// Returns an error if the parameters are invalid
    /// Parameters must hold: `shares_num` >= `security_threshold`
    pub fn new(
        tau: u32,
        security_threshold: u32,
        shares_num: u32,
    ) -> Result<Self> {
        if shares_num < security_threshold
            || shares_num == 0
            || security_threshold == 0
        {
            return Err(Error::InvalidDkgParameters(
                shares_num,
                security_threshold,
            ));
        }
        Ok(Self {
            tau,
            security_threshold,
            shares_num,
        })
    }

    pub fn tau(&self) -> u32 {
        self.tau
    }

    pub fn security_threshold(&self) -> u32 {
        self.security_threshold
    }

    pub fn shares_num(&self) -> u32 {
        self.shares_num
    }
}

pub type ValidatorsByIndex<E> = BTreeMap<u32, Validator<E>>;
pub type ValidatorsByAddress<E> = BTreeMap<EthereumAddress, Validator<E>>;
pub type PVSSMap<E> = BTreeMap<EthereumAddress, PubliclyVerifiableSS<E>>;

/// The DKG context that holds all the local state for participating in the DKG
// TODO: Consider removing Clone to avoid accidentally NOT-mutating state.
//  Currently, we're assuming that the DKG is only mutated by the owner of the instance.
//  Consider removing Clone after finalizing ferveo::api
#[derive(Clone, Debug)]
pub struct PubliclyVerifiableDkg<E: Pairing> {
    pub dkg_params: DkgParams,
    pub validators: ValidatorsByIndex<E>,
    pub domain: ark_poly::GeneralEvaluationDomain<E::ScalarField>,
    pub me: Validator<E>,
}

impl<E: Pairing> PubliclyVerifiableDkg<E> {
    /// Create a new DKG context to participate in the DKG
    /// Every identity in the DKG is linked to a bls12-381 public key;
    /// `validators`: List of validators
    /// `params` contains the parameters of the DKG such as number of shares
    /// `me` the validator creating this instance
    /// `session_keypair` the keypair for `me`
    pub fn new(
        validators: &[Validator<E>],
        dkg_params: &DkgParams,
        me: &Validator<E>,
    ) -> Result<Self> {
        assert_no_share_duplicates(validators)?;

        let domain = ark_poly::GeneralEvaluationDomain::<E::ScalarField>::new(
            validators.len(),
        )
        .expect("unable to construct domain");

        let validators: ValidatorsByIndex<E> = validators
            .iter()
            .map(|validator| (validator.share_index, validator.clone()))
            .collect();

        // Make sure that `me` is a known validator
        if let Some(my_validator) = validators.get(&me.share_index) {
            if my_validator.public_key != me.public_key {
                return Err(Error::ValidatorPublicKeyMismatch);
            }
        } else {
            return Err(Error::DealerNotInValidatorSet(me.address.clone()));
        }

        Ok(Self {
            dkg_params: *dkg_params,
            domain,
            me: me.clone(),
            validators,
        })
    }

    /// Get the validator with for the given public key
    pub fn get_validator(
        &self,
        public_key: &PublicKey<E>,
    ) -> Option<&Validator<E>> {
        self.validators
            .values()
            .find(|validator| &validator.public_key == public_key)
    }

    /// Create a new PVSS instance within this DKG session, contributing to the final key
    pub fn generate_transcript<R: RngCore>(
        &self,
        rng: &mut R,
    ) -> Result<PubliclyVerifiableSS<E>> {
        PubliclyVerifiableSS::<E>::new(&DomainPoint::<E>::rand(rng), self, rng)
    }

    /// Aggregate all received PVSS messages into a single message, prepared to post on-chain
    pub fn aggregate_transcripts(
        &self,
        messages: &[ValidatorMessage<E>],
    ) -> Result<AggregatedTranscript<E>> {
        self.verify_transcripts(messages)?;
        let transcripts: Vec<PubliclyVerifiableSS<E>> = messages
            .iter()
            .map(|(_sender, transcript)| transcript.clone())
            .collect();
        AggregatedTranscript::<E>::from_transcripts(&transcripts)
    }

    /// Return a domain point for the share_index
    pub fn get_domain_point(&self, share_index: u32) -> Result<DomainPoint<E>> {
        self.domain_points()
            .get(share_index as usize)
            .ok_or_else(|| Error::InvalidShareIndex(share_index))
            .copied()
    }

    /// Return an appropriate amount of domain points for the DKG
    /// The number of domain points should be equal to the number of validators
    pub fn domain_points(&self) -> Vec<DomainPoint<E>> {
        self.domain.elements().take(self.validators.len()).collect()
    }

    /// Return a map of domain points for the DKG
    pub fn domain_point_map(&self) -> HashMap<u32, DomainPoint<E>> {
        self.domain_points()
            .iter()
            .enumerate()
            .map(|(share_index, point)| (share_index as u32, *point))
            .collect::<HashMap<u32, DomainPoint<E>>>()
    }

    // TODO: Revisit naming later
    /// Return a map of domain points for the DKG
    pub fn domain_and_key_map(
        &self,
    ) -> HashMap<u32, (DomainPoint<E>, PublicKey<E>)> {
        let map = self.domain_point_map();
        self.validators
            .values()
            .map(|v| {
                let domain_point = map.get(&v.share_index).unwrap();
                (v.share_index, (*domain_point, v.public_key))
            })
            .collect::<_>()
    }

    /// Verify PVSS transcripts against the set of validators in the DKG
    fn verify_transcripts(
        &self,
        messages: &[ValidatorMessage<E>],
    ) -> Result<()> {
        let mut validator_set = HashSet::<EthereumAddress>::new();
        let mut transcript_set = HashSet::<PubliclyVerifiableSS<E>>::new();
        for (sender, transcript) in messages.iter() {
            let index = sender.share_index;
            let sender = &sender.address;
            if !self.validators.contains_key(&index) {
                return Err(Error::UnknownDealer(sender.clone()));
            } else if validator_set.contains(sender) {
                return Err(Error::DuplicateDealer(sender.clone()));
            } else if transcript_set.contains(transcript) {
                return Err(Error::DuplicateTranscript(sender.clone()));
            } else if !transcript.verify_optimistic() {
                return Err(Error::InvalidPvssTranscript(sender.clone()));
            }
            validator_set.insert(sender.clone());
            transcript_set.insert(transcript.clone());
        }

        if validator_set.len() > self.validators.len()
            || transcript_set.len() > self.validators.len()
        {
            return Err(Error::TooManyTranscripts(
                self.validators.len() as u32,
                validator_set.len() as u32,
            ));
        }

        Ok(())
    }

    // Returns a new refresh transcript for current validators in DKG
    // TODO: Allow to pass a parameter to restrict target validators
    pub fn generate_refresh_transcript<R: RngCore>(
        &self,
        rng: &mut R,
    ) -> Result<refresh::UpdateTranscript<E>> {
        Ok(UpdateTranscript::create_refresh_updates(
            &self.domain_and_key_map(),
            self.dkg_params.security_threshold(),
            rng,
        ))
    }
}

/// Test initializing DKG
#[cfg(test)]
mod test_dkg_init {
    use crate::{
        dkg::{PubliclyVerifiableDkg, Validator},
        test_common::*,
        DkgParams,
    };

    /// Test that dkg fails to start if the `me` input
    /// is not in the validator set
    #[test]
    fn test_dkg_fail_unknown_validator() {
        let rng = &mut ark_std::test_rng();
        let known_keypairs = gen_keypairs(SHARES_NUM);
        let unknown_keypair = ferveo_common::Keypair::<E>::new(rng);
        let unknown_validator = Validator::<E> {
            address: gen_address((SHARES_NUM + 1) as usize),
            public_key: unknown_keypair.public_key(),
            share_index: SHARES_NUM + 5, // Not in the validator set
        };
        let err = PubliclyVerifiableDkg::<E>::new(
            &gen_validators(&known_keypairs),
            &DkgParams::new(TAU, SECURITY_THRESHOLD, SHARES_NUM).unwrap(),
            &unknown_validator,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "Expected validator to be a part of the DKG validator set: 0x0000000000000000000000000000000000000005")
    }
}

/// Test the dealing phase of the DKG
#[cfg(test)]
mod test_dealing {

    use crate::{
        test_common::*, DkgParams, Error, PubliclyVerifiableDkg, Validator,
    };

    /// Check that the canonical share indices of validators are expected and enforced
    /// by the DKG methods.
    #[test]
    fn test_canonical_share_indices_are_enforced() {
        let shares_num = 4;
        let security_threshold = shares_num;
        let keypairs = gen_keypairs(shares_num);
        let mut validators = gen_validators(&keypairs);
        let me = validators[0].clone();

        // Validators (share indices) are not unique
        let duplicated_index = 0;
        validators.insert(duplicated_index, me.clone());

        // And because of that the DKG should fail
        let result = PubliclyVerifiableDkg::new(
            &validators,
            &DkgParams::new(0, security_threshold, shares_num).unwrap(),
            &me,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            Error::DuplicatedShareIndex(duplicated_index as u32).to_string()
        );
    }

    #[test]
    fn test_validator_ordering() {
        let shares_num = 4;
        let security_threshold = shares_num;
        let keypairs = gen_keypairs(shares_num);
        // Create validators, ordered by address
        let mut validators = gen_validators(&keypairs);

        // Swap the share indices of two validators
        let me = Validator {
            address: validators[0].address.clone(),
            public_key: validators[0].public_key,
            share_index: 1,
        };
        let someone_else = Validator {
            address: validators[1].address.clone(),
            public_key: validators[1].public_key,
            share_index: 0,
        };
        validators[0] = me.clone();
        validators[1] = someone_else;

        let dkg = PubliclyVerifiableDkg::new(
            &validators,
            &DkgParams::new(0, security_threshold, shares_num).unwrap(),
            &me,
        )
        .unwrap();

        // DKG should keep the original validators indices, as passed from the constructor. See issue #204
        for validator in validators.iter() {
            let validator_in_dkg =
                dkg.validators.get(&validator.share_index).unwrap();
            assert_eq!(validator_in_dkg.share_index, validator.share_index);
            assert_eq!(validator_in_dkg.public_key, validator.public_key);
            assert_eq!(validator_in_dkg.address, validator.address);
        }
    }

    /// Test that dealing correct PVSS transcripts passes validation
    #[test]
    fn test_pvss_dealing() {
        let rng = &mut ark_std::test_rng();
        let (dkg, _) = setup_dkg(0);
        let messages = make_messages(rng, &dkg);
        assert!(dkg.verify_transcripts(&messages).is_ok());
    }

    /// Test the verification and application of pvss transcripts from
    /// unknown validators are rejected
    #[test]
    fn test_pvss_from_unknown_dealer_rejected() {
        let rng = &mut ark_std::test_rng();
        let (dkg, _) = setup_dkg(0);
        let mut messages = make_messages(rng, &dkg);

        // Need to make sure this falls outside the validator set:
        let unknown_validator_index =
            dkg.dkg_params.shares_num + VALIDATORS_NUM + 1;
        let sender = Validator::<E> {
            address: gen_address(unknown_validator_index as usize),
            public_key: ferveo_common::Keypair::<E>::new(rng).public_key(),
            share_index: unknown_validator_index,
        };
        let transcript = dkg.generate_transcript(rng).unwrap();
        messages.push((sender, transcript));

        assert!(dkg.verify_transcripts(&messages).is_err());
    }

    /// Test that if a validator sends two pvss transcripts, the second fails to verify
    #[test]
    fn test_pvss_sent_twice_rejected() {
        let rng = &mut ark_std::test_rng();
        let (dkg, _) = setup_dkg(0);
        let mut messages = make_messages(rng, &dkg);

        messages.push(messages[0].clone());

        assert!(dkg.verify_transcripts(&messages).is_err());
    }

    /// Test that if a validators tries to verify its own share message, it passes
    #[test]
    fn test_own_pvss() {
        let rng = &mut ark_std::test_rng();
        let (dkg, _) = setup_dkg(0);
        let messages = make_messages(rng, &dkg)
            .iter()
            .take(1)
            .cloned()
            .collect::<Vec<_>>();

        assert!(dkg.verify_transcripts(&messages).is_ok());
    }
}

/// Test aggregating transcripts into final key
#[cfg(test)]
mod test_aggregation {
    use ark_poly::EvaluationDomain;

    use crate::test_common::*;

    /// Test that if the security threshold is met, we can create a final key
    #[test]
    fn test_aggregate() {
        let rng = &mut ark_std::test_rng();
        let (dkg, _) = setup_dkg(0);
        let all_messages = make_messages(rng, &dkg);

        let not_enough_messages = all_messages
            .iter()
            .take((dkg.dkg_params.security_threshold - 1) as usize)
            .cloned()
            .collect::<Vec<_>>();
        let bad_aggregate =
            dkg.aggregate_transcripts(&not_enough_messages).unwrap();

        let enough_messages = all_messages
            .iter()
            .take(dkg.dkg_params.security_threshold as usize)
            .cloned()
            .collect::<Vec<_>>();
        let good_aggregate_1 =
            dkg.aggregate_transcripts(&enough_messages).unwrap();
        assert_ne!(bad_aggregate, good_aggregate_1);

        let good_aggregate_2 =
            dkg.aggregate_transcripts(&all_messages).unwrap();
        assert_ne!(good_aggregate_1, good_aggregate_2);
    }

    /// Size of the domain should be equal a power of 2
    #[test]
    fn test_domain_points_size_is_power_of_2() {
        // Using a validators number which is not a power of 2
        let validators_num = 6;
        let (dkg, _, _) = setup_dealt_dkg_with_n_validators(
            validators_num,
            validators_num,
            validators_num,
        );
        // This should cause the domain to be of size that is a power of 2
        assert_eq!(dkg.domain.elements().count(), 8);
    }

    /// For the same number of validators, we should get the same domain points
    /// in two different DKG instances
    #[test]
    fn test_domain_point_determinism_for_share_number() {
        let validators_num = 6;
        let (dkg1, _, _) = setup_dealt_dkg_with_n_validators(
            validators_num,
            validators_num,
            validators_num,
        );
        let (dkg2, _, _) = setup_dealt_dkg_with_n_validators(
            validators_num,
            validators_num,
            validators_num,
        );
        assert_eq!(dkg1.domain_points(), dkg2.domain_points());
    }

    /// For a different number of validators, two DKG instances should have different domain points
    /// This is because the number of share determines the generator of the domain
    #[test]
    fn test_domain_points_different_for_different_domain_size() {
        // In the first case, both DKG should have the same domain points despite different
        // number of validators. This is because the domain size is the nearest power of 2
        // and both 6 and 7 are rounded to 8
        let validators_num = 6;
        let (dkg1, _, _) = setup_dealt_dkg_with_n_validators(
            validators_num,
            validators_num,
            validators_num,
        );
        let (dkg2, _, _) = setup_dealt_dkg_with_n_validators(
            validators_num + 1,
            validators_num + 1,
            validators_num + 1,
        );
        assert_eq!(dkg1.domain.elements().count(), 8);
        assert_eq!(dkg2.domain.elements().count(), 8);
        assert_eq!(
            dkg1.domain_points()[..validators_num as usize],
            dkg2.domain_points()[..validators_num as usize]
        );

        // In the second case, the domain size is different and so the domain points
        // should be different
        let validators_num_different = 15;
        let (dkg3, _, _) = setup_dealt_dkg_with_n_validators(
            validators_num_different,
            validators_num_different,
            validators_num_different,
        );
        assert_eq!(dkg3.domain.elements().count(), 16);
        assert_ne!(dkg1.domain_points(), dkg3.domain_points());
    }
}

/// Test DKG parameters
#[cfg(test)]
mod test_dkg_params {
    use crate::test_common::*;

    #[test]
    fn test_shares_num_less_than_security_threshold() {
        let dkg_params = super::DkgParams::new(TAU, SHARES_NUM + 1, SHARES_NUM);
        assert!(dkg_params.is_err());
    }

    #[test]
    fn test_valid_dkg_params() {
        let dkg_params =
            super::DkgParams::new(TAU, SECURITY_THRESHOLD, SHARES_NUM);
        assert!(dkg_params.is_ok());
    }
}
