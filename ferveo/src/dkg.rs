use std::collections::BTreeMap;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_poly::EvaluationDomain;
use ark_std::UniformRand;
use ferveo_common::PublicKey;
use measure_time::print_time;
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    aggregate, assert_no_share_duplicates, AggregatedPvss, Error,
    EthereumAddress, PubliclyVerifiableParams, PubliclyVerifiableSS, Result,
    Validator,
};

pub type DomainPoint<E> = <E as Pairing>::ScalarField;

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

pub type ValidatorsMap<E> = BTreeMap<EthereumAddress, Validator<E>>;
pub type PVSSMap<E> = BTreeMap<EthereumAddress, PubliclyVerifiableSS<E>>;

#[derive(Debug, Clone)]
pub enum DkgState<E: Pairing> {
    // TODO: Do we need to keep track of the block number?
    Sharing {
        accumulated_shares: u32,
        block: u32,
    },
    Dealt,
    Success {
        public_key: ferveo_tdec::PublicKeyShare<E>,
    },
    Invalid,
}

impl<E: Pairing> DkgState<E> {
    fn new() -> Self {
        DkgState::Sharing {
            accumulated_shares: 0,
            block: 0,
        }
    }
}

/// The DKG context that holds all the local state for participating in the DKG
// TODO: Consider removing Clone to avoid accidentally NOT-mutating state.
//  Currently, we're assuming that the DKG is only mutated by the owner of the instance.
//  Consider removing Clone after finalizing ferveo::api
#[derive(Clone, Debug)]
pub struct PubliclyVerifiableDkg<E: Pairing> {
    pub dkg_params: DkgParams,
    pub pvss_params: PubliclyVerifiableParams<E>,
    pub validators: ValidatorsMap<E>,
    pub vss: PVSSMap<E>,
    pub domain: ark_poly::GeneralEvaluationDomain<E::ScalarField>,
    pub me: Validator<E>,
    state: DkgState<E>,
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
        let validators: ValidatorsMap<E> = validators
            .iter()
            .map(|validator| (validator.address.clone(), validator.clone()))
            .collect();

        // Make sure that `me` is a known validator
        if let Some(my_validator) = validators.get(&me.address) {
            if my_validator.public_key != me.public_key {
                return Err(Error::ValidatorPublicKeyMismatch);
            }
        } else {
            return Err(Error::DealerNotInValidatorSet(me.address.clone()));
        }

        Ok(Self {
            dkg_params: *dkg_params,
            pvss_params: PubliclyVerifiableParams::<E>::default(),
            vss: PVSSMap::<E>::new(),
            domain,
            me: me.clone(),
            validators,
            state: DkgState::new(),
        })
    }

    pub fn get_validator(
        &self,
        public_key: &PublicKey<E>,
    ) -> Option<&Validator<E>> {
        self.validators
            .values()
            .find(|validator| &validator.public_key == public_key)
    }

    /// Create a new PVSS instance within this DKG session, contributing to the final key
    /// `rng` is a cryptographic random number generator
    /// Returns a PVSS dealing message to post on-chain
    pub fn share<R: RngCore>(&mut self, rng: &mut R) -> Result<Message<E>> {
        print_time!("PVSS Sharing");
        match self.state {
            DkgState::Sharing { .. } | DkgState::Dealt => {
                let vss = PubliclyVerifiableSS::<E>::new(
                    &DomainPoint::<E>::rand(rng),
                    self,
                    rng,
                )?;
                Ok(Message::Deal(vss))
            }
            _ => Err(Error::InvalidDkgStateToDeal),
        }
    }

    /// Aggregate all received PVSS messages into a single message, prepared to post on-chain
    pub fn aggregate(&self) -> Result<Message<E>> {
        match self.state {
            DkgState::Dealt => {
                let public_key = self.public_key();
                let pvss_list = self.vss.values().cloned().collect::<Vec<_>>();
                Ok(Message::Aggregate(Aggregation {
                    vss: aggregate(&pvss_list)?,
                    public_key: public_key.public_key_share,
                }))
            }
            _ => Err(Error::InvalidDkgStateToAggregate),
        }
    }

    /// Returns the public key generated by the DKG
    pub fn public_key(&self) -> ferveo_tdec::PublicKeyShare<E> {
        ferveo_tdec::PublicKeyShare {
            public_key_share: self
                .vss
                .values()
                .map(|vss| vss.coeffs[0].into_group())
                .sum::<E::G1>()
                .into_affine(),
        }
    }

    /// Return a domain point for the share_index
    pub fn get_domain_point(&self, share_index: u32) -> Result<DomainPoint<E>> {
        self.domain_points()
            .get(share_index as usize)
            .ok_or_else(|| Error::InvalidShareIndex(share_index))
            .copied()
    }

    /// Return an appropriate amount of domain points for the DKG
    pub fn domain_points(&self) -> Vec<DomainPoint<E>> {
        self.domain.elements().take(self.validators.len()).collect()
    }

    pub fn offboard_validator(
        &mut self,
        address: &EthereumAddress,
    ) -> Result<Validator<E>> {
        if let Some(validator) = self.validators.remove(address) {
            self.vss.remove(address);
            Ok(validator)
        } else {
            Err(Error::UnknownValidator(address.clone()))
        }
    }

    pub fn verify_message(
        &self,
        sender: &Validator<E>,
        message: &Message<E>,
    ) -> Result<()> {
        match message {
            Message::Deal(pvss)
                if matches!(
                    self.state,
                    DkgState::Sharing { .. } | DkgState::Dealt
                ) =>
            {
                if !self.validators.contains_key(&sender.address) {
                    Err(Error::UnknownDealer(sender.clone().address))
                } else if self.vss.contains_key(&sender.address) {
                    Err(Error::DuplicateDealer(sender.clone().address))
                } else if !pvss.verify_optimistic() {
                    Err(Error::InvalidPvssTranscript)
                } else {
                    Ok(())
                }
            }
            Message::Aggregate(Aggregation { vss, public_key })
                if matches!(self.state, DkgState::Dealt) =>
            {
                let minimum_shares = self.dkg_params.shares_num
                    - self.dkg_params.security_threshold;
                let actual_shares = vss.shares.len() as u32;
                // We reject aggregations that fail to meet the security threshold
                if actual_shares < minimum_shares {
                    Err(Error::InsufficientTranscriptsForAggregate(
                        minimum_shares,
                        actual_shares,
                    ))
                } else if vss.verify_aggregation(self).is_err() {
                    Err(Error::InvalidTranscriptAggregate)
                } else if &self.public_key().public_key_share == public_key {
                    Ok(())
                } else {
                    Err(Error::InvalidDkgPublicKey)
                }
            }
            _ => Err(Error::InvalidDkgStateToVerify),
        }
    }

    /// After consensus has agreed to include a verified message on the blockchain,
    /// we apply the chains to the state machine
    pub fn apply_message(
        &mut self,
        sender: &Validator<E>,
        payload: &Message<E>,
    ) -> Result<()> {
        match payload {
            Message::Deal(pvss)
                if matches!(
                    self.state,
                    DkgState::Sharing { .. } | DkgState::Dealt
                ) =>
            {
                if !self.validators.contains_key(&sender.address) {
                    return Err(Error::UnknownDealer(sender.clone().address));
                }

                // TODO: Throw error instead of silently accepting excess shares?
                // if self.vss.len() < self.dkg_params.shares_num as usize {
                //     self.vss.insert(sender.address.clone(), pvss.clone());
                // }
                self.vss.insert(sender.address.clone(), pvss.clone());

                // we keep track of the amount of shares seen until the security
                // threshold is met. Then we may change the state of the DKG
                if let DkgState::Sharing {
                    ref mut accumulated_shares,
                    ..
                } = &mut self.state
                {
                    *accumulated_shares += 1;
                    if *accumulated_shares >= self.dkg_params.security_threshold
                    {
                        self.state = DkgState::Dealt;
                    }
                }
                Ok(())
            }
            Message::Aggregate(_) if matches!(self.state, DkgState::Dealt) => {
                // change state and cache the final key
                self.state = DkgState::Success {
                    public_key: self.public_key(),
                };
                Ok(())
            }
            _ => Err(Error::InvalidDkgStateToIngest),
        }
    }

    pub fn deal(
        &mut self,
        sender: &Validator<E>,
        pvss: &PubliclyVerifiableSS<E>,
    ) -> Result<()> {
        // Add the ephemeral public key and pvss transcript
        let (sender_address, _) = self
            .validators
            .iter()
            .find(|(probe_address, _)| sender.address == **probe_address)
            .ok_or_else(|| Error::UnknownDealer(sender.address.clone()))?;
        self.vss.insert(sender_address.clone(), pvss.clone());
        Ok(())
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound(
    serialize = "AggregatedPvss<E>: Serialize",
    deserialize = "AggregatedPvss<E>: DeserializeOwned"
))]
pub struct Aggregation<E: Pairing> {
    vss: AggregatedPvss<E>,
    #[serde_as(as = "ferveo_common::serialization::SerdeAs")]
    public_key: E::G1Affine,
}

// TODO: Remove these?
// TODO: These messages are not actually used anywhere, we use our own ValidatorMessage for Deal, and Aggregate for Message.Aggregate
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound(
    serialize = "AggregatedPvss<E>: Serialize, PubliclyVerifiableSS<E>: Serialize",
    deserialize = "AggregatedPvss<E>: DeserializeOwned, PubliclyVerifiableSS<E>: DeserializeOwned"
))]
pub enum Message<E: Pairing> {
    Deal(PubliclyVerifiableSS<E>),
    Aggregate(Aggregation<E>),
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
    use ark_ec::AffineRepr;
    use ferveo_tdec::PublicKeyShare;

    use crate::{
        test_common::*, DkgParams, DkgState, DkgState::Dealt, Error,
        PubliclyVerifiableDkg, Validator,
    };

    /// Check that the canonical share indices of validators are expected and enforced
    /// by the DKG methods.
    #[test]
    fn test_canonical_share_indices_are_enforced() {
        let shares_num = 4;
        let security_threshold = shares_num - 1;
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

    /// Test that dealing correct PVSS transcripts
    /// pass verification an application and that
    /// state is updated correctly
    #[test]
    fn test_pvss_dealing() {
        let rng = &mut ark_std::test_rng();

        // Create a test DKG instance
        let (mut dkg, _) = setup_dkg(0);

        // Gather everyone's transcripts
        let mut messages = vec![];
        for i in 0..dkg.dkg_params.shares_num() {
            let (mut dkg, _) = setup_dkg(i as usize);
            let message = dkg.share(rng).unwrap();
            let sender = dkg.me.clone();
            messages.push((sender, message));
        }

        let mut expected = 0u32;
        for (sender, pvss) in messages.iter() {
            // Check the verification passes
            assert!(dkg.verify_message(sender, pvss).is_ok());

            // Check that application passes
            assert!(dkg.apply_message(sender, pvss).is_ok());

            expected += 1;
            if expected < dkg.dkg_params.security_threshold {
                // check that shares accumulates correctly
                match dkg.state {
                    DkgState::Sharing {
                        accumulated_shares, ..
                    } => {
                        assert_eq!(accumulated_shares, expected)
                    }
                    _ => panic!("Test failed"),
                }
            } else {
                // Check that when enough shares is accumulated, we transition state
                assert!(matches!(dkg.state, DkgState::Dealt));
            }
        }
    }

    /// Test the verification and application of
    /// pvss transcripts from unknown validators
    /// are rejected
    #[test]
    fn test_pvss_from_unknown_dealer_rejected() {
        let rng = &mut ark_std::test_rng();
        let (mut dkg, _) = setup_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0
            }
        ));
        let pvss = dkg.share(rng).unwrap();
        // Need to make sure this falls outside of the validator set:
        let unknown_validator_index =
            dkg.dkg_params.shares_num + VALIDATORS_NUM + 1;
        let sender = Validator::<E> {
            address: gen_address(unknown_validator_index as usize),
            public_key: ferveo_common::Keypair::<E>::new(rng).public_key(),
            share_index: unknown_validator_index,
        };
        // check that verification fails
        assert!(dkg.verify_message(&sender, &pvss).is_err());
        // check that application fails
        assert!(dkg.apply_message(&sender, &pvss).is_err());
        // check that state has not changed
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));
    }

    /// Test that if a validator sends two pvss transcripts,
    /// the second fails to verify
    #[test]
    fn test_pvss_sent_twice_rejected() {
        let rng = &mut ark_std::test_rng();
        let (mut dkg, _) = setup_dkg(0);
        // We start with an empty state
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));

        let pvss = dkg.share(rng).unwrap();

        // This validator has already sent a PVSS
        let sender = dkg.me.clone();

        // First PVSS is accepted
        assert!(dkg.verify_message(&sender, &pvss).is_ok());
        assert!(dkg.apply_message(&sender, &pvss).is_ok());
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 1,
                block: 0,
            }
        ));

        // Second PVSS is rejected
        assert!(dkg.verify_message(&sender, &pvss).is_err());
    }

    /// Test that if a validators tries to verify it's own
    /// share message, it passes
    #[test]
    fn test_own_pvss() {
        let rng = &mut ark_std::test_rng();
        let (mut dkg, _) = setup_dkg(0);
        // We start with an empty state
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));

        // Sender creates a PVSS transcript
        let pvss = dkg.share(rng).unwrap();
        // Note that state of DKG has not changed
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));

        let sender = dkg.me.clone();

        // Sender verifies it's own PVSS transcript
        assert!(dkg.verify_message(&sender, &pvss).is_ok());
        assert!(dkg.apply_message(&sender, &pvss).is_ok());
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 1,
                block: 0,
            }
        ));
    }

    /// Test that the [`PubliclyVerifiableDkg<E>::share`] method
    /// errors if its state is not [`DkgState::Shared{..} | Dkg::Dealt`]
    #[test]
    fn test_pvss_cannot_share_from_wrong_state() {
        let rng = &mut ark_std::test_rng();
        let (mut dkg, _) = setup_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));

        dkg.state = DkgState::Success {
            public_key: PublicKeyShare {
                public_key_share: G1::zero(),
            },
        };
        assert!(dkg.share(rng).is_err());

        // check that even if security threshold is met, we can still share
        dkg.state = Dealt;
        assert!(dkg.share(rng).is_ok());
    }

    /// Check that share messages can only be
    /// verified or applied if the dkg is in
    /// state [`DkgState::Share{..} | DkgState::Dealt`]
    #[test]
    fn test_share_message_state_guards() {
        let rng = &mut ark_std::test_rng();
        let (mut dkg, _) = setup_dkg(0);
        let pvss = dkg.share(rng).unwrap();
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));

        let sender = dkg.me.clone();
        dkg.state = DkgState::Success {
            public_key: PublicKeyShare {
                public_key_share: G1::zero(),
            },
        };
        assert!(dkg.verify_message(&sender, &pvss).is_err());
        assert!(dkg.apply_message(&sender, &pvss).is_err());

        // check that we can still accept pvss transcripts after meeting threshold
        dkg.state = Dealt;
        assert!(dkg.verify_message(&sender, &pvss).is_ok());
        assert!(dkg.apply_message(&sender, &pvss).is_ok());
        assert!(matches!(dkg.state, DkgState::Dealt))
    }
}

/// Test aggregating transcripts into final key
#[cfg(test)]
mod test_aggregation {
    use ark_ec::AffineRepr;
    use ferveo_tdec::PublicKeyShare;
    use test_case::test_case;

    use crate::{dkg::*, test_common::*, DkgState, Message};

    /// Test that if the security threshold is met, we can create a final key
    #[test_case(4, 4; "number of validators equal to the number of shares")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn test_aggregate(shares_num: u32, validators_num: u32) {
        let security_threshold = shares_num - 1;
        let (mut dkg, _) = setup_dealt_dkg_with_n_validators(
            security_threshold,
            shares_num,
            validators_num,
        );
        let aggregate_msg = dkg.aggregate().unwrap();
        if let Message::Aggregate(Aggregation { public_key, .. }) =
            &aggregate_msg
        {
            assert_eq!(public_key, &dkg.public_key().public_key_share);
        } else {
            panic!("Expected aggregate message")
        }
        let sender = dkg.me.clone();
        assert!(dkg.verify_message(&sender, &aggregate_msg).is_ok());
        assert!(dkg.apply_message(&sender, &aggregate_msg).is_ok());
        assert!(matches!(dkg.state, DkgState::Success { .. }));
    }

    /// Test that aggregate only succeeds if we are in the state [`DkgState::Dealt]
    #[test]
    fn test_aggregate_state_guards() {
        let (mut dkg, _) = setup_dealt_dkg();
        dkg.state = DkgState::Sharing {
            accumulated_shares: 0,
            block: 0,
        };
        assert!(dkg.aggregate().is_err());
        dkg.state = DkgState::Success {
            public_key: PublicKeyShare {
                public_key_share: G1::zero(),
            },
        };
        assert!(dkg.aggregate().is_err());
    }

    /// Test that aggregate message fail to be verified or applied unless
    /// dkg.state is [`DkgState::Dealt`]
    #[test]
    fn test_aggregate_message_state_guards() {
        let (mut dkg, _) = setup_dealt_dkg();
        let aggregate = dkg.aggregate().unwrap();
        let sender = dkg.me.clone();

        dkg.state = DkgState::Sharing {
            accumulated_shares: 0,
            block: 0,
        };
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
        assert!(dkg.apply_message(&sender, &aggregate).is_err());

        dkg.state = DkgState::Success {
            public_key: PublicKeyShare {
                public_key_share: G1::zero(),
            },
        };
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
        assert!(dkg.apply_message(&sender, &aggregate).is_err())
    }

    /// Test that an aggregate message will fail to verify if the
    /// security threshold is not met
    #[test]
    fn test_aggregate_wont_verify_if_under_threshold() {
        let (mut dkg, _) = setup_dealt_dkg();
        dkg.dkg_params.shares_num = 10;
        let aggregate = dkg.aggregate().unwrap();
        let sender = dkg.me.clone();
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
    }

    /// If the aggregated pvss passes, check that the announced
    /// key is correct. Verification should fail if it is not
    #[test]
    fn test_aggregate_wont_verify_if_wrong_key() {
        let (dkg, _) = setup_dealt_dkg();
        let mut aggregate = dkg.aggregate().unwrap();
        while dkg.public_key().public_key_share == G1::zero() {
            let (_dkg, _) = setup_dealt_dkg();
        }
        if let Message::Aggregate(Aggregation { public_key, .. }) =
            &mut aggregate
        {
            *public_key = G1::zero();
        }
        let sender = dkg.me.clone();
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
    }

    /// Size of the domain should be equal a power of 2
    #[test]
    fn test_domain_points_size_is_power_of_2() {
        // Using a validators number which is not a power of 2
        let validators_num = 6;
        let (dkg, _) = setup_dealt_dkg_with_n_validators(
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
        let (dkg1, _) = setup_dealt_dkg_with_n_validators(
            validators_num,
            validators_num,
            validators_num,
        );
        let (dkg2, _) = setup_dealt_dkg_with_n_validators(
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
        let (dkg1, _) = setup_dealt_dkg_with_n_validators(
            validators_num,
            validators_num,
            validators_num,
        );
        let (dkg2, _) = setup_dealt_dkg_with_n_validators(
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
        let (dkg3, _) = setup_dealt_dkg_with_n_validators(
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
