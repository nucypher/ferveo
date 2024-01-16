use std::{cmp::Ordering, collections::BTreeMap};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_poly::EvaluationDomain;
use ferveo_common::PublicKey;
use measure_time::print_time;
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    aggregate, utils::is_sorted, AggregatedPvss, Error, EthereumAddress,
    PubliclyVerifiableParams, PubliclyVerifiableSS, Result, Validator,
};

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
        if shares_num < security_threshold {
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

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct DkgValidator<E: Pairing> {
    pub validator: Validator<E>,
    pub share_index: usize,
}

impl<E: Pairing> PartialOrd for DkgValidator<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: Pairing> Ord for DkgValidator<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.share_index.cmp(&other.share_index)
    }
}

pub type ValidatorsMap<E> = BTreeMap<EthereumAddress, DkgValidator<E>>;
pub type PVSSMap<E> = BTreeMap<EthereumAddress, PubliclyVerifiableSS<E>>;

#[derive(Debug, Clone)]
pub enum DkgState<E: Pairing> {
    Sharing { accumulated_shares: u32, block: u32 },
    Dealt,
    Success { public_key: E::G1Affine },
    Invalid,
}

/// The DKG context that holds all of the local state for participating in the DKG
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
    pub me: DkgValidator<E>,
    pub state: DkgState<E>,
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
        let domain = ark_poly::GeneralEvaluationDomain::<E::ScalarField>::new(
            validators.len(),
        )
        .expect("unable to construct domain");

        // Verify the global ordering of validators
        if !is_sorted(validators) {
            return Err(Error::ValidatorsNotSorted);
        }
        // TODO: Should we take it from the coordinator instead of using validators: &[Validator<E>] as input?
        let validators: ValidatorsMap<E> = validators
            .iter()
            .enumerate()
            .map(|(validator_index, validator)| {
                (
                    validator.address.clone(),
                    DkgValidator {
                        validator: validator.clone(),
                        share_index: validator_index,
                    },
                )
            })
            .collect();

        // Make sure that `me` is a known validator
        if let Some(my_validator) = validators.get(&me.address) {
            if my_validator.validator.public_key != me.public_key {
                return Err(Error::ValidatorPublicKeyMismatch);
            }
        } else {
            return Err(Error::DealerNotInValidatorSet(me.address.clone()));
        }

        Ok(Self {
            dkg_params: *dkg_params,
            pvss_params: PubliclyVerifiableParams::<E> {
                g: E::G1::generator(),
                h: E::G2::generator(),
            },
            vss: BTreeMap::new(),
            domain,
            me: DkgValidator {
                validator: me.clone(),
                share_index: validators[&me.address].share_index,
            },
            validators,
            state: DkgState::Sharing {
                accumulated_shares: 0,
                // TODO: Do we need to keep track of the block number?
                block: 0,
            },
        })
    }

    pub fn get_validator(
        &self,
        public_key: &PublicKey<E>,
    ) -> Option<&DkgValidator<E>> {
        self.validators
            .values()
            .find(|validator| &validator.validator.public_key == public_key)
    }

    /// Create a new PVSS instance within this DKG session, contributing to the final key
    /// `rng` is a cryptographic random number generator
    /// Returns a PVSS dealing message to post on-chain
    pub fn share<R: RngCore>(&mut self, rng: &mut R) -> Result<Message<E>> {
        print_time!("PVSS Sharing");
        let vss = self.create_share(rng)?;
        match self.state {
            DkgState::Sharing { .. } | DkgState::Dealt => {
                Ok(Message::Deal(vss))
            }
            _ => Err(Error::InvalidDkgStateToDeal),
        }
    }

    // TODO: Make private, use `share` instead. Currently used only in bindings
    pub fn create_share<R: RngCore>(
        &self,
        rng: &mut R,
    ) -> Result<PubliclyVerifiableSS<E>> {
        use ark_std::UniformRand;
        PubliclyVerifiableSS::<E>::new(&E::ScalarField::rand(rng), self, rng)
    }

    /// Aggregate all received PVSS messages into a single message, prepared to post on-chain
    pub fn aggregate(&self) -> Result<Message<E>> {
        match self.state {
            DkgState::Dealt => {
                let public_key = self.public_key();
                Ok(Message::Aggregate(Aggregation {
                    vss: aggregate(&self.vss),
                    public_key,
                }))
            }
            _ => Err(Error::InvalidDkgStateToAggregate),
        }
    }

    /// Returns the public key generated by the DKG
    pub fn public_key(&self) -> E::G1Affine {
        self.vss
            .values()
            .map(|vss| vss.coeffs[0].into_group())
            .sum::<E::G1>()
            .into_affine()
    }

    /// `payload` is the content of the message
    pub fn verify_message(
        &self,
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
                } else if &self.public_key() == public_key {
                    Ok(())
                } else {
                    Err(Error::InvalidDkgPublicKey)
                }
            }
            _ => Err(Error::InvalidDkgStateToVerify),
        }
    }

    /// After consensus has agreed to include a verified
    /// message on the blockchain, we apply the chains
    /// to the state machine
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound(
    serialize = "AggregatedPvss<E>: Serialize, PubliclyVerifiableSS<E>: Serialize",
    deserialize = "AggregatedPvss<E>: DeserializeOwned, PubliclyVerifiableSS<E>: DeserializeOwned"
))]
pub enum Message<E: Pairing> {
    Deal(PubliclyVerifiableSS<E>),
    Aggregate(Aggregation<E>),
}

/// Factory functions for testing
#[cfg(test)]
pub(crate) mod test_common {
    use std::str::FromStr;

    pub use ark_bls12_381::Bls12_381 as E;
    use ferveo_common::Keypair;
    use rand::seq::SliceRandom;

    pub use super::*;

    pub type G1 = <E as Pairing>::G1Affine;

    pub fn gen_keypairs(n: u32) -> Vec<Keypair<E>> {
        let rng = &mut ark_std::test_rng();
        (0..n).map(|_| Keypair::<E>::new(rng)).collect()
    }

    pub fn gen_address(i: usize) -> EthereumAddress {
        EthereumAddress::from_str(&format!("0x{i:040}")).unwrap()
    }

    pub fn gen_validators(keypairs: &[Keypair<E>]) -> Vec<Validator<E>> {
        keypairs
            .iter()
            .enumerate()
            .map(|(i, keypair)| Validator {
                address: gen_address(i),
                public_key: keypair.public_key(),
            })
            .collect()
    }

    pub type TestSetup = (PubliclyVerifiableDkg<E>, Vec<Keypair<E>>);

    pub fn setup_dkg_for_me(
        security_threshold: u32,
        shares_num: u32,
        my_index: usize,
    ) -> TestSetup {
        setup_dkg_for_me_with_n_validators(
            security_threshold,
            shares_num,
            my_index,
            shares_num,
        )
    }

    pub fn setup_dkg_for_me_with_n_validators(
        security_threshold: u32,
        shares_num: u32,
        my_index: usize,
        n_validators: u32,
    ) -> TestSetup {
        let keypairs = gen_keypairs(n_validators);
        let mut validators = gen_validators(keypairs.as_slice());
        validators.sort();
        let me = validators[my_index].clone();
        let dkg = PubliclyVerifiableDkg::new(
            &validators,
            &DkgParams::new(0, security_threshold, shares_num).unwrap(),
            &me,
        )
        .expect("Setup failed");
        (dkg, keypairs)
    }

    /// Create a test dkg
    ///
    /// The [`test_dkg_init`] module checks correctness of this setup
    pub fn setup_dkg() -> TestSetup {
        setup_dkg_for_me(2, 4, 0)
    }

    /// Set up a dkg with enough pvss transcripts to meet the threshold
    ///
    /// The correctness of this function is tested in the module [`test_dealing`]
    pub fn setup_dealt_dkg() -> TestSetup {
        setup_dealt_dkg_with_n_validators(2, 4, 4)
    }

    pub fn setup_dealt_dkg_with_n_validators(
        security_threshold: u32,
        shares_num: u32,
        validators_num: u32,
    ) -> TestSetup {
        let rng = &mut ark_std::test_rng();

        // Gather everyone's transcripts
        let mut dkgs = Vec::new();
        let mut messages: Vec<_> = (0..validators_num)
            .map(|my_index| {
                let (mut dkg, _) = setup_dkg_for_me_with_n_validators(
                    security_threshold,
                    shares_num,
                    my_index as usize,
                    validators_num,
                );
                dkgs.push(dkg.clone());

                let me = dkg.me.validator.clone();
                let message = dkg.share(rng).unwrap();
                println!("{my_index}");
                (me, message)
            })
            .collect();

        // Create a test DKG instance
        let mut dkg = dkgs.pop().unwrap();

        // `shares_num` is either equal or lower than `validators_num`, so we always take `shares_num` messages
        assert!(shares_num <= validators_num);
        // Make sure messages are out of order - The ordering should not matter
        messages.shuffle(rng);
        messages.iter().take(shares_num as usize).for_each(
            |(sender, message)| {
                dkg.apply_message(sender, message).expect("Setup failed");
            },
        );
        (dkg, gen_keypairs(validators_num))
    }
}

/// Test initializing DKG
#[cfg(test)]
mod test_dkg_init {
    use super::test_common::*;

    /// Test that dkg fails to start if the `me` input
    /// is not in the validator set
    #[test]
    fn test_dkg_fail_unknown_validator() {
        let rng = &mut ark_std::test_rng();
        let shares_num = 4;
        let known_keypairs = gen_keypairs(shares_num);
        let unknown_keypair = ferveo_common::Keypair::<E>::new(rng);
        let unknown_validator = Validator::<E> {
            address: gen_address((shares_num + 1) as usize),
            public_key: unknown_keypair.public_key(),
        };
        let err = PubliclyVerifiableDkg::<E>::new(
            &gen_validators(&known_keypairs),
            &DkgParams {
                tau: 0,
                security_threshold: shares_num / 2,
                shares_num,
            },
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
    use test_case::test_case;

    use super::test_common::*;
    use crate::DkgState::Dealt;

    /// Test that dealing correct PVSS transcripts pass verification an application and that
    /// state is updated correctly
    #[test_case(4, 4 ; "number of shares is equal to number of validators")]
    #[test_case(4, 6 ; "number of shares is smaller than the number of validators")]
    fn test_pvss_dealing(shares_num: u32, validator_num: u32) {
        let threshold = 3;
        // Create a test DKG instance
        let (mut dkg, _) = setup_dkg_for_me_with_n_validators(
            threshold,
            shares_num,
            0,
            validator_num,
        );

        // Gather everyone's transcripts
        let mut messages = vec![];
        let rng = &mut ark_std::test_rng();
        // Notice how we use `shares_num` instead of `validator_num` - Not everyone will send a message
        for i in 0..shares_num {
            let (mut dkg, _) = setup_dkg_for_me_with_n_validators(
                threshold,
                shares_num,
                i as usize,
                validator_num,
            );
            let message = dkg.share(rng).unwrap();
            let sender = dkg.me.validator.clone();
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
                // Check that shares accumulates correctly
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
        let (mut dkg, _) = setup_dkg();
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0
            }
        ));
        let pvss = dkg.share(rng).unwrap();
        let unknown_validator_i = dkg.dkg_params.shares_num + 1;
        let sender = Validator::<E> {
            address: gen_address(unknown_validator_i as usize),
            public_key: ferveo_common::Keypair::<E>::new(rng).public_key(),
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
        let (mut dkg, _) = setup_dkg();
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
        let sender = dkg.me.validator.clone();

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
        let (mut dkg, _) = setup_dkg();
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

        let sender = dkg.me.validator.clone();

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
        let (mut dkg, _) = setup_dkg();
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));

        dkg.state = DkgState::Success {
            public_key: G1::zero(),
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
        let (mut dkg, _) = setup_dkg();
        let pvss = dkg.share(rng).unwrap();
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));

        let sender = dkg.me.validator.clone();

        dkg.state = DkgState::Success {
            public_key: G1::zero(),
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

    use super::test_common::*;

    /// Test that if the security threshold is
    /// met, we can create a final key
    #[test]
    fn test_aggregate() {
        let (mut dkg, _) = setup_dealt_dkg();
        let aggregate = dkg.aggregate().unwrap();
        let sender = dkg.me.validator.clone();
        assert!(dkg.verify_message(&sender, &aggregate).is_ok());
        assert!(dkg.apply_message(&sender, &aggregate).is_ok());
        assert!(matches!(dkg.state, DkgState::Success { .. }));
    }

    /// Test that aggregate only succeeds if we are in
    /// the state [`DkgState::Dealt]
    #[test]
    fn test_aggregate_state_guards() {
        let (mut dkg, _) = setup_dealt_dkg();
        dkg.state = DkgState::Sharing {
            accumulated_shares: 0,
            block: 0,
        };
        assert!(dkg.aggregate().is_err());
        dkg.state = DkgState::Success {
            public_key: G1::zero(),
        };
        assert!(dkg.aggregate().is_err());
    }

    /// Test that aggregate message fail to be verified
    /// or applied unless dkg.state is
    /// [`DkgState::Dealt`]
    #[test]
    fn test_aggregate_message_state_guards() {
        let (mut dkg, _) = setup_dealt_dkg();
        let aggregate = dkg.aggregate().unwrap();
        let sender = dkg.me.validator.clone();

        dkg.state = DkgState::Sharing {
            accumulated_shares: 0,
            block: 0,
        };
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
        assert!(dkg.apply_message(&sender, &aggregate).is_err());

        dkg.state = DkgState::Success {
            public_key: G1::zero(),
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
        let sender = dkg.me.validator.clone();
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
    }

    /// If the aggregated pvss passes, check that the announced
    /// key is correct. Verification should fail if it is not
    #[test]
    fn test_aggregate_wont_verify_if_wrong_key() {
        let (dkg, _) = setup_dealt_dkg();
        let mut aggregate = dkg.aggregate().unwrap();
        while dkg.public_key() == G1::zero() {
            let (_dkg, _) = setup_dealt_dkg();
        }
        if let Message::Aggregate(Aggregation { public_key, .. }) =
            &mut aggregate
        {
            *public_key = G1::zero();
        }
        let sender = dkg.me.validator.clone();
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
    }
}

/// Test DKG parameters
#[cfg(test)]
mod test_dkg_params {
    const TAU: u32 = 0;

    #[test]
    fn test_shares_num_less_than_security_threshold() {
        let dkg_params = super::DkgParams::new(TAU, 4, 3);
        assert!(dkg_params.is_err());
    }

    #[test]
    fn test_valid_dkg_params() {
        let dkg_params = super::DkgParams::new(TAU, 2, 3);
        assert!(dkg_params.is_ok());
    }
}
