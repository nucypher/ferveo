use std::collections::HashSet;

use ark_ec::pairing::Pairing;
use ferveo_common::PublicKey as ValidatorPublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Represents an external validator
pub struct Validator<E: Pairing> {
    /// The Public key
    #[serde(bound(
        serialize = "ValidatorPublicKey<E>: Serialize",
        deserialize = "ValidatorPublicKey<E>: DeserializeOwned"
    ))]
    pub public_key: ValidatorPublicKey<E>,
    /// The index of the validator in the given ritual
    pub share_index: u32,
}

impl<E: Pairing> Validator<E> {
    pub fn new(public_key: ValidatorPublicKey<E>, share_index: u32) -> Self {
        Self {
            public_key,
            share_index,
        }
    }
}

pub fn assert_no_share_duplicates<E: Pairing>(
    validators: &[Validator<E>],
) -> Result<(), Error> {
    let mut set = HashSet::new();
    for validator in validators {
        if set.contains(&validator.share_index) {
            return Err(Error::DuplicatedShareIndex(validator.share_index));
        } else {
            set.insert(validator.share_index);
        }
    }
    Ok(())
}
