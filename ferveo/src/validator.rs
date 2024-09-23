use std::{collections::HashSet, fmt::Display, str::FromStr};

use ark_ec::pairing::Pairing;
use ferveo_common::PublicKey as ValidatorPublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Error;

const ETHEREUM_ADDRESS_LEN: usize = 42;

#[derive(
    Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize, Hash,
)]
pub struct EthereumAddress(String);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EthereumAddressParseError {
    #[error("Invalid Ethereum address length.")]
    InvalidLength,

    #[error("Invalid hex value in Ethereum address.")]
    InvalidHex,
}

impl FromStr for EthereumAddress {
    type Err = EthereumAddressParseError;

    fn from_str(s: &str) -> Result<EthereumAddress, EthereumAddressParseError> {
        if s.len() != ETHEREUM_ADDRESS_LEN {
            return Err(EthereumAddressParseError::InvalidLength);
        }
        let prefix_len = "0x".len();
        hex::decode(&s[prefix_len..])
            .map_err(|_| EthereumAddressParseError::InvalidHex)?;
        Ok(EthereumAddress(s.to_string()))
    }
}

impl Display for EthereumAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Represents an external validator
pub struct Validator<E: Pairing> {
    /// The established address of the validator
    pub address: EthereumAddress,
    /// The Public key
    pub public_key: ValidatorPublicKey<E>,
    /// The index of the validator in the given ritual
    pub share_index: u32,
}

impl<E: Pairing> Validator<E> {
    pub fn new(
        address: String,
        public_key: ValidatorPublicKey<E>,
        share_index: u32,
    ) -> Result<Self, EthereumAddressParseError> {
        Ok(Self {
            address: EthereumAddress::from_str(&address)?,
            public_key,
            share_index,
        })
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
