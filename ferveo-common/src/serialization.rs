//! This adds a few utility functions for serializing and deserializing
//! [arkworks](http://arkworks.rs/) types that implement [CanonicalSerialize] and [CanonicalDeserialize].
//! Adapted from [o1-labs/proof-systems](https://raw.githubusercontent.com/o1-labs/proof-systems/31c76ceae3122f0ce09cded8260960ed5cbbe3d8/utils/src/serialization.rs).

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{self, Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};

//
// Serialization with serde
//

pub mod ser {
    //! You can use this module for serialization and deserializing arkworks types with [serde].
    //! Simply use the following attribute on your field:
    //! `#[serde(with = "serialization::ser") attribute"]`

    use serde_encoded_bytes::{Hex, SliceLike};

    use super::*;

    /// You can use this to serialize an arkworks type with serde and the "serialize_with" attribute.
    /// See <https://serde.rs/field-attrs.html>
    pub fn serialize<S>(
        val: impl CanonicalSerialize,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        SliceLike::<Hex>::serialize(&bytes, serializer)
    }

    /// You can use this to deserialize an arkworks type with serde and the "deserialize_with" attribute.
    /// See <https://serde.rs/field-attrs.html>
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: CanonicalDeserialize,
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = SliceLike::<Hex>::deserialize(deserializer)?;
        T::deserialize_compressed(&mut &bytes[..])
            .map_err(serde::de::Error::custom)
    }
}

//
// Serialization with [serde_with]
//

/// You can use [SerdeAs] with [serde_with] in order to serialize and deserialize types that implement [CanonicalSerialize] and [CanonicalDeserialize],
/// or containers of types that implement these traits (Vec, arrays, etc.)
/// Simply add annotations like `#[serde_as(as = "serialization::SerdeAs")]`
/// See <https://docs.rs/serde_with/1.10.0/serde_with/guide/serde_as/index.html#switching-from-serdes-with-to-serde_as>
pub struct SerdeAs;

impl<T> serde_with::SerializeAs<T> for SerdeAs
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        SliceLike::<Hex>::serialize(&bytes, serializer)
    }
}

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAs
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = SliceLike::<Hex>::deserialize(deserializer)?;
        T::deserialize_compressed(&mut &bytes[..])
            .map_err(serde::de::Error::custom)
    }
}

// TODO: Trait aliases are experimental
// trait ByteSerializable = ToBytes + FromBytes;

pub trait ToBytes {
    fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error>;
}

pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error>;
}

impl<T: Serialize> ToBytes for T {
    fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }
}

impl<T: for<'de> Deserialize<'de>> FromBytes for T {
    fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Test {
        a: u32,
        b: u32,
    }

    #[test]
    fn test_serde() {
        let test = Test { a: 1, b: 2 };
        let bytes = test.to_bytes().unwrap();
        let test2 = Test::from_bytes(&bytes).unwrap();
        assert_eq!(test, test2);
    }
}
