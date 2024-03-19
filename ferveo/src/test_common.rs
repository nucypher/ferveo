/// Factory functions and variables for testing
use std::str::FromStr;

use ark_bls12_381::Bls12_381;
pub use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use ferveo_common::Keypair;
use rand::{seq::SliceRandom, Rng};

use crate::{
    DkgParams, EthereumAddress, PubliclyVerifiableDkg, PubliclyVerifiableSS,
    Validator, ValidatorMessage,
};

pub type ScalarField = <E as Pairing>::ScalarField;
pub type G1 = <E as Pairing>::G1Affine;
pub type G2 = <E as Pairing>::G2Affine;
pub type TargetField = <E as Pairing>::TargetField;

pub const TAU: u32 = 0;
pub const MSG: &[u8] = b"my-msg";
pub const AAD: &[u8] = b"my-aad";
pub const SECURITY_THRESHOLD: u32 = 3;
pub const SHARES_NUM: u32 = 4;
pub const VALIDATORS_NUM: u32 = SHARES_NUM + 2;

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
            share_index: i as u32,
        })
        .collect()
}

pub type TestSetup = (PubliclyVerifiableDkg<E>, Vec<Keypair<E>>);

pub fn setup_dkg_for_n_validators(
    security_threshold: u32,
    shares_num: u32,
    my_validator_index: usize,
    validators_num: u32,
) -> TestSetup {
    let keypairs = gen_keypairs(validators_num);
    let validators = gen_validators(keypairs.as_slice());
    let me = validators[my_validator_index].clone();
    let dkg = PubliclyVerifiableDkg::new(
        &validators,
        &DkgParams::new(TAU, security_threshold, shares_num).unwrap(),
        &me,
    )
    .expect("Setup failed");
    (dkg, keypairs)
}

/// Create a test dkg
///
/// The [`crate::dkg::test_dkg_init`] module checks correctness of this setup
pub fn setup_dkg(my_validator_index: usize) -> TestSetup {
    setup_dkg_for_n_validators(
        SECURITY_THRESHOLD,
        SHARES_NUM,
        my_validator_index,
        VALIDATORS_NUM,
    )
}

pub type DealtTestSetup = (
    PubliclyVerifiableDkg<E>,
    Vec<Keypair<E>>,
    Vec<ValidatorMessage<E>>,
);

/// Set up a dkg with enough pvss transcripts to meet the threshold
///
/// The correctness of this function is tested in the module [`crate::dkg::test_dealing`]
pub fn setup_dealt_dkg() -> DealtTestSetup {
    setup_dealt_dkg_with(SECURITY_THRESHOLD, SHARES_NUM)
}

// TODO: Rewrite setup_utils to return messages separately

pub fn setup_dealt_dkg_with(
    security_threshold: u32,
    shares_num: u32,
) -> DealtTestSetup {
    setup_dealt_dkg_with_n_validators(
        security_threshold,
        shares_num,
        shares_num,
    )
}

pub fn setup_dealt_dkg_with_n_validators(
    security_threshold: u32,
    shares_num: u32,
    validators_num: u32,
) -> DealtTestSetup {
    setup_dealt_dkg_with_n_transcript_dealt(
        security_threshold,
        shares_num,
        validators_num,
        security_threshold,
    )
}

pub fn make_messages(
    rng: &mut (impl Rng + Sized),
    dkg: &PubliclyVerifiableDkg<Bls12_381>,
) -> Vec<(Validator<E>, PubliclyVerifiableSS<E>)> {
    let mut messages = vec![];
    for i in 0..dkg.dkg_params.shares_num() {
        let (dkg, _) = setup_dkg(i as usize);
        let transcript = dkg.generate_transcript(rng).unwrap();
        let sender = dkg.me.clone();
        messages.push((sender, transcript));
    }
    messages
}

pub fn setup_dealt_dkg_with_n_transcript_dealt(
    security_threshold: u32,
    shares_num: u32,
    validators_num: u32,
    transcripts_to_use: u32,
) -> DealtTestSetup {
    let rng = &mut ark_std::test_rng();

    // Gather everyone's transcripts
    // Use only the first `transcripts_to_use` transcripts
    let mut transcripts: Vec<_> = (0..transcripts_to_use)
        .map(|my_index| {
            let (dkg, _) = setup_dkg_for_n_validators(
                security_threshold,
                shares_num,
                my_index as usize,
                validators_num,
            );
            let me = dkg.me.clone();
            let transcript = dkg.generate_transcript(rng).unwrap();
            (me, transcript)
        })
        .collect();

    // Create a test DKG instance
    let (dkg, keypairs) = setup_dkg_for_n_validators(
        security_threshold,
        shares_num,
        0,
        validators_num,
    );
    // The ordering of messages should not matter
    transcripts.shuffle(rng);
    (dkg, keypairs, transcripts)
}
