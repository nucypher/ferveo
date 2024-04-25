//! Test suite for the Node.js.

extern crate wasm_bindgen_test;

use ferveo_wasm::{test_common::*, *};
use itertools::zip_eq;
use wasm_bindgen_test::*;

type TestSetup = (
    Vec<Keypair>,
    Vec<Validator>,
    ValidatorArray,
    ValidatorMessageArray,
    Vec<u8>,
    Vec<u8>,
    Ciphertext,
);

const TAU: u32 = 0;

fn setup_dkg(
    shares_num: u32,
    validators_num: u32,
    security_threshold: u32,
) -> TestSetup {
    let validator_keypairs = (0..validators_num as usize)
        .map(gen_keypair)
        .collect::<Vec<Keypair>>();
    let validators = validator_keypairs
        .iter()
        .enumerate()
        .map(|(i, keypair)| gen_validator(i, keypair))
        .collect::<Vec<Validator>>();
    let validators_js = into_js_array(validators.clone());

    // Each validator holds their own DKG instance and generates a transcript every
    // validator, including themselves
    let messages = validators.iter().map(|sender| {
        let mut validator_dkg = Dkg::new(
            TAU,
            shares_num,
            security_threshold,
            &validators_js,
            sender,
        )
        .unwrap();
        let transcript = validator_dkg.generate_transcript().unwrap();
        ValidatorMessage::new(sender, &transcript).unwrap()
    });

    // Now that every validator holds a dkg instance and a transcript for every other validator,
    // every validator can aggregate the transcripts

    let mut dkg = Dkg::new(
        TAU,
        shares_num,
        security_threshold,
        &validators_js,
        &validators[0],
    )
    .unwrap();

    // We only need `shares_num` messages to aggregate the transcripts
    let messages = messages.take(shares_num as usize).collect::<Vec<_>>();
    let messages_js = into_js_array(messages);

    // Server can aggregate the transcripts and verify them
    let server_aggregate = dkg.aggregate_transcripts(&messages_js).unwrap();
    let is_valid = server_aggregate
        .verify(validators_num, &messages_js)
        .unwrap();
    assert!(is_valid);

    // Client can also aggregate the transcripts and verify them
    let client_aggregate = AggregatedTranscript::new(&messages_js).unwrap();
    let is_valid = client_aggregate
        .verify(validators_num, &messages_js)
        .unwrap();
    assert!(is_valid);

    // In the meantime, the client creates a ciphertext and decryption request
    let msg = "my-msg".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();
    let ciphertext =
        ferveo_encrypt(&msg, &aad, &client_aggregate.public_key()).unwrap();

    (
        validator_keypairs,
        validators,
        validators_js,
        messages_js,
        msg,
        aad,
        ciphertext,
    )
}

#[wasm_bindgen_test]
fn tdec_simple() {
    let shares_num = 16;
    let security_threshold = shares_num / 2;
    for validators_num in [shares_num, shares_num + 2] {
        let (
            validator_keypairs,
            validators,
            validators_js,
            messages_js,
            msg,
            aad,
            ciphertext,
        ) = setup_dkg(shares_num, validators_num, security_threshold);

        // Having aggregated the transcripts, the validators can now create decryption shares
        let decryption_shares = zip_eq(validators, validator_keypairs)
            .map(|(validator, keypair)| {
                let mut dkg = Dkg::new(
                    TAU,
                    shares_num,
                    security_threshold,
                    &validators_js,
                    &validator,
                )
                .unwrap();
                let aggregate =
                    dkg.aggregate_transcripts(&messages_js).unwrap();
                let is_valid =
                    aggregate.verify(validators_num, &messages_js).unwrap();
                assert!(is_valid);
                aggregate
                    .create_decryption_share_simple(
                        &dkg,
                        &ciphertext.header().unwrap(),
                        &aad,
                        &keypair,
                    )
                    .unwrap()
            })
            // We only need `security_threshold` decryption shares in simple variant
            .take(security_threshold as usize)
            .collect::<Vec<DecryptionShareSimple>>();

        let decryption_shares_js = into_js_array(decryption_shares);

        // Now, decryption shares can be used to decrypt the ciphertext
        // This part happens in the client API
        let shared_secret =
            combine_decryption_shares_simple(&decryption_shares_js).unwrap();
        let plaintext =
            decrypt_with_shared_secret(&ciphertext, &aad, &shared_secret)
                .unwrap();
        assert_eq!(msg, plaintext);
    }
}

#[wasm_bindgen_test]
fn tdec_precomputed() {
    let shares_num = 16;
    let security_threshold = shares_num * 2 / 3;
    for validators_num in [shares_num, shares_num + 2] {
        let (
            validator_keypairs,
            validators,
            validators_js,
            messages_js,
            msg,
            aad,
            ciphertext,
        ) = setup_dkg(shares_num, validators_num, security_threshold);

        // In precomputed variant, the client selects a subset of validators to create decryption shares
        let selected_validators =
            validators[..(security_threshold as usize)].to_vec();
        let selected_validators_js = into_js_array(selected_validators);

        // Having aggregated the transcripts, the validators can now create decryption shares
        let decryption_shares = zip_eq(validators, validator_keypairs)
            .map(|(validator, keypair)| {
                let mut dkg = Dkg::new(
                    TAU,
                    shares_num,
                    security_threshold,
                    &validators_js,
                    &validator,
                )
                .unwrap();
                let server_aggregate =
                    dkg.aggregate_transcripts(&messages_js).unwrap();
                assert!(server_aggregate
                    .verify(validators_num, &messages_js)
                    .unwrap());
                server_aggregate
                    .create_decryption_share_precomputed(
                        &dkg,
                        &ciphertext.header().unwrap(),
                        &aad,
                        &keypair,
                        &selected_validators_js,
                    )
                    .unwrap()
            })
            // We need `security_threshold` decryption shares to decrypt
            .take(security_threshold as usize)
            .collect::<Vec<DecryptionSharePrecomputed>>();
        let decryption_shares_js = into_js_array(decryption_shares);

        // Now, decryption shares can be used to decrypt the ciphertext
        // This part happens in the client API
        let shared_secret =
            combine_decryption_shares_precomputed(&decryption_shares_js)
                .unwrap();
        let plaintext =
            decrypt_with_shared_secret(&ciphertext, &aad, &shared_secret)
                .unwrap();
        assert_eq!(msg, plaintext);
    }
}
