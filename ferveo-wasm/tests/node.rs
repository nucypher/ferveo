//! Test suite for the Nodejs.

extern crate wasm_bindgen_test;

use ferveo_wasm::{test_common::*, *};
use itertools::zip_eq;
use wasm_bindgen_test::*;

type TestSetup = (
    u32,
    u32,
    u32,
    Vec<Keypair>,
    Vec<Validator>,
    ValidatorArray,
    ValidatorMessageArray,
    Vec<u8>,
    Vec<u8>,
    Ciphertext,
);

fn setup_dkg() -> TestSetup {
    let tau = 1;
    let shares_num: u32 = 16;
    let security_threshold = shares_num * 2 / 3;

    let validator_keypairs = (0..shares_num as usize)
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
        let dkg = Dkg::new(
            tau,
            shares_num,
            security_threshold,
            &validators_js,
            sender,
        )
        .unwrap();
        let transcript = dkg.generate_transcript().unwrap();

        ValidatorMessage::new(sender, &transcript).unwrap()
    });

    // Now that every validator holds a dkg instance and a transcript for every other validator,
    // every validator can aggregate the transcripts

    let mut dkg = Dkg::new(
        tau,
        shares_num,
        security_threshold,
        &validators_js,
        &validators[0],
    )
    .unwrap();

    let messages_js = into_js_array(messages);

    // Server can aggregate the transcripts and verify them
    let server_aggregate = dkg.aggregate_transcripts(&messages_js).unwrap();
    let is_valid = server_aggregate.verify(shares_num, &messages_js).unwrap();
    assert!(is_valid);

    // Client can also aggregate the transcripts and verify them
    let client_aggregate = AggregatedTranscript::new(&messages_js).unwrap();
    let is_valid = client_aggregate.verify(shares_num, &messages_js).unwrap();
    assert!(is_valid);

    // In the meantime, the client creates a ciphertext and decryption request
    let msg = "my-msg".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();
    let ciphertext = ferveo_encrypt(&msg, &aad, &dkg.public_key()).unwrap();

    (
        tau,
        shares_num,
        security_threshold,
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
    let (
        tau,
        shares_num,
        security_threshold,
        validator_keypairs,
        validators,
        validators_js,
        messages_js,
        msg,
        aad,
        ciphertext,
    ) = setup_dkg();

    // Having aggregated the transcripts, the validators can now create decryption shares
    let decryption_shares = zip_eq(validators, validator_keypairs)
        .map(|(validator, keypair)| {
            let mut dkg = Dkg::new(
                tau,
                shares_num,
                security_threshold,
                &validators_js,
                &validator,
            )
            .unwrap();
            let aggregate = dkg.aggregate_transcripts(&messages_js).unwrap();
            let is_valid = aggregate.verify(shares_num, &messages_js).unwrap();
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
        .collect::<Vec<DecryptionShareSimple>>();
    let decryption_shares_js = into_js_array(decryption_shares);

    // Now, the decryption share can be used to decrypt the ciphertext
    // This part is in the client API

    let shared_secret =
        combine_decryption_shares_simple(&decryption_shares_js).unwrap();

    // The client should have access to the public parameters of the DKG
    let plaintext =
        decrypt_with_shared_secret(&ciphertext, &aad, &shared_secret).unwrap();
    assert_eq!(msg, plaintext);
}

#[wasm_bindgen_test]
fn tdec_precomputed() {
    let (
        tau,
        shares_num,
        security_threshold,
        validator_keypairs,
        validators,
        validators_js,
        messages_js,
        msg,
        aad,
        ciphertext,
    ) = setup_dkg();

    // Having aggregated the transcripts, the validators can now create decryption shares
    let decryption_shares = zip_eq(validators, validator_keypairs)
        .map(|(validator, keypair)| {
            let mut dkg = Dkg::new(
                tau,
                shares_num,
                security_threshold,
                &validators_js,
                &validator,
            )
            .unwrap();
            let aggregate = dkg.aggregate_transcripts(&messages_js).unwrap();
            let is_valid = aggregate.verify(shares_num, &messages_js).unwrap();
            assert!(is_valid);

            aggregate
                .create_decryption_share_precomputed(
                    &dkg,
                    &ciphertext.header().unwrap(),
                    &aad,
                    &keypair,
                )
                .unwrap()
        })
        .collect::<Vec<DecryptionSharePrecomputed>>();
    let decryption_shares_js = into_js_array(decryption_shares);

    // Now, the decryption share can be used to decrypt the ciphertext
    // This part is in the client API

    let shared_secret =
        combine_decryption_shares_precomputed(&decryption_shares_js).unwrap();

    // The client should have access to the public parameters of the DKG
    let plaintext =
        decrypt_with_shared_secret(&ciphertext, &aad, &shared_secret).unwrap();
    assert_eq!(msg, plaintext);
}
