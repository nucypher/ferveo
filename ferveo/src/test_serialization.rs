use ferveo_common::{FromBytes, ToBytes};
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use secrecy::SecretBox;

use crate::api::*;

const EXPECTED_VALIDATOR_BINARY_HEX: &str = concat![
    "60000000000000009580af6d5259701d7bc2eb9cbccf48b4ea5b953953a4bebc",
    "f083256c31d885ded41c85329cfff48391d8d45c7ee060f70adb5f3169a528fa",
    "20fad84ef9fc050bdd1d0e4a8cf98744dae5377d0d47bc847d2e2676be4a2136",
    "069fa0dfa93742b800000000",
];
const EXPECTED_VALIDATOR_KEYPAIR_BINARY_HEX: &str = concat![
    "2000000000000000839b4936d38aa2f8d9e4ecf8993f95636692b659f155f572",
    "430745e491fdc241",
];
const EXPECTED_VALIDATOR_PUBLIC_KEY_BINARY_HEX: &str = concat![
    "60000000000000009580af6d5259701d7bc2eb9cbccf48b4ea5b953953a4bebc",
    "f083256c31d885ded41c85329cfff48391d8d45c7ee060f70adb5f3169a528fa",
    "20fad84ef9fc050bdd1d0e4a8cf98744dae5377d0d47bc847d2e2676be4a2136",
    "069fa0dfa93742b8",
];
const EXPECTED_TRANSCRIPT_BINARY_HEX: &str = concat![
    "6800000000000000020000000000000094248a08e31c9ec0d7fabf7535e3dcc0",
    "e70f22f9eda5ade6e6a66f950bb1322ee1f9d798fa7eb6554610e5620fdc3f99",
    "b26b4511ab8a0d66a971c769a0faef74a98f580c205e6516260e8a0b0390f09e",
    "de09accdb3b72a98641b188f9fcb102128010000000000000300000000000000",
    "8748adac53fa6761b638cdda6ab75e0d118ef42fd40595897a6151a0a3134a9a",
    "ecdddc4f440314b2e2874c617e7177ab172e1a60580e51720773310f36d30155",
    "1be8f5cf63515e78f774cf1c91dcbe5d76348e92a120dd3fe1b78fb67f0782a0",
    "b4611c8a8ac208f33632dc303b71ec0b02394f3abaf24bf628e941107ecedb8e",
    "da2e86db99827d8fbedbd8922d48c2fc0f9598b0043bb550a29769279088e93e",
    "0d6bd781fbea06fd0cf84a1b3ac1a1c28e6ccffee0ea1cb21789e50316afa432",
    "80e7eaf0a7eb193c1c7711dced8a0cc75ffc0a47cd731f6aa8a966d5eb1c584a",
    "10b8f9acdcc4901b7550adf5098d0dd514f244f1c0b52bbd0355074bb403edce",
    "a66e7df73ef72b533ac053fc0e34521849e4e4d20cc91cc60b1832435509dfbd",
    "60000000000000008e687a56311ff489c84c1f7bf7981b7b3695451f4491b580",
    "f19c24f52b7d0c47f1e312038e9824a5d64974cf281550cf19b19857bfbb11da",
    "8c195ffbab0ae31a44937c2794871d552af210b0288bf634cc4fc0fffe617d95",
    "83f5f0ad02b29ea3",
];
const EXPECTED_AGGREGATED_TRANSCRIPT_BINARY_HEX: &str = concat![
    "68000000000000000200000000000000b593fb0151e20229edcb564da0628ae7",
    "28d6dbbfe58ca45b06e2058dfb684b0c2a6516cb69ff83d51229086d933c5ae4",
    "8b9edba9df37286552e70682f9db275d4682e479c3ef6d5417652dcf2320a5c6",
    "81379845c8f416acffbbe0c90ebe04a128010000000000000300000000000000",
    "99fd3d0162387ef6ebd96feb36bf1b1fba4dee01fd4ae4667af215e7256745e3",
    "954c54f4fa773a604408b7ea58e21f6106dd33cb857b99b2893f9eb38c252e04",
    "3fc4d76892e6372223a3d0fb8a82744690a0917fd07116260832290de21a58ae",
    "854c95613170d42fee39a159306194281d2528eda64937a5636bc54aaac292cc",
    "753289d222a14241b6837705c3b1c2ab03d4244bdee495ddec3ae264b842645d",
    "7998c6a7281277754fa3367e5640e00f9decebf0a9f820489a5b8a73016611fc",
    "888f703e32b88187302d71245f8b3c6602b5db3a19caea33cb2b918008147cab",
    "f46548a837676ad13e4fc36e92041ecc09ade4bc4591ab97332a84af266a9be5",
    "3cb5b02b7688399fbb013e039d9b44df468553265c6daa042acfc831e2b5bfa1",
    "600000000000000098c62bc13cf7570daf7bf84f9bbe3d58b97fbecfeb0ccac0",
    "645ea6d19032427a676ef46b7609a4c8026e5552f13f34c910fab79edb261228",
    "b79c027f01bc453d0ec7ecb62c78bb31b803efe71bab0b45f6ca65c85e9fe1a6",
    "9ced417f4e3ef0253000000000000000b593fb0151e20229edcb564da0628ae7",
    "28d6dbbfe58ca45b06e2058dfb684b0c2a6516cb69ff83d51229086d933c5ae4",
];
const EXPECTED_DKG_PUBLIC_KEY_BINARY_HEX: &str = concat![
    "3000000000000000b593fb0151e20229edcb564da0628ae728d6dbbfe58ca45b",
    "06e2058dfb684b0c2a6516cb69ff83d51229086d933c5ae4",
];
const EXPECTED_CIPHERTEXT_BINARY_HEX: &str = concat![
    "3000000000000000a4cceadb09fe0a04281b0e814904883538c86bf77e449a18",
    "67661ec806a4e1dd398a5396868e13d3f76e2a7796b164e26000000000000000",
    "8e3646c5760763d672a7e68f1f56dae59f140053e5332e4e3b8d79dfeadff79b",
    "dbeb9a0975afbc9a961cdb95aec253981090186fa58342b4ae91ef9b45b45ed8",
    "aca12fe38303d014bd1155e89f19d13f53b5a5947fc9260a4320bdbbf052ba1c",
    "16000000000000005d7211cd1afebc032eb78c4cfa05e508fa27926de52e",
];
const EXPECTED_CIPHERTEXT_HEADER_BINARY_HEX: &str = concat![
    "3000000000000000a4cceadb09fe0a04281b0e814904883538c86bf77e449a18",
    "67661ec806a4e1dd398a5396868e13d3f76e2a7796b164e26000000000000000",
    "8e3646c5760763d672a7e68f1f56dae59f140053e5332e4e3b8d79dfeadff79b",
    "dbeb9a0975afbc9a961cdb95aec253981090186fa58342b4ae91ef9b45b45ed8",
    "aca12fe38303d014bd1155e89f19d13f53b5a5947fc9260a4320bdbbf052ba1c",
    "dde1dbf3c9db75e93f9997631d51f0544d042dd45fc0006700613a5d15671bfc",
];
const EXPECTED_HANDOVER_TRANSCRIPT_BINARY_HEX: &str = concat![
    "010000006000000000000000b2520d7370b0476705e06f59c8111b34063bb4f5",
    "9d494a9c21c8a69a954ad5595452c69347e67a36959c57f63ef173371462269b",
    "cd9afef28131f8ff2472b4d8274ed8fee5e0f65ce8ba4f78742f5e91b3e583f9",
    "13aae4f4448efae6da0474556000000000000000a9fa8c79eb04d56587a421db",
    "6f202e999ebd06448fde7749c248f1c39a3d8c6572bd1c4823abc47fc73cc772",
    "fd2102930d32910250d0a987979a9aa6aa77950c0fb0fce5335ad7290f2cdd0f",
    "0b7e5d21288fa25249f9b28a4a636baef9b827d6300000000000000090c00a69",
    "d24e3dcaf9cfe6b52b60400b73d1f15673f67ef9218717043127e77b1c082fd9",
    "dfefc9fd95985bb2fbd647fe6000000000000000aba0ce7a5d4327c3936687c3",
    "5db0756a23d293521afc281aa5c7e3b97076f57e43e0a6a80ebe165a61557bf6",
    "155c7e0a08467f29e116b655dcdcbc86488b87c78361c1232257c317408b9237",
    "4a3733590d95d97d788fd016682c5ac7aafa8775600000000000000086a4a874",
    "93e53073f9646273db321e1c6bf81d5dcc87cf442c8ee50de27af6d32184f4c9",
    "5276b152cabd860234a606ab0758fa8f72d65be0efd6824dbde99c16ba2adff8",
    "8407f554afb45ee11677984d5b82cf099f2eafcea95a00bf807bf22860000000",
    "00000000ae0d66b56f1979a5e02406fda7807641d5dd7f5f9c6c1a10cddcb99b",
    "be7e51d7f3973e00b4ec388fce002339d94e16f7186a26eed700442bb281f864",
    "c749eb3a46b0b0f95cb27e6ad84213f6d964ea85a5a855c1662d22f37887ffb2",
    "7a40933b",
];
const EXPECTED_DECRYPTION_SHARE_SIMPLE_BINARY_HEX: &str = concat![
    "400200000000000071e6c0850c76e1029e8543b839d25f54a0aed88cd4040257",
    "448d2807a2c60114241ddd52c9eb10b420497debf152b01052f07eb6296171d5",
    "908bc4f7a9a3daf6069e5949b31e1f59cd6cacc5b0517c526ea036853f14ed3b",
    "84f517d04e509903b6f9d7d57d0d9291737e705065efb7c698fafb5b2b16e37b",
    "bca841cf75cbac4a001ba280c767e39a929d62c07a25d308ad2d6baac40c8f79",
    "1b01a5e394950cfb4d8a78282ff0f979aa62ec30e507637971d8b71ef2c30eeb",
    "97b14b309b0f660ff0da27dd423b5436f01700a14e1e405d4d031ccfe5ea59c5",
    "03addd5a4fde7d8551cb25516a5219fdf2a12a7941040a0c8aed182ac889ad45",
    "aa68008e41bd0360550ec09d1817e09cadc61bbc8e10539081cce32cfafaedb2",
    "92cb8109772a8910c0c40c4dd74e4f30347fab5eaf46e94de28a4d8e4ffc3813",
    "b0670c0f66f697ddd3f833d542d72d5df5d390e23e3163163e17aa791ddcaada",
    "c964808867d2c64cbcd1961e0862e797103ec5dfdae9072ef9dcd116643965eb",
    "2523640c02b43619e4c3f8d81ac36bc82591d6829782e4388656ddc76d97578a",
    "4ea18ac480b2232d1a50fee599da763f76f0b2872b716706c8028616f6b0233b",
    "ed044a13b8f3dd4e114d57e4d0067e1e99b77166fe42760e4d7b948908069be6",
    "aeefb00cb007c512fd5d32896ceacb31dfa7b1387bd0923536f38a615e39e045",
    "a814e1ed2bbc4de4c0c98a5029cd9052f20abe6ee28bbf169af51ab203e8f265",
    "49a3f726e784773e02e6cb7c12e98583c0ef36a66923c61c1b2a63770979f0d0",
    "27e94807512b4e003000000000000000abc30d9ba3e7d483540e55a0bf078590",
    "0e4db2fb9d77e24e4bf9e69357a50988dfc8f95dd5cdbdf67c4fb6276337f862",
    "2000000000000000010000000000000000000000000000000000000000000000",
    "0000000000000000",
];
const EXPECTED_SHARED_SECRET_BINARY_HEX: &str = concat![
    "4002000000000000c5bbab273f0775686e3a31fda150d8a6402df599c3074ea2",
    "57c41625d73bf29e3a8358febdeb4c2a111189194d8ecf15f43cef038ecdabf7",
    "20479e01808fd36ab2cd17c48ea90e5104a688098f79f0b2639c445bc1cfff3d",
    "b4c6f8212984e90a94bb4174b531ed2883a129d45ff5b13e80388901c285c7b8",
    "68c0cc24d3c9f4aae890ac1fa7c2c4dc3eaac18c8d159511b22f1e42521b3b8f",
    "6e295a2fc5bfd15001ad00a705f9d7f98d3e1ecf7b566038134646bd90d4512e",
    "0f7e7eb2cf6fb40ae8d61a43c06862e511d0dddc1b49bb5b1f5bf212f18dc0e8",
    "036b9a66e233f427489eb186fc5a97f98a52ee70b743560c2cda1f0aaa5a20fe",
    "c6ffcedf8525c5808944efa6fae495ab358af0d0787ed35a6f4cf0c472284889",
    "7057a50220c4941504ff877686c15fe4db50bb9907ce5f2228da0ba146c47902",
    "d52f026a63f34015fe58de7f1b5ea66c3be5692fb92b02160fa720d6b176faea",
    "c780f3ededb12efc18727bca8088b5c348e541118888497c8c9b440cce12ac3e",
    "8e70ee082c3d0603e6d62ee32398e7f8ec8aa896bc7a0692f8ed885c62f2ed03",
    "f112522b733b1cba59491e6a42ae7b48d0c351eef4cb820c35a32ab94cf5a671",
    "42c3db3e0e5a72b9a9b4ad931b01c770279f2b7d4c6d651cecc2e5debcc3611b",
    "c136075bfce8c1030ebdbb848d05e03bc0793bf42eb1aa2d78eea01aa9d0595e",
    "b21d2edd222b7171d2e063205f72f97ca99e9b1f759a200b0a38178d92a6dea7",
    "26723dbba91f86f97f4ec7c76c7b987719cddff8a9c9215ef9c30dd32cbec271",
    "a00eacb61c728f10",
];

pub fn check_serialization_roundtrip<T>(obj: &T, expected_binary_hex: &str)
where
    T: core::fmt::Debug + PartialEq + ToBytes + FromBytes,
{
    // Check serialization to Bincode (binary)

    let serialized = obj.to_bytes().unwrap();
    assert_eq!(hex::encode(&serialized), expected_binary_hex);

    let deserialized: T = T::from_bytes(&serialized).unwrap();
    assert_eq!(obj, &deserialized);
}

// Test artifacts produced during simple DKG against saved vectors.
// Helps detect ABI changes.
#[test]
fn test_simple_dkg_handover_serialization() {
    let shares_num = 3;
    let security_threshold = 2;
    let tau = 0;
    let msg = b"my-msg";
    let aad = b"my-aad";

    let mut rng = ChaCha12Rng::seed_from_u64(12345);

    let mut validator_keypairs = (0..shares_num)
        .map(|_| ValidatorKeypair::new(&mut rng))
        .collect::<Vec<_>>();
    let mut validators = validator_keypairs
        .iter()
        .enumerate()
        .map(|(i, keypair)| Validator {
            public_key: keypair.public_key(),
            share_index: i as u32,
        })
        .collect::<Vec<_>>();

    let dkg =
        Dkg::new(tau, shares_num, security_threshold, &validators).unwrap();

    let messages = (0..shares_num)
        .map(|my_index| {
            let transcript = dkg.generate_transcript(&mut rng).unwrap();
            let sender = validators[my_index as usize].clone();
            (sender, transcript)
        })
        .collect::<Vec<_>>();

    check_serialization_roundtrip(
        &validators[0],
        EXPECTED_VALIDATOR_BINARY_HEX,
    );
    check_serialization_roundtrip(
        &validator_keypairs[0],
        EXPECTED_VALIDATOR_KEYPAIR_BINARY_HEX,
    );
    check_serialization_roundtrip(
        &validator_keypairs[0].public_key(),
        EXPECTED_VALIDATOR_PUBLIC_KEY_BINARY_HEX,
    );

    let transcripts = messages
        .iter()
        .take(shares_num as usize)
        .map(|m| m.1.clone())
        .collect::<Vec<_>>();

    check_serialization_roundtrip(
        &transcripts[0],
        EXPECTED_TRANSCRIPT_BINARY_HEX,
    );

    // Initially, each participant creates a transcript, which is
    // combined into a joint AggregateTranscript.
    let local_aggregate = AggregatedTranscript::new(&messages).unwrap();

    check_serialization_roundtrip(
        &local_aggregate,
        EXPECTED_AGGREGATED_TRANSCRIPT_BINARY_HEX,
    );
    check_serialization_roundtrip(
        &local_aggregate.public_key(),
        EXPECTED_DKG_PUBLIC_KEY_BINARY_HEX,
    );

    // Ciphertext created from the aggregate public key
    let ciphertext = encrypt_with_rng(
        SecretBox::new(msg.to_vec().into()),
        aad,
        &local_aggregate.public_key(),
        &mut rng,
    )
    .unwrap();

    check_serialization_roundtrip(&ciphertext, EXPECTED_CIPHERTEXT_BINARY_HEX);
    check_serialization_roundtrip(
        &ciphertext.header().unwrap(),
        EXPECTED_CIPHERTEXT_HEADER_BINARY_HEX,
    );

    // Let's choose a random validator to handover
    let handover_slot_index = 1;
    let departing_keypair = validator_keypairs[handover_slot_index];

    // New participant that will receive the handover
    let incoming_validator_keypair = ValidatorKeypair::new(&mut rng);

    // Incoming node creates a handover transcript
    let handover_transcript = dkg
        .generate_handover_transcript(
            &local_aggregate,
            handover_slot_index as u32,
            &incoming_validator_keypair,
            &mut rng,
        )
        .unwrap();

    check_serialization_roundtrip(
        &handover_transcript,
        EXPECTED_HANDOVER_TRANSCRIPT_BINARY_HEX,
    );

    let aggregate_after_handover = local_aggregate
        .finalize_handover(&handover_transcript, &departing_keypair)
        .unwrap();

    validators[handover_slot_index] = Validator {
        public_key: incoming_validator_keypair.public_key(),
        share_index: handover_slot_index as u32,
    };
    validator_keypairs[handover_slot_index] = incoming_validator_keypair;
    let dkg =
        Dkg::new(tau, shares_num, security_threshold, &validators).unwrap();

    // Get decryption shares, now with the aggregate transcript after handover:
    let decryption_shares: Vec<DecryptionShareSimple> = validator_keypairs
        .iter()
        .map(|validator_keypair| {
            aggregate_after_handover
                .create_decryption_share_simple(
                    &dkg,
                    &ciphertext.header().unwrap(),
                    aad,
                    validator_keypair,
                )
                .unwrap()
        })
        // We take only the first `security_threshold` decryption shares
        .take(security_threshold as usize)
        .collect();
    check_serialization_roundtrip(
        &decryption_shares[0],
        EXPECTED_DECRYPTION_SHARE_SIMPLE_BINARY_HEX,
    );

    let new_shared_secret = combine_shares_simple(&decryption_shares);
    check_serialization_roundtrip(
        &new_shared_secret,
        EXPECTED_SHARED_SECRET_BINARY_HEX,
    );
}
