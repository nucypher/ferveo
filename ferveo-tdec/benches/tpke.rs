#![allow(clippy::redundant_closure)]

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use ferveo_tdec::{
    test_common::{setup_fast, setup_simple},
    *,
};
use rand::prelude::StdRng;
use rand_core::{RngCore, SeedableRng};

const NUM_SHARES_CASES: [usize; 5] = [4, 8, 16, 32, 64];
const MSG_SIZE_CASES: [usize; 7] = [256, 512, 1024, 2048, 4096, 8192, 16384];

type E = Bls12_381;
type G2Prepared = <E as Pairing>::G2Prepared;

#[allow(dead_code)]
#[derive(Clone)]
struct SetupShared {
    threshold: usize,
    shares_num: usize,
    msg: Vec<u8>,
    aad: Vec<u8>,
    pubkey: PublicKey<E>,
    privkey: PrivateKeyShare<E>,
    ciphertext: Ciphertext<E>,
    shared_secret: SharedSecret<E>,
}

#[derive(Clone)]
struct SetupFast {
    shared: SetupShared,
    contexts: Vec<PrivateDecryptionContextFast<E>>,
    pub_contexts: Vec<PublicDecryptionContextFast<E>>,
    decryption_shares: Vec<DecryptionShareFast<E>>,
    prepared_key_shares: Vec<G2Prepared>,
}

impl SetupFast {
    pub fn new(shares_num: usize, msg_size: usize, rng: &mut StdRng) -> Self {
        let threshold = shares_num * 2 / 3;
        let mut msg: Vec<u8> = vec![0u8; msg_size];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, contexts) =
            setup_fast::<E>(threshold, shares_num, rng);
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg.clone()), aad, &pubkey, rng)
                .unwrap();

        let mut decryption_shares: Vec<DecryptionShareFast<E>> = vec![];
        for context in contexts.iter() {
            decryption_shares
                .push(context.create_share(&ciphertext, aad).unwrap());
        }

        let pub_contexts = contexts[0].clone().public_decryption_contexts;
        let prepared_key_shares =
            prepare_combine_fast(&pub_contexts, &decryption_shares);

        let shared_secret = share_combine_fast_unchecked(
            &decryption_shares,
            &prepared_key_shares,
        );

        let shared = SetupShared {
            threshold,
            shares_num,
            msg: msg.to_vec(),
            aad: aad.to_vec(),
            pubkey,
            privkey,
            ciphertext,
            shared_secret,
        };
        Self {
            shared,
            contexts,
            pub_contexts,
            decryption_shares,
            prepared_key_shares,
        }
    }
}

#[derive(Clone)]
struct SetupSimple {
    shared: SetupShared,
    contexts: Vec<PrivateDecryptionContextSimple<E>>,
    pub_contexts: Vec<PublicDecryptionContextSimple<E>>,
    decryption_shares: Vec<DecryptionShareSimple<E>>,
    lagrange_coeffs: Vec<Fr>,
}

impl SetupSimple {
    pub fn new(shares_num: usize, msg_size: usize, rng: &mut StdRng) -> Self {
        let threshold = shares_num * 2 / 3;
        let mut msg: Vec<u8> = vec![0u8; msg_size];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, contexts) =
            setup_simple::<E>(shares_num, threshold, rng);

        // Ciphertext.commitment is already computed to match U
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg.clone()), aad, &pubkey, rng)
                .unwrap();

        // Creating decryption shares
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|context| {
                context
                    .create_share(&ciphertext.header().unwrap(), aad)
                    .unwrap()
            })
            .collect();

        let pub_contexts = contexts[0].clone().public_decryption_contexts;
        let domain: Vec<Fr> = pub_contexts.iter().map(|c| c.domain).collect();
        let lagrange_coeffs = prepare_combine_simple::<E>(&domain);

        let shared_secret =
            share_combine_simple::<E>(&decryption_shares, &lagrange_coeffs);

        let shared = SetupShared {
            threshold,
            shares_num,
            msg: msg.to_vec(),
            aad: aad.to_vec(),
            pubkey,
            privkey,
            ciphertext,
            shared_secret,
        };
        Self {
            shared,
            contexts,
            pub_contexts,
            decryption_shares,
            lagrange_coeffs,
        }
    }
}

pub fn bench_create_decryption_share(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("SHARE CREATE");
    group.sample_size(10);

    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in NUM_SHARES_CASES {
        let fast = {
            let setup = SetupFast::new(shares_num, msg_size, rng);
            move || {
                black_box({
                    // TODO: Consider running benchmarks for a single iteration and not for all iterations.
                    // This way we could test the performance of this method for a single participant.
                    setup
                        .contexts
                        .iter()
                        .map(|ctx| {
                            ctx.create_share(
                                &setup.shared.ciphertext,
                                &setup.shared.aad,
                            )
                        })
                        .collect::<Vec<_>>()
                })
            }
        };
        let simple = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || {
                black_box({
                    // TODO: Consider running benchmarks for a single iteration and not for all iterations.
                    // This way we could test the performance of this method for a single participant.
                    setup
                        .contexts
                        .iter()
                        .map(|ctx| {
                            // Using create_unchecked here to avoid the cost of verifying the ciphertext
                            DecryptionShareSimple::create_unchecked(
                                &ctx.setup_params.b,
                                &ctx.private_key_share,
                                &setup.shared.ciphertext.header().unwrap(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            }
        };
        let simple_precomputed = {
            let setup = SetupSimple::new(shares_num, MSG_SIZE_CASES[0], rng);
            let selected_participants =
                (0..setup.shared.threshold).collect::<Vec<_>>();
            move || {
                black_box(
                    setup
                        .contexts
                        .iter()
                        .map(|context| {
                            context.create_share_precomputed(
                                &setup.shared.ciphertext.header().unwrap(),
                                &setup.shared.aad,
                                &selected_participants,
                            )
                        })
                        .collect::<Vec<_>>(),
                );
            }
        };

        group.bench_function(
            BenchmarkId::new("share_create_fast", shares_num),
            |b| b.iter(|| fast()),
        );
        group.bench_function(
            BenchmarkId::new("share_create_simple", shares_num),
            |b| b.iter(|| simple()),
        );
        group.bench_function(
            BenchmarkId::new("share_create_simple_precomputed", shares_num),
            |b| b.iter(|| simple_precomputed()),
        );
    }
}

pub fn bench_share_prepare(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("SHARE PREPARE");
    group.sample_size(10);
    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in NUM_SHARES_CASES {
        let fast = {
            let setup = SetupFast::new(shares_num, msg_size, rng);
            move || {
                black_box(prepare_combine_fast(
                    &setup.pub_contexts,
                    &setup.decryption_shares,
                ))
            }
        };
        let simple = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            let domain: Vec<Fr> =
                setup.pub_contexts.iter().map(|c| c.domain).collect();
            move || black_box(prepare_combine_simple::<E>(&domain))
        };

        group.bench_function(
            BenchmarkId::new("share_prepare_fast", shares_num),
            |b| b.iter(|| fast()),
        );
        group.bench_function(
            BenchmarkId::new("share_prepare_simple", shares_num),
            |b| b.iter(|| simple()),
        );
    }
}

pub fn bench_share_combine(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("SHARE COMBINE");
    group.sample_size(10);

    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in NUM_SHARES_CASES {
        let fast = {
            let setup = SetupFast::new(shares_num, msg_size, rng);
            move || {
                black_box(share_combine_fast_unchecked(
                    &setup.decryption_shares,
                    &setup.prepared_key_shares,
                ));
            }
        };
        let simple = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || {
                black_box(share_combine_simple::<E>(
                    &setup.decryption_shares,
                    &setup.lagrange_coeffs,
                ));
            }
        };
        let simple_precomputed = {
            let setup = SetupSimple::new(shares_num, MSG_SIZE_CASES[0], rng);
            // TODO: Use threshold instead of shares_num
            let selected_participants = (0..shares_num).collect::<Vec<_>>();

            let decryption_shares: Vec<_> = setup
                .contexts
                .iter()
                .map(|context| {
                    context
                        .create_share_precomputed(
                            &setup.shared.ciphertext.header().unwrap(),
                            &setup.shared.aad,
                            &selected_participants,
                        )
                        .unwrap()
                })
                .collect();

            move || {
                black_box(share_combine_precomputed::<E>(&decryption_shares));
            }
        };

        group.bench_function(
            BenchmarkId::new("share_combine_fast", shares_num),
            |b| b.iter(|| fast()),
        );
        group.bench_function(
            BenchmarkId::new("share_combine_simple", shares_num),
            |b| b.iter(|| simple()),
        );
        group.bench_function(
            BenchmarkId::new("share_combine_simple_precomputed", shares_num),
            |b| b.iter(|| simple_precomputed()),
        );
    }
}

pub fn bench_share_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("ENCRYPT DECRYPT");
    group.sample_size(10);

    let rng = &mut StdRng::seed_from_u64(0);
    let shares_num = NUM_SHARES_CASES[0];

    for msg_size in MSG_SIZE_CASES {
        let mut encrypt = {
            let mut rng = rng.clone();
            let setup = SetupFast::new(shares_num, msg_size, &mut rng);
            move || {
                let setup = setup.clone();
                black_box(
                    encrypt::<E>(
                        SecretBox::new(setup.shared.msg),
                        &setup.shared.aad,
                        &setup.shared.pubkey,
                        &mut rng,
                    )
                    .unwrap(),
                );
            }
        };
        let decrypt = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || {
                black_box(
                    decrypt_with_shared_secret::<E>(
                        &setup.shared.ciphertext,
                        &setup.shared.aad,
                        &setup.shared.shared_secret,
                        &setup.contexts[0].setup_params.g_inv,
                    )
                    .unwrap(),
                );
            }
        };

        group.bench_function(BenchmarkId::new("encrypt", msg_size), |b| {
            b.iter(|| encrypt())
        });
        group.bench_function(BenchmarkId::new("decrypt", msg_size), |b| {
            b.iter(|| decrypt())
        });
    }
}

pub fn bench_ciphertext_validity_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("CIPHERTEXT VERIFICATION");
    group.sample_size(10);

    let rng = &mut StdRng::seed_from_u64(0);
    let shares_num = NUM_SHARES_CASES[0];

    for msg_size in MSG_SIZE_CASES {
        let ciphertext_verification = {
            let mut rng = rng.clone();
            let setup = SetupFast::new(shares_num, msg_size, &mut rng);
            move || {
                black_box(setup.shared.ciphertext.check(
                    &setup.shared.aad,
                    &setup.contexts[0].setup_params.g_inv,
                ))
                .unwrap();
            }
        };
        group.bench_function(
            BenchmarkId::new("ciphertext_verification", msg_size),
            |b| b.iter(|| ciphertext_verification()),
        );
    }
}

pub fn bench_decryption_share_validity_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("DECRYPTION SHARE VERIFICATION");
    group.sample_size(10);

    let rng = &mut StdRng::seed_from_u64(0);
    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in NUM_SHARES_CASES {
        let share_fast_verification = {
            let mut rng = rng.clone();
            let setup = SetupFast::new(shares_num, msg_size, &mut rng);
            move || {
                black_box(verify_decryption_shares_fast(
                    &setup.pub_contexts,
                    &setup.shared.ciphertext,
                    &setup.decryption_shares,
                ))
            }
        };
        group.bench_function(
            BenchmarkId::new("share_fast_verification", shares_num),
            |b| b.iter(|| share_fast_verification()),
        );

        let mut share_fast_batch_verification = {
            let mut rng = rng.clone();
            let setup = SetupFast::new(shares_num, msg_size, &mut rng);
            // We need to repackage a bunch of variables here to avoid borrowing issues:
            let ciphertext = setup.shared.ciphertext.clone();
            let ciphertexts = vec![ciphertext];
            let decryption_shares = setup.decryption_shares.clone();
            let decryption_shares = vec![decryption_shares];
            move || {
                black_box(batch_verify_decryption_shares(
                    &setup.pub_contexts,
                    &ciphertexts,
                    &decryption_shares,
                    &mut rng,
                ))
            }
        };
        group.bench_function(
            BenchmarkId::new("share_fast_batch_verification", shares_num),
            |b| b.iter(|| share_fast_batch_verification()),
        );

        let share_simple_verification = {
            let mut rng = rng.clone();
            let setup = SetupSimple::new(shares_num, msg_size, &mut rng);
            move || {
                black_box(verify_decryption_shares_simple(
                    &setup.pub_contexts,
                    &setup.shared.ciphertext,
                    &setup.decryption_shares,
                ))
            }
        };
        group.bench_function(
            BenchmarkId::new("share_simple_verification", shares_num),
            |b| b.iter(|| share_simple_verification()),
        );
    }
}

// TODO: Relocate benchmark to ferveo/benches as part of #162, #163
// pub fn bench_recover_share_at_point(c: &mut Criterion) {
//     let mut group = c.benchmark_group("RECOVER SHARE");
//     let rng = &mut StdRng::seed_from_u64(0);
//     let msg_size = MSG_SIZE_CASES[0];

//     for &shares_num in NUM_SHARES_CASES.iter() {
//         let mut setup = SetupSimple::new(shares_num, msg_size, rng);
//         let threshold = setup.shared.threshold;
//         let selected_participant = setup.contexts.pop().unwrap();
//         let x_r = selected_participant
//             .public_decryption_contexts
//             .last()
//             .unwrap()
//             .domain;
//         let mut remaining_participants = setup.contexts;
//         for p in &mut remaining_participants {
//             p.public_decryption_contexts.pop();
//         }
//         let domain_points = &remaining_participants[0]
//             .public_decryption_contexts
//             .iter()
//             .map(|ctxt| ctxt.domain)
//             .collect::<Vec<_>>();
//         let h = remaining_participants[0].public_decryption_contexts[0].h;
//         let share_updates = remaining_participants
//             .iter()
//             .map(|p| {
//                 let deltas_i = prepare_share_updates_for_recovery::<E>(
//                     domain_points,
//                     &h,
//                     &x_r,
//                     threshold,
//                     rng,
//                 );
//                 (p.index, deltas_i)
//             })
//             .collect::<HashMap<_, _>>();
//         let new_share_fragments: Vec<_> = remaining_participants
//             .iter()
//             .map(|p| {
//                 // Current participant receives updates from other participants
//                 let updates_for_participant: Vec<_> = share_updates
//                     .values()
//                     .map(|updates| *updates.get(p.index).unwrap())
//                     .collect();

//                 // And updates their share
//                 apply_updates_to_private_share::<E>(
//                     &p.private_key_share,
//                     &updates_for_participant,
//                 )
//             })
//             .collect();
//         group.bench_function(
//             BenchmarkId::new(
//                 "recover_share_from_updated_private_shares",
//                 shares_num,
//             ),
//             |b| {
//                 b.iter(|| {
//                     let _ = black_box(
//                         recover_share_from_updated_private_shares::<E>(
//                             &x_r,
//                             domain_points,
//                             &new_share_fragments,
//                         ),
//                     );
//                 });
//             },
//         );
//     }
// }

// TODO: Relocate benchmark to ferveo/benches as part of #162, #163
// pub fn bench_refresh_shares(c: &mut Criterion) {
//     let mut group = c.benchmark_group("REFRESH SHARES");
//     let rng = &mut StdRng::seed_from_u64(0);
//     let msg_size = MSG_SIZE_CASES[0];

//     for &shares_num in NUM_SHARES_CASES.iter() {
//         let setup = SetupSimple::new(shares_num, msg_size, rng);
//         let threshold = setup.shared.threshold;
//         let polynomial = create_random_polynomial_with_root::<E>(
//             threshold - 1,
//             &Fr::zero(),
//             rng,
//         );
//         let p = setup.contexts[0].clone();
//         group.bench_function(
//             BenchmarkId::new("refresh_private_key_share", shares_num),
//             |b| {
//                 b.iter(|| {
//                     black_box(refresh_private_key_share::<E>(
//                         &p.setup_params.h.into_group(),
//                         &p.public_decryption_contexts[0].domain,
//                         &polynomial,
//                         &p.private_key_share,
//                     ));
//                 });
//             },
//         );
//     }
// }

criterion_group!(
    benches,
    bench_create_decryption_share,
    bench_share_prepare,
    bench_share_combine,
    bench_share_encrypt_decrypt,
    bench_ciphertext_validity_checks,
    bench_decryption_share_validity_checks,
    // bench_recover_share_at_point,
    // bench_refresh_shares,
);

criterion_main!(benches);
