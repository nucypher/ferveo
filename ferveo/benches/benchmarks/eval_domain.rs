#![allow(clippy::redundant_closure)]
#![allow(clippy::unit_arg)]

use ark_ff::Field;
use ark_poly::EvaluationDomain;
use criterion::{black_box, criterion_group, BenchmarkId, Criterion};
use digest::crypto_common::rand_core::SeedableRng;
use ferveo_nucypher_temp6::*;
use rand::prelude::StdRng;

const NUM_SHARES_CASES: [usize; 6] = [2, 4, 8, 16, 32, 64];

pub fn bench_eval_domain(c: &mut Criterion) {
    let mut group = c.benchmark_group("EVAL DOMAIN");
    group.sample_size(10);

    let rng = &mut StdRng::seed_from_u64(0);
    let s = ark_bls12_381::Fr::from_random_bytes(&[0u8; 32]).unwrap();

    for shares_num in NUM_SHARES_CASES {
        let eval_radix2_eval_domain = {
            let domain =
                ark_poly::GeneralEvaluationDomain::new(shares_num).unwrap();
            let phi = SecretPolynomial::<ark_bls12_381::Bls12_381>::new(
                &s, shares_num, rng,
            );

            move || {
                black_box(phi.0.evaluate_over_domain_by_ref(domain));
            }
        };

        let eval_mixed_eval_domain = {
            let domain =
                ark_poly::GeneralEvaluationDomain::new(shares_num).unwrap();
            let phi = SecretPolynomial::<ark_bls12_381::Bls12_381>::new(
                &s, shares_num, rng,
            );

            move || {
                black_box(phi.0.evaluate_over_domain_by_ref(domain));
            }
        };

        group.bench_function(
            BenchmarkId::new("eval_radix2_eval_domain", shares_num),
            |b| b.iter(|| eval_radix2_eval_domain()),
        );
        group.bench_function(
            BenchmarkId::new("eval_mixed_eval_domain", shares_num),
            |b| b.iter(|| eval_mixed_eval_domain()),
        );
    }
}

criterion_group!(eval_domain, bench_eval_domain);
