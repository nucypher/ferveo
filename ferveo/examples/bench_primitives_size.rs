use std::{
    collections::BTreeSet,
    fs::{create_dir_all, OpenOptions},
    io::prelude::*,
    path::PathBuf,
    str::FromStr,
};

use ark_bls12_381::Bls12_381 as EllipticCurve;
use ferveo_pre_release::*;
use itertools::iproduct;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

const OUTPUT_DIR_PATH: &str = "/tmp/benchmark_setup";
const OUTPUT_FILE_NAME: &str = "results.md";

pub fn create_or_truncate_output_file() -> std::io::Result<()> {
    let file_path = PathBuf::from(OUTPUT_DIR_PATH).join(OUTPUT_FILE_NAME);
    eprintln!("Creating output file at {}", file_path.display());

    let dir_path = PathBuf::from(OUTPUT_DIR_PATH);
    create_dir_all(dir_path).unwrap();

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;
    file.sync_all()?;

    writeln!(file, "|shares_num|threshold|pvss_transcript_size_bytes|",)?;
    writeln!(file, "|---|---|---|---|")
}

pub fn save_data(
    shares_num: usize,
    threshold: usize,
    transcript_size_bytes: usize,
) {
    let file_path = PathBuf::from(OUTPUT_DIR_PATH).join(OUTPUT_FILE_NAME);

    eprintln!("Appending to file: {}", file_path.display());
    let mut file = OpenOptions::new().append(true).open(&file_path).unwrap();
    writeln!(file, "{shares_num}|{threshold}|{transcript_size_bytes}|")
        .unwrap();
}

// TODO: Find a way to deduplicate the following methods with benchmarks and test setup

fn gen_keypairs(num: u32) -> Vec<ferveo_common::Keypair<EllipticCurve>> {
    let rng = &mut ark_std::test_rng();
    (0..num)
        .map(|_| ferveo_common::Keypair::<EllipticCurve>::new(rng))
        .collect()
}

pub fn gen_address(i: usize) -> EthereumAddress {
    EthereumAddress::from_str(&format!("0x{i:040}")).unwrap() // TODO: Randomize - #207
}

fn gen_validators(
    keypairs: &[ferveo_common::Keypair<EllipticCurve>],
) -> Vec<Validator<EllipticCurve>> {
    (0..keypairs.len())
        .map(|i| Validator {
            address: gen_address(i),
            public_key: keypairs[i].public_key(),
            share_index: i as u32,
        })
        .collect()
}

fn setup_dkg(
    validator: usize,
    shares_num: u32,
    security_threshold: u32,
) -> PubliclyVerifiableDkg<EllipticCurve> {
    let keypairs = gen_keypairs(shares_num);
    let validators = gen_validators(&keypairs);
    let me = validators[validator].clone();
    PubliclyVerifiableDkg::new(
        &validators,
        &DkgParams::new(0, security_threshold, shares_num).unwrap(),
        &me,
    )
    .expect("Setup failed")
}

fn setup(
    shares_num: u32,
    security_threshold: u32,
    rng: &mut StdRng,
) -> (
    PubliclyVerifiableDkg<EllipticCurve>,
    Vec<PubliclyVerifiableSS<EllipticCurve>>,
) {
    let mut transcripts = vec![];
    for i in 0..shares_num {
        let dkg = setup_dkg(i as usize, shares_num, security_threshold);
        let transcript = dkg.generate_transcript(rng).expect("Test failed");
        transcripts.push(transcript.clone());
    }
    let dkg = setup_dkg(0, shares_num, security_threshold);
    (dkg, transcripts)
}

fn main() {
    let rng = &mut StdRng::seed_from_u64(0);

    create_or_truncate_output_file().unwrap();

    let share_num_vec = [2, 4, 8, 16, 32, 64];
    let threshold_ratio_vec = [0.51, 0.66, 0.8, 1.0];

    // Create benchmark parameters without duplicates
    let configs = iproduct!(&share_num_vec, &threshold_ratio_vec)
        .map(|(shares_num, threshold_ratio)| {
            let threshold =
                (*shares_num as f64 * threshold_ratio).ceil() as u32;
            (shares_num, threshold)
        })
        .collect::<BTreeSet<_>>();

    println!("Running benchmarks for {configs:?}");

    for (shares_num, threshold) in configs {
        println!("shares_num: {shares_num}, threshold: {threshold}");
        let (_, transcripts) = setup(*shares_num as u32, threshold, rng);
        let transcript_bytes = bincode::serialize(&transcripts[0]).unwrap();

        save_data(
            *shares_num as usize,
            threshold as usize,
            transcript_bytes.len(),
        );
    }
}
