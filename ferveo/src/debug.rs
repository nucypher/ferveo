use core::str::FromStr;
use std::{
    fs::File,
    io::{self, BufRead},
    path::PathBuf,
};

use hex::FromHex;
use crate::api::{PublicKey, Transcript, AggregatedTranscript};
use ferveo_common::FromBytes;
use crate::EthereumAddress;
use crate::pvss::aggregate;

#[derive(Debug)]
struct ValidatorTranscript{
    validator_address: EthereumAddress,
    validator_pk: PublicKey,
    transcript: Transcript
}

fn parse_file(file_path: &PathBuf) -> io::Result<Vec<ValidatorTranscript>> {
    let mut records = Vec::new();

    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            eprintln!("Invalid line: {line}");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid line",
            ));
        }

        let validator_address = parts[0].to_string();
        let validator_pk = Vec::from_hex(parts[1])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let transcript = Vec::from_hex(parts[2])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if validator_address.len() != 42 {
            eprintln!(
                "Invalid validator_address length: {}",
                validator_address.len()
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid validator_address length",
            ));
        }
        if validator_pk.len() != 96 {
            eprintln!("Invalid validator_pk length: {}", validator_pk.len());
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid validator_pk length",
            ));
        }
        if transcript.len() != 3784 {
            eprintln!("Invalid transcript length: {}", transcript.len());
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid transcript length",
            ));
        }

        let validator_address = EthereumAddress::from_str(&validator_address).unwrap();
        let validator_pk = PublicKey::from_bytes(&validator_pk).unwrap();
        let transcript = Transcript::from_bytes(&transcript).unwrap();

        records.push(ValidatorTranscript {
            validator_address,
            validator_pk,
            transcript,
        });
    }

    Ok(records)
}

#[cfg(test)]
mod test {
    use crate::{api::AggregatedTranscript, Validator};

    use super::*;

    #[test]
    fn test_parse_file() {
        let filename = "gistfile1.csv";
        let file_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(filename);
        let records = parse_file(&file_path).unwrap();
        assert_eq!(records.len(), 30);

        let mut transcripts = Vec::new();
        let mut vmessages = Vec::new();

        // verify_optimistic
        for (i, record) in records.iter().enumerate(){
            assert!(record.transcript.verify_optimistic());

            transcripts.push(record.transcript.clone());

            let validator = Validator::new(record.validator_address.to_string(), record.validator_pk, i as u32).unwrap();
            vmessages.push((validator.clone(), record.transcript.clone()));
        }

        // Aggregate
        let agg = aggregate(&transcripts).unwrap();
        assert!(agg.verify_optimistic());

        let at = AggregatedTranscript::new(&vmessages).unwrap();
        assert!(at.verify(30, &vmessages).unwrap());
    }
}
