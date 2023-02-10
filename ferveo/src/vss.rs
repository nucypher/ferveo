pub mod pvss;

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use ark_ec::{msm::FixedBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain,
};
use ark_std::{end_timer, start_timer};
use ferveo_common::Rng;
use itertools::{izip, zip_eq};
use measure_time::print_time;
pub use pvss::*;
use serde::{Deserialize, Serialize};

/// The possible States of a VSS instance
#[derive(Clone, Debug)]
pub enum VssState<Affine: AffineCurve> {
    /// The VSS is currently in a Sharing state with weight_ready
    /// of participants signaling Ready for this VSS
    Sharing { weight_ready: u32 },
    /// The VSS has completed Successfully with final secret commitment g^{\phi(0)}
    Success { final_secret: Affine },
    /// The VSS has ended in Failure
    Failure,
}
