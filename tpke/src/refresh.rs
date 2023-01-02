use crate::{lagrange_basis_at, PrivateDecryptionContextSimple};
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use ark_std::UniformRand;
use itertools::zip_eq;
use rand::prelude::StdRng;
use rand_core::RngCore;
use std::collections::HashMap;
use std::usize;

pub fn recover_share_at_point<E: PairingEngine>(
    other_participants: &[PrivateDecryptionContextSimple<E>],
    threshold: usize,
    x_r: &E::Fr,
    rng: &mut StdRng,
) -> E::G2Projective {
    let share_updates =
        prepare_share_updates::<E>(other_participants, x_r, threshold, rng);

    let new_shares_y =
        update_decryption_shares::<E>(other_participants, &share_updates);

    // Interpolate new shares to recover y_r
    let shares_x = &other_participants[0]
        .public_decryption_contexts
        .iter()
        .map(|ctxt| ctxt.domain)
        .collect::<Vec<_>>();

    // Recover y_r
    let lagrange = lagrange_basis_at::<E>(shares_x, x_r);
    let prods =
        zip_eq(new_shares_y, lagrange).map(|(y_j, l)| y_j.mul(l.into_repr()));
    prods.fold(E::G2Projective::zero(), |acc, y_j| acc + y_j)
}

fn prepare_share_updates<E: PairingEngine>(
    participants: &[PrivateDecryptionContextSimple<E>],
    x_r: &E::Fr,
    threshold: usize,
    rng: &mut impl RngCore,
) -> HashMap<usize, HashMap<usize, E::G2Projective>> {
    // TODO: Refactor this function so that each participant performs it individually
    // Each participant prepares an update for each other participant
    participants
        .iter()
        .map(|p1| {
            let i = p1.index;
            // Generate a new random polynomial with constant term 0
            let d_i = make_random_polynomial::<E>(threshold, x_r, rng);

            // Now, we need to evaluate the polynomial at each of participants' indices
            let deltas_i: HashMap<_, _> = participants
                .iter()
                .map(|p2| {
                    let j = p2.index;
                    let x_j = p2.public_decryption_contexts[j].domain;
                    // Compute the evaluation of the polynomial at the domain element x_j
                    // d_i(x_j)
                    let eval = evaluate_polynomial::<E>(&d_i, &x_j);
                    let h_g2 = E::G2Projective::from(p2.h);
                    let eval_g2 = h_g2.mul(eval.into_repr());
                    (j, eval_g2)
                })
                .collect();
            (i, deltas_i)
        })
        .collect::<HashMap<_, _>>()
}

fn update_decryption_shares<E: PairingEngine>(
    participants: &[PrivateDecryptionContextSimple<E>],
    deltas: &HashMap<usize, HashMap<usize, E::G2Projective>>,
) -> Vec<E::G2Projective> {
    // TODO: Refactor this function so that each participant performs it individually
    participants
        .iter()
        .map(|p| {
            let i = p.index;
            let mut new_y = E::G2Projective::from(
                p.private_key_share.private_key_shares[0], // y_i
            );
            for j in deltas.keys() {
                new_y += deltas[j][&i];
            }
            new_y
        })
        .collect()
}

fn make_random_polynomial<E: PairingEngine>(
    threshold: usize,
    x_r: &E::Fr,
    rng: &mut impl RngCore,
) -> Vec<E::Fr> {
    // [][threshold-1]
    let mut d_i = (0..threshold - 1)
        .map(|_| E::Fr::rand(rng))
        .collect::<Vec<_>>();
    // [0..][threshold]
    d_i.insert(0, E::Fr::zero());

    // Now, we calculate d_i_0
    // This is the term that will "zero out" the polynomial at x_r, d_i(x_r) = 0
    let d_i_0 = E::Fr::zero() - evaluate_polynomial::<E>(&d_i, x_r);
    d_i[0] = d_i_0;
    assert_eq!(evaluate_polynomial::<E>(&d_i, x_r), E::Fr::zero());

    assert_eq!(d_i.len(), threshold);

    d_i
}

fn evaluate_polynomial<E: PairingEngine>(
    polynomial: &[E::Fr],
    x: &E::Fr,
) -> E::Fr {
    let mut result = E::Fr::zero();
    let mut x_power = E::Fr::one();
    for coeff in polynomial {
        result += *coeff * x_power;
        x_power *= x;
    }
    result
}
