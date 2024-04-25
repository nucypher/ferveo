use std::{collections::HashMap, ops::Mul, usize};

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ferveo_common::Keypair;
use ferveo_tdec::{
    lagrange_basis_at, prepare_combine_simple, CiphertextHeader,
    DecryptionSharePrecomputed, DecryptionShareSimple,
};
use itertools::{zip_eq, Itertools};
use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{DomainPoint, Error, PubliclyVerifiableParams, Result};

// TODO: Rename refresh.rs to key_share.rs?

type InnerPrivateKeyShare<E> = ferveo_tdec::PrivateKeyShare<E>;

/// Private key share held by a participant in the DKG protocol.
#[derive(
    Debug, Clone, PartialEq, Eq, ZeroizeOnDrop, Serialize, Deserialize,
)]
pub struct PrivateKeyShare<E: Pairing>(
    #[serde(bound(
        serialize = "ferveo_tdec::PrivateKeyShare<E>: Serialize",
        deserialize = "ferveo_tdec::PrivateKeyShare<E>: DeserializeOwned"
    ))]
    pub InnerPrivateKeyShare<E>,
);

impl<E: Pairing> PrivateKeyShare<E> {
    pub fn new(private_key_share: InnerPrivateKeyShare<E>) -> Self {
        Self(private_key_share)
    }
}

impl<E: Pairing> PrivateKeyShare<E> {
    /// From PSS paper, section 4.2.3, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    pub fn create_updated_key_share(
        &self,
        share_updates: &[impl PrivateKeyShareUpdate<E>],
    ) -> UpdatedPrivateKeyShare<E> {
        let updated_key_share = share_updates
            .iter()
            .fold(self.0 .0, |acc, delta| (acc + delta.inner().0).into());
        let updated_key_share = ferveo_tdec::PrivateKeyShare(updated_key_share);
        UpdatedPrivateKeyShare(updated_key_share)
    }

    /// From the PSS paper, section 4.2.4, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    /// `x_r` is the point at which the share is to be recovered
    pub fn recover_share_from_updated_private_shares(
        x_r: &DomainPoint<E>,
        domain_points: &HashMap<u32, DomainPoint<E>>,
        updated_shares: &HashMap<u32, UpdatedPrivateKeyShare<E>>,
    ) -> Result<PrivateKeyShare<E>> {
        // Pick the domain points and updated shares according to share index
        let mut domain_points_ = vec![];
        let mut updated_shares_ = vec![];
        for share_index in updated_shares.keys().sorted() {
            domain_points_.push(
                *domain_points
                    .get(share_index)
                    .ok_or(Error::InvalidShareIndex(*share_index))?,
            );
            updated_shares_.push(
                updated_shares
                    .get(share_index)
                    .ok_or(Error::InvalidShareIndex(*share_index))?
                    .0
                    .clone(),
            );
        }

        // Interpolate new shares to recover y_r
        let lagrange = lagrange_basis_at::<E>(&domain_points_, x_r);
        let prods =
            zip_eq(updated_shares_, lagrange).map(|(y_j, l)| y_j.0.mul(l));
        let y_r = prods.fold(E::G2::zero(), |acc, y_j| acc + y_j);
        Ok(PrivateKeyShare(ferveo_tdec::PrivateKeyShare(
            y_r.into_affine(),
        )))
    }

    pub fn create_decryption_share_simple(
        &self,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        validator_keypair: &Keypair<E>,
    ) -> Result<DecryptionShareSimple<E>> {
        let g_inv = PubliclyVerifiableParams::<E>::default().g_inv();
        DecryptionShareSimple::create(
            &validator_keypair.decryption_key,
            &self.0,
            ciphertext_header,
            aad,
            &g_inv,
        )
        .map_err(|e| e.into())
    }

    /// In precomputed variant, we offload some of the decryption related computation to the server-side:
    /// We use the `prepare_combine_simple` function to precompute the lagrange coefficients
    pub fn create_decryption_share_precomputed(
        &self,
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
        validator_keypair: &Keypair<E>,
        share_index: u32,
        domain_points_map: &HashMap<u32, DomainPoint<E>>,
    ) -> Result<DecryptionSharePrecomputed<E>> {
        // We need to turn the domain points into a vector, and sort it by share index
        let mut domain_points = domain_points_map
            .iter()
            .map(|(share_index, domain_point)| (*share_index, *domain_point))
            .collect::<Vec<_>>();
        domain_points.sort_by_key(|(share_index, _)| *share_index);

        // Now, we have to pass the domain points to the `prepare_combine_simple` function
        // and use the resulting lagrange coefficients to create the decryption share

        let only_domain_points = domain_points
            .iter()
            .map(|(_, domain_point)| *domain_point)
            .collect::<Vec<_>>();
        let lagrange_coeffs = prepare_combine_simple::<E>(&only_domain_points);

        // Before we pick the lagrange coefficient for the current share index, we need
        // to map the share index to the index in the domain points vector
        // Given that we sorted the domain points by share index, the first element in the vector
        // will correspond to the smallest share index, second to the second smallest, and so on

        let sorted_share_indices = domain_points
            .iter()
            .enumerate()
            .map(|(adjusted_share_index, (share_index, _))| {
                (*share_index, adjusted_share_index)
            })
            .collect::<HashMap<u32, usize>>();
        let adjusted_share_index = *sorted_share_indices
            .get(&share_index)
            .ok_or(Error::InvalidShareIndex(share_index))?;

        // Finally, pick the lagrange coefficient for the current share index
        let lagrange_coeff = &lagrange_coeffs[adjusted_share_index];
        let g_inv = PubliclyVerifiableParams::<E>::default().g_inv();
        DecryptionSharePrecomputed::create(
            share_index as usize,
            &validator_keypair.decryption_key,
            &self.0,
            ciphertext_header,
            aad,
            lagrange_coeff,
            &g_inv,
        )
        .map_err(|e| e.into())
    }
}

/// An updated private key share, resulting from an intermediate step in a share recovery or refresh operation.
#[derive(
    Debug, Clone, PartialEq, Eq, ZeroizeOnDrop, Serialize, Deserialize,
)]
pub struct UpdatedPrivateKeyShare<E: Pairing>(
    #[serde(bound(
        serialize = "ferveo_tdec::PrivateKeyShare<E>: Serialize",
        deserialize = "ferveo_tdec::PrivateKeyShare<E>: DeserializeOwned"
    ))]
    pub(crate) InnerPrivateKeyShare<E>,
);

impl<E: Pairing> UpdatedPrivateKeyShare<E> {
    /// One-way conversion from `UpdatedPrivateKeyShare` to `PrivateKeyShare`.
    /// Use this method to eject from the `UpdatedPrivateKeyShare` type and use the resulting `PrivateKeyShare` in further operations.
    pub fn inner(&self) -> PrivateKeyShare<E> {
        PrivateKeyShare(self.0.clone())
    }
}

impl<E: Pairing> UpdatedPrivateKeyShare<E> {
    pub fn new(private_key_share: InnerPrivateKeyShare<E>) -> Self {
        Self(private_key_share)
    }
}

/// Trait for types that can be used to update a private key share.
pub trait PrivateKeyShareUpdate<E: Pairing> {
    fn inner(&self) -> &InnerPrivateKeyShare<E>;
}

/// An update to a private key share generated by a participant in a share recovery operation.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ShareRecoveryUpdate<E: Pairing>(pub(crate) InnerPrivateKeyShare<E>);

impl<E: Pairing> PrivateKeyShareUpdate<E> for ShareRecoveryUpdate<E> {
    fn inner(&self) -> &InnerPrivateKeyShare<E> {
        &self.0
    }
}

impl<E: Pairing> ShareRecoveryUpdate<E> {
    /// From PSS paper, section 4.2.1, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    pub fn create_share_updates(
        domain_points: &HashMap<u32, DomainPoint<E>>,
        h: &E::G2Affine,
        x_r: &DomainPoint<E>,
        threshold: u32,
        rng: &mut impl RngCore,
    ) -> HashMap<u32, ShareRecoveryUpdate<E>> {
        // Update polynomial has root at x_r
        prepare_share_updates_with_root::<E>(
            domain_points,
            h,
            x_r,
            threshold,
            rng,
        )
        .into_iter()
        .map(|(share_index, share_update)| (share_index, Self(share_update)))
        .collect()
    }
}

/// An update to a private key share generated by a participant in a share refresh operation.
#[derive(
    Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ZeroizeOnDrop,
)]
pub struct ShareRefreshUpdate<E: Pairing>(
    #[serde(bound(
        serialize = "ferveo_tdec::PrivateKeyShare<E>: Serialize",
        deserialize = "ferveo_tdec::PrivateKeyShare<E>: DeserializeOwned"
    ))]
    pub(crate) ferveo_tdec::PrivateKeyShare<E>,
);

impl<E: Pairing> PrivateKeyShareUpdate<E> for ShareRefreshUpdate<E> {
    fn inner(&self) -> &InnerPrivateKeyShare<E> {
        &self.0
    }
}

impl<E: Pairing> ShareRefreshUpdate<E> {
    /// From PSS paper, section 4.2.1, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    pub fn create_share_updates(
        domain_points: &HashMap<u32, DomainPoint<E>>,
        h: &E::G2Affine,
        threshold: u32,
        rng: &mut impl RngCore,
    ) -> HashMap<u32, ShareRefreshUpdate<E>> {
        // Update polynomial has root at 0
        prepare_share_updates_with_root::<E>(
            domain_points,
            h,
            &DomainPoint::<E>::zero(),
            threshold,
            rng,
        )
        .into_iter()
        .map(|(share_index, share_update)| {
            (share_index, ShareRefreshUpdate(share_update))
        })
        .collect()
    }
}

/// Prepare share updates with a given root
/// This is a helper function for `ShareRecoveryUpdate::create_share_updates_for_recovery` and `ShareRefreshUpdate::create_share_updates_for_refresh`
/// It generates a new random polynomial with a defined root and evaluates it at each of the participants' indices.
/// The result is a list of share updates.
/// We represent the share updates as `InnerPrivateKeyShare` to avoid dependency on the concrete implementation of `PrivateKeyShareUpdate`.
fn prepare_share_updates_with_root<E: Pairing>(
    domain_points: &HashMap<u32, DomainPoint<E>>,
    h: &E::G2Affine,
    root: &DomainPoint<E>,
    threshold: u32,
    rng: &mut impl RngCore,
) -> HashMap<u32, InnerPrivateKeyShare<E>> {
    // Generate a new random polynomial with a defined root
    let d_i = make_random_polynomial_with_root::<E>(threshold - 1, root, rng);

    // Now, we need to evaluate the polynomial at each of participants' indices
    domain_points
        .iter()
        .map(|(share_index, x_i)| {
            let eval = d_i.evaluate(x_i);
            let share_update =
                ferveo_tdec::PrivateKeyShare(h.mul(eval).into_affine());
            (*share_index, share_update)
        })
        .collect::<HashMap<_, _>>()
}

/// Generate a random polynomial with a given root
fn make_random_polynomial_with_root<E: Pairing>(
    degree: u32,
    root: &DomainPoint<E>,
    rng: &mut impl RngCore,
) -> DensePolynomial<DomainPoint<E>> {
    // [c_0, c_1, ..., c_{degree}] (Random polynomial)
    let mut poly =
        DensePolynomial::<DomainPoint<E>>::rand(degree as usize, rng);

    // [0, c_1, ... , c_{degree}]  (We zeroize the free term)
    poly[0] = DomainPoint::<E>::zero();

    // Now, we calculate a new free term so that `poly(root) = 0`
    let new_c_0 = DomainPoint::<E>::zero() - poly.evaluate(root);
    poly[0] = new_c_0;

    // Evaluating the polynomial at the root should result in 0
    debug_assert!(poly.evaluate(root) == DomainPoint::<E>::zero());
    debug_assert!(poly.coeffs.len() == (degree + 1) as usize);

    poly
}

#[cfg(test)]
mod tests_refresh {
    use std::collections::HashMap;

    use ark_bls12_381::Fr;
    use ark_std::{test_rng, UniformRand, Zero};
    use ferveo_tdec::{
        test_common::setup_simple, PrivateDecryptionContextSimple,
    };
    use rand_core::RngCore;
    use test_case::{test_case, test_matrix};

    use crate::{
        test_common::*, PrivateKeyShare, ShareRecoveryUpdate,
        ShareRefreshUpdate, UpdatedPrivateKeyShare,
    };

    /// Using tdec test utilities here instead of PVSS to test the internals of the shared key recovery
    fn create_updated_private_key_shares<R: RngCore>(
        rng: &mut R,
        threshold: u32,
        x_r: &Fr,
        remaining_participants: &[PrivateDecryptionContextSimple<E>],
    ) -> HashMap<u32, UpdatedPrivateKeyShare<E>> {
        // Each participant prepares an update for each other participant
        let domain_points = remaining_participants
            .iter()
            .map(|c| {
                (c.index as u32, c.public_decryption_contexts[c.index].domain)
            })
            .collect::<HashMap<_, _>>();
        let h = remaining_participants[0].public_decryption_contexts[0].h;
        let share_updates = remaining_participants
            .iter()
            .map(|p| {
                let share_updates = ShareRecoveryUpdate::create_share_updates(
                    &domain_points,
                    &h,
                    x_r,
                    threshold,
                    rng,
                );
                (p.index as u32, share_updates)
            })
            .collect::<HashMap<u32, _>>();

        // Participants share updates and update their shares
        let updated_private_key_shares = remaining_participants
            .iter()
            .map(|p| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| {
                        updates.get(&(p.index as u32)).cloned().unwrap()
                    })
                    .collect();

                // And updates their share
                let updated_share =
                    PrivateKeyShare(p.private_key_share.clone())
                        .create_updated_key_share(&updates_for_participant);
                (p.index as u32, updated_share)
            })
            .collect::<HashMap<u32, _>>();

        updated_private_key_shares
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is intended to restore a previously existing share, e.g., due to loss or corruption.
    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    fn tdec_simple_variant_share_recovery_at_selected_point(
        shares_num: u32,
        _validators_num: u32,
    ) {
        let rng = &mut test_rng();
        let security_threshold = shares_num * 2 / 3;

        let (_, _, mut contexts) = setup_simple::<E>(
            shares_num as usize,
            security_threshold as usize,
            rng,
        );

        // Prepare participants

        // First, save the soon-to-be-removed participant
        let selected_participant = contexts.pop().unwrap();
        let x_r = selected_participant
            .public_decryption_contexts
            .last()
            .unwrap()
            .domain;
        let original_private_key_share =
            PrivateKeyShare(selected_participant.private_key_share);

        // Remove the selected participant from the contexts and all nested structures
        let mut remaining_participants = contexts;
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop().unwrap();
        }

        // Each participant prepares an update for each other participant, and uses it to create a new share fragment
        let updated_private_key_shares = create_updated_private_key_shares(
            rng,
            security_threshold,
            &x_r,
            &remaining_participants,
        );
        // We only need `security_threshold` updates to recover the original share
        let updated_private_key_shares = updated_private_key_shares
            .into_iter()
            .take(security_threshold as usize)
            .collect::<HashMap<_, _>>();

        // Now, we have to combine new share fragments into a new share
        let domain_points = remaining_participants
            .into_iter()
            .map(|ctxt| {
                (
                    ctxt.index as u32,
                    ctxt.public_decryption_contexts[ctxt.index].domain,
                )
            })
            .collect::<HashMap<u32, _>>();
        let new_private_key_share =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &x_r,
                &domain_points,
                &updated_private_key_shares,
            )
            .unwrap();
        assert_eq!(new_private_key_share, original_private_key_share);

        // If we don't have enough private share updates, the resulting private share will be incorrect
        let not_enough_shares = updated_private_key_shares
            .into_iter()
            .take(security_threshold as usize - 1)
            .collect::<HashMap<_, _>>();
        let incorrect_private_key_share =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &x_r,
                &domain_points,
                &not_enough_shares,
            )
            .unwrap();
        assert_ne!(incorrect_private_key_share, original_private_key_share);
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is independent of the previously existing shares. We can use this to on-board a new participant into an existing cohort.
    #[test_case(4; "number of shares (validators) is a power of 2")]
    #[test_case(7; "number of shares (validators) is not a power of 2")]
    fn tdec_simple_variant_share_recovery_at_random_point(shares_num: u32) {
        let rng = &mut test_rng();
        let security_threshold = shares_num * 2 / 3;

        let (_, shared_private_key, mut contexts) = setup_simple::<E>(
            shares_num as usize,
            security_threshold as usize,
            rng,
        );

        // Prepare participants

        // Remove one participant from the contexts and all nested structures
        let removed_participant = contexts.pop().unwrap();
        let mut remaining_participants = contexts.clone();
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop().unwrap();
        }

        // Now, we're going to recover a new share at a random point and check that the shared secret is still the same

        // Our random point
        let x_r = ScalarField::rand(rng);

        // Each remaining participant prepares an update for every other participant, and uses it to create a new share fragment
        let share_recovery_updates = create_updated_private_key_shares(
            rng,
            security_threshold,
            &x_r,
            &remaining_participants,
        );
        // We only need `threshold` updates to recover the original share
        let share_recovery_updates = share_recovery_updates
            .into_iter()
            .take(security_threshold as usize)
            .collect::<HashMap<_, _>>();
        let domain_points = &mut remaining_participants
            .into_iter()
            .map(|ctxt| {
                (
                    ctxt.index as u32,
                    ctxt.public_decryption_contexts[ctxt.index].domain,
                )
            })
            .collect::<HashMap<_, _>>();

        // Now, we have to combine new share fragments into a new share
        let recovered_private_key_share =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &x_r,
                domain_points,
                &share_recovery_updates,
            )
            .unwrap();

        // Finally, let's recreate the shared private key from some original shares and the recovered one
        let mut private_shares = contexts
            .into_iter()
            .map(|ctxt| (ctxt.index as u32, ctxt.private_key_share))
            .collect::<HashMap<u32, _>>();

        // Need to update these to account for recovered private key share
        domain_points.insert(removed_participant.index as u32, x_r);
        private_shares.insert(
            removed_participant.index as u32,
            recovered_private_key_share.0.clone(),
        );

        // This is a workaround for a type mismatch - We need to convert the private shares to updated private shares
        // This is just to test that we are able to recover the shared private key from the updated private shares
        let updated_private_key_shares = private_shares
            .into_iter()
            .map(|(share_index, share)| {
                (share_index, UpdatedPrivateKeyShare(share))
            })
            .collect::<HashMap<u32, _>>();
        let new_shared_private_key =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &ScalarField::zero(),
                domain_points,
                &updated_private_key_shares,
            )
            .unwrap();
        assert_eq!(shared_private_key, new_shared_private_key.0);
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share refresh" algorithm.
    /// The output is M new shares (with M <= Ñ), with each of the M new shares substituting the
    /// original share (i.e., the original share is deleted).
    #[test_matrix([4, 7, 11, 16])]
    fn tdec_simple_variant_share_refreshing(shares_num: usize) {
        let rng = &mut test_rng();
        let security_threshold = shares_num * 2 / 3;

        let (_, private_key_share, contexts) =
            setup_simple::<E>(shares_num, security_threshold, rng);
        let domain_points = &contexts
            .iter()
            .map(|ctxt| {
                (
                    ctxt.index as u32,
                    ctxt.public_decryption_contexts[ctxt.index].domain,
                )
            })
            .collect::<HashMap<u32, _>>();
        let h = contexts[0].public_decryption_contexts[0].h;

        // Each participant prepares an update for each other participant:
        let share_updates = contexts
            .iter()
            .map(|p| {
                let share_updates =
                    ShareRefreshUpdate::<E>::create_share_updates(
                        domain_points,
                        &h,
                        security_threshold as u32,
                        rng,
                    );
                (p.index as u32, share_updates)
            })
            .collect::<HashMap<u32, _>>();

        // Participants refresh their shares with the updates from each other:
        let refreshed_shares = contexts
            .iter()
            .map(|p| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| {
                        updates.get(&(p.index as u32)).cloned().unwrap()
                    })
                    .collect();

                // And creates a new, refreshed share
                let updated_share =
                    PrivateKeyShare(p.private_key_share.clone())
                        .create_updated_key_share(&updates_for_participant);
                (p.index as u32, updated_share)
            })
            // We only need `threshold` refreshed shares to recover the original share
            .take(security_threshold)
            .collect::<HashMap<u32, UpdatedPrivateKeyShare<E>>>();

        // Finally, let's recreate the shared private key from the refreshed shares
        let new_shared_private_key =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &ScalarField::zero(),
                domain_points,
                &refreshed_shares,
            )
            .unwrap();
        assert_eq!(private_key_share, new_shared_private_key.0);
    }
}
