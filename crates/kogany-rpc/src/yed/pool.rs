//! The node's attestation pool (ycash6 `AttestationPool`, `src/yellowback/index.{h,cpp}` at
//! `65cb4ae0f`): in memory, non-consensus, fed by `yed_addattestation`, the newest
//! [`POOL_PER_SEQ`] attestations per `seq` by `citedHeight`. Empty after a restart until the
//! subscriber refills it. Never a state input: the bundle builder reads it, no rule does.

use std::collections::BTreeMap;

use super::state::Attestation;

/// `AttestationPool::POOL_PER_SEQ`: `ceil(ATTEST_MAX_AGE / k) + 1 = 3` (at most two signed prices
/// fall in a bundle's window, so three keeps one spare).
pub const POOL_PER_SEQ: usize = 3;

/// One pooled attestation and the index tip at which it arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pooled {
    /// The attestation.
    pub attestation: Attestation,
    /// The index tip height when it was pooled (`receivedHeight`).
    pub received_height: i64,
}

/// The pool: per `seq`, ascending `citedHeight`.
#[derive(Clone, Debug, Default)]
pub struct AttestationPool {
    by_seq: BTreeMap<u16, Vec<Pooled>>,
}

impl AttestationPool {
    /// `Add`: pools one verified attestation. `None` for a byte-identical resubmission (nothing
    /// changes); otherwise `Some(replaced)`, `replaced` when an older attestation of the `seq` was
    /// dropped to make room or a different one for the same `citedHeight` was overwritten (the
    /// newest wins; the pool is not the equivocation detector).
    pub fn add(&mut self, att: Attestation, received_height: i64) -> Option<bool> {
        let v = self.by_seq.entry(att.seq).or_default();
        if let Some(slot) = v
            .iter_mut()
            .find(|p| p.attestation.cited_height == att.cited_height)
        {
            if slot.attestation == att {
                return None;
            }
            slot.attestation = att;
            slot.received_height = received_height;
            return Some(true);
        }
        let at = v
            .iter()
            .position(|p| p.attestation.cited_height >= att.cited_height)
            .unwrap_or(v.len());
        v.insert(
            at,
            Pooled {
                attestation: att,
                received_height,
            },
        );
        let mut replaced = false;
        while v.len() > POOL_PER_SEQ {
            v.remove(0);
            replaced = true;
        }
        Some(replaced)
    }

    /// `All`: every pooled attestation, ascending `seq` then `citedHeight`.
    pub fn all(&self) -> Vec<Pooled> {
        self.by_seq.values().flatten().copied().collect()
    }

    /// `Freshest`: the newest attestation of `seq` with `citedHeight` in
    /// `(ref_height - max_age, ref_height]` and at or above `start_height`.
    pub fn freshest(
        &self,
        seq: u16,
        ref_height: i64,
        max_age: i64,
        start_height: i64,
    ) -> Option<Attestation> {
        self.by_seq.get(&seq)?.iter().rev().find_map(|p| {
            let h = i64::from(p.attestation.cited_height);
            (h <= ref_height && h > ref_height.saturating_sub(max_age) && h >= start_height)
                .then_some(p.attestation)
        })
    }

    /// `Size`.
    pub fn size(&self) -> usize {
        self.by_seq.values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(seq: u16, cited: u32, price: u32) -> Attestation {
        Attestation {
            seq,
            price_micro_usd: price,
            cited_height: cited,
            sig: [7; 64],
        }
    }

    #[test]
    fn add_keeps_the_newest_three_per_seq_in_cited_order() {
        let mut pool = AttestationPool::default();
        assert_eq!(pool.add(att(1, 10, 100), 12), Some(false));
        assert_eq!(pool.add(att(1, 10, 100), 13), None, "byte-identical");
        assert_eq!(
            pool.add(att(1, 10, 101), 13),
            Some(true),
            "same height, newest wins"
        );
        assert_eq!(pool.add(att(1, 8, 100), 13), Some(false));
        assert_eq!(pool.add(att(1, 12, 100), 13), Some(false));
        assert_eq!(pool.size(), 3);
        assert_eq!(
            pool.add(att(1, 14, 100), 15),
            Some(true),
            "the oldest is dropped"
        );
        let cited: Vec<u32> = pool
            .all()
            .iter()
            .map(|p| p.attestation.cited_height)
            .collect();
        assert_eq!(cited, vec![10, 12, 14]);
        assert_eq!(pool.add(att(0, 14, 100), 15), Some(false));
        let seqs: Vec<u16> = pool.all().iter().map(|p| p.attestation.seq).collect();
        assert_eq!(seqs, vec![0, 1, 1, 1]);
    }

    #[test]
    fn freshest_is_the_newest_in_the_window() {
        let mut pool = AttestationPool::default();
        for h in [5, 7, 9] {
            pool.add(att(1, h, 100), 9);
        }
        // ycash6 yellowback_index_tests: (R - maxAge, R], at or above the start height
        assert_eq!(pool.freshest(1, 9, 3, 0).map(|a| a.cited_height), Some(9));
        assert_eq!(pool.freshest(1, 8, 3, 0).map(|a| a.cited_height), Some(7));
        assert_eq!(pool.freshest(1, 12, 3, 0), None);
        assert_eq!(pool.freshest(1, 6, 1, 0), None);
        assert_eq!(pool.freshest(1, 9, 10, 8).map(|a| a.cited_height), Some(9));
        assert_eq!(pool.freshest(1, 7, 10, 8), None);
        assert_eq!(pool.freshest(2, 9, 10, 0), None);
    }
}
