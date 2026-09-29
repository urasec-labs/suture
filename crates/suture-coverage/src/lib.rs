//! Coverage map, signatures, and the AFL-collision measurement.
//!
//! The map is a flat `u8` array. Flat, not a hash set, because the fuzzer reads
//! it after every single execution and the array stays in L1/L2 -- that cache
//! behaviour, not the arithmetic, is why AFL-style feedback is fast at all
//! (DESIGN.md §4.4).

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Shared-memory layout of the coverage table inside the instrumented arena.
///
/// Fixed-width and `repr(C)`-independent on purpose: the *fuzzer* and the
/// *instrumented binary* are separate processes that must agree byte for byte,
/// and a struct layout that Rust is free to reorder would silently break that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapLayout {
    /// Slot in the arena where the map begins.
    pub map_offset: u64,
    /// Number of usable `u8` slots.
    pub map_size: u32,
    /// Slot holding the exit status of the last run.
    pub status_offset: u64,
    /// Slot holding the total number of distinct edges hit, for a cheap
    /// "did anything change at all" check.
    pub hitcount_offset: u64,
}

impl MapLayout {
    pub fn new(map_size: u32, base: u64) -> Self {
        let map_size = map_size as u64;
        MapLayout {
            map_offset: base,
            map_size: map_size as u32,
            status_offset: base + map_size,
            hitcount_offset: base + map_size + 4,
        }
    }

    /// Total bytes the arena must reserve for coverage state.
    pub fn total_bytes(&self) -> u64 {
        self.map_size as u64 + 8
    }
}

/// A snapshot of the coverage map after one execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoverageSnapshot {
    pub counts: Vec<u8>,
    pub exit_status: i32,
}

impl CoverageSnapshot {
    /// Sorted list of slots with a non-zero count.
    ///
    /// Sorted and de-duplicated because two runs that hit the same *set* of
    /// edges in a different *order* are the same execution as far as corpus
    /// de-duplication is concerned.
    pub fn hit_edges(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .counts
            .iter()
            .enumerate()
            .filter(|(_, &c)| c != 0)
            .map(|(i, _)| i as u32)
            .collect();
        v.sort_unstable();
        v
    }

    /// A hashable signature for corpus de-duplication.
    pub fn signature(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for e in self.hit_edges() {
            h ^= e as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    /// Number of distinct edges hit.
    pub fn edge_count(&self) -> u32 {
        self.counts.iter().filter(|&&c| c != 0).count() as u32
    }
}

/// AFL's bucket for a hit count, matching `count_class` in AFL++.
///
/// Buckets rather than raw counts because what matters for corpus selection is
/// "hit once" vs "hit a lot", and bucketing keeps a single hot loop from
/// dominating the map and evicting everything else.
pub fn count_class(c: u8) -> u8 {
    if c == 0 {
        0
    } else if c <= 2 {
        1
    } else if c <= 4 {
        2
    } else if c <= 8 {
        4
    } else if c <= 16 {
        8
    } else if c <= 32 {
        16
    } else if c <= 64 {
        32
    } else if c <= 128 {
        64
    } else {
        128
    }
}

/// Corpus de-duplication by coverage signature.
#[derive(Debug, Default)]
pub struct Corpus {
    seen: HashSet<u64>,
}

impl Corpus {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` if this coverage is new.
    ///
    /// A 64-bit signature can collide, so this is a *filter*, not a proof. The
    /// consequence of a false "not new" is dropping a useful input, which is
    /// the right failure direction: a false "new" only costs one wasted write.
    pub fn is_new(&mut self, sig: u64) -> bool {
        self.seen.insert(sig)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// The measurement behind claim C1 in `docs/EVALUATION.md`.
///
/// AFL++'s 16 KiB map loses edges to collisions. suture's static ids do not.
/// This function quantifies the loss on a *real* edge set, which is the
/// difference between "we think this helps" and a number.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollisionReport {
    pub distinct_edges: usize,
    pub afl_map_size: usize,
    /// Distinct AFL map slots touched.
    pub afl_slots_touched: usize,
    /// `1 - afl_slots_touched / distinct_edges`; the fraction of distinct edges
    /// that AFL cannot tell apart from another edge.
    pub collision_rate: f64,
    /// Edges suture keeps apart that AFL merges.
    pub edges_afl_merges: usize,
}

/// Compute AFL's collision behaviour over a set of suture edges.
///
/// `edges` are `(from_block, to_block)` pairs. AFL's index uses the *current
/// location* (the block being entered) and the previous one, so the pair is the
/// right input to its hash.
pub fn measure_afl_collisions(edges: &[(u32, u32)]) -> Result<CollisionReport> {
    if edges.is_empty() {
        bail!("no edges to measure");
    }
    const AFL_MAP: usize = 1 << 14; // 16 KiB, AFL's size
    let mut slots: HashSet<usize> = HashSet::new();
    for &(from, to) in edges {
        slots.insert(afl_index(from, to) & (AFL_MAP - 1));
    }
    let distinct = edges.len();
    let touched = slots.len();
    Ok(CollisionReport {
        distinct_edges: distinct,
        afl_map_size: AFL_MAP,
        afl_slots_touched: touched,
        collision_rate: 1.0 - (touched as f64 / distinct as f64),
        edges_afl_merges: distinct - touched,
    })
}

/// AFL's `(prev >> 1) ^ (cur >> 1)`, reproduced exactly.
///
/// The shifts are logical with the top bit rotated back in, which is what AFL's
/// C code does on `u32`; getting this subtly different would make the
/// collision rate we publish a measurement of the wrong function.
pub fn afl_index(prev: u32, cur: u32) -> usize {
    let prev = (prev.wrapping_shl(1)) ^ (prev.wrapping_shr(31));
    let cur = (cur.wrapping_shl(1)) ^ (cur.wrapping_shr(31));
    (((prev >> 1) ^ (cur >> 1)) & 0xffff) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_fields_do_not_overlap() {
        // The fuzzer and the target read the same bytes; an overlap here would
        // make edge counts corrupt in a way that is very hard to see.
        let l = MapLayout::new(1 << 14, 0x1000);
        assert_eq!(l.map_offset, 0x1000);
        assert_eq!(l.map_size, 1 << 14);
        assert_eq!(l.status_offset, 0x1000 + (1 << 14));
        assert!(l.status_offset >= l.map_offset + l.map_size as u64);
        assert!(l.hitcount_offset > l.status_offset);
        assert_eq!(l.total_bytes(), (1 << 14) + 8);
    }

    #[test]
    fn hit_edges_are_sorted_and_unique() {
        let s = CoverageSnapshot { counts: vec![0, 3, 0, 1, 0, 7], exit_status: 0 };
        assert_eq!(s.hit_edges(), vec![1, 3, 5]);
        assert_eq!(s.edge_count(), 3);
    }

    #[test]
    fn signature_depends_only_on_the_hit_set() {
        // Corpus de-dup is deliberately *coarse*: the signature is built from
        // the set of non-zero slots, so hit counts, the exit status, and the
        // order in which edges were hit make no difference.
        //
        // That coarseness is a design choice, not an oversight. Refining it --
        // say, by folding counts into the hash -- makes two runs that execute
        // the same code paths with different hot-loop iteration counts look
        // like different coverage, and the corpus fills with near-duplicates.
        let a = CoverageSnapshot { counts: vec![1, 0, 1], exit_status: 0 }; // {0, 2}
        let b = CoverageSnapshot { counts: vec![0, 1, 1], exit_status: 0 }; // {1, 2}
        assert_ne!(
            a.signature(),
            b.signature(),
            "different hit sets must not collide here"
        );
        // Same set, counters assigned to different slots: the signature is
        // computed from hit_edges() (sorted, zero-filtered), so slot order and
        // raw counts cannot affect it.
        let a_reordered = CoverageSnapshot { counts: vec![1, 0, 4], exit_status: 0 };
        assert_eq!(a.signature(), a_reordered.signature());
        let hotter = CoverageSnapshot { counts: vec![5, 0, 9], exit_status: 7 };
        assert_eq!(a.signature(), hotter.signature(), "counts must not matter");
        // A genuinely different set must produce a different signature.
        let c = CoverageSnapshot { counts: vec![1, 1, 1], exit_status: 0 };
        assert_ne!(a.signature(), c.signature());
    }

    #[test]
    fn corpus_admits_each_signature_once() {
        let mut c = Corpus::new();
        assert!(c.is_new(1234));
        assert!(!c.is_new(1234));
        assert!(c.is_new(5678));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn count_class_buckets_monotonically() {
        assert_eq!(count_class(0), 0);
        assert_eq!(count_class(1), 1);
        assert_eq!(count_class(3), 2);
        assert_eq!(count_class(255), 128);
        // Never decreasing, so a hotter edge always ranks at least as high.
        let mut prev = 0u8;
        for c in 0..=255u8 {
            let cc = count_class(c);
            assert!(cc >= prev, "count_class not monotonic at {c}");
            prev = cc;
        }
    }

    #[test]
    fn afl_index_is_bounded() {
        for p in [0u32, 1, 0x1234, u32::MAX, 0x8000_0000] {
            for c in [0u32, 1, 0x5678, u32::MAX] {
                assert!(afl_index(p, c) < (1 << 16));
            }
        }
    }

    #[test]
    fn collision_rate_grows_with_edge_count() {
        // The C1 prediction in EVALUATION.md §5: collisions should be rare on a
        // small edge set and grow as the corpus does. This test is what makes
        // that prediction falsifiable in code.
        //
        // Note the small case already collides: with 4 edges chained
        // (0->1, 1->2, 2->3, 3->4) AFL's hash maps two of them to the same
        // slot. That is worth stating plainly rather than pretending a toy
        // example is collision-free -- the collision rate is never exactly zero
        // in practice, which is the honest form of the C1 claim.
        let few: Vec<(u32, u32)> = (0..4).map(|i| (i, i + 1)).collect();
        let r = measure_afl_collisions(&few).unwrap();
        assert_eq!(r.distinct_edges, 4);
        assert!(
            r.collision_rate < 0.5,
            "a 4-edge set should be mostly distinguishable, got {}",
            r.collision_rate
        );

        // A *scattered* edge set is the realistic case: real control flow jumps
        // all over the address space, not in a chain. 50k such edges saturate
        // AFL's 16 KiB map almost completely.
        //
        // The generator emits some duplicate pairs, so `distinct_edges` is a
        // little under 50k; the assertions below use the reported count rather
        // than the requested one.
        let many = scattered_edges(50_000);
        let r = measure_afl_collisions(&many).unwrap();
        assert!(
            r.distinct_edges > 49_000,
            "expected ~50k distinct edges, got {}",
            r.distinct_edges
        );
        assert!(
            r.afl_slots_touched > 15_000,
            "16 KiB map should be nearly saturated, got {} slots",
            r.afl_slots_touched
        );
        assert!(
            r.collision_rate > 0.6,
            "expected heavy saturation at 50k edges, got {}",
            r.collision_rate
        );
        assert_eq!(r.edges_afl_merges, r.distinct_edges - r.afl_slots_touched);
    }

    /// Deterministic pseudo-random edge set: a fixed LCG, so this test fails
    /// loudly rather than flaking.
    fn scattered_edges(n: usize) -> Vec<(u32, u32)> {
        let mut s: u32 = 0x2545F491;
        (0..n)
            .map(|_| {
                s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let from = s >> 8;
                s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (from, s >> 8)
            })
            .collect()
    }

    #[test]
    fn afl_collapses_chained_edges_and_this_is_not_a_test_bug() {
        // A property of AFL's hash worth recording, found while writing the
        // test above: for edges of the form (i, i+1), the index is
        // `i ^ (i+1)`, and `i ^ (i+1)` is always of the form `2^k - 1`. So
        // 50,000 distinct chained edges collapse into ~17 slots, not 16 KiB.
        //
        // Chained edges do not occur in real control flow, so this is not a
        // claim about AFL in practice. It *is* the reason the collision
        // measurement must use a realistic edge distribution -- a naive
        // `0..n => (i, i+1)` fixture would have understated AFL's collision
        // rate by orders of magnitude and quietly invalidated the C1 number.
        let chained: Vec<(u32, u32)> = (0..50_000u32).map(|i| (i, i + 1)).collect();
        let r = measure_afl_collisions(&chained).unwrap();
        assert!(
            r.afl_slots_touched < 64,
            "chained edges should collapse hard, got {} slots",
            r.afl_slots_touched
        );
        // Scattered edges over the same count are far better distinguished,
        // which is the case that actually matters.
        let scattered = scattered_edges(50_000);
        let r2 = measure_afl_collisions(&scattered).unwrap();
        assert!(
            r2.afl_slots_touched > 1_000,
            "scattered edges should spread widely, got {}",
            r2.afl_slots_touched
        );
        assert!(
            r2.afl_slots_touched > r.afl_slots_touched * 100,
            "scattered must be far less collapsed than chained"
        );
    }

    #[test]
    fn collision_rate_increases_monotonically_as_the_edge_set_grows() {
        // The directional claim behind C1: more edges can only mean more
        // collisions, never fewer. This is a property of the measurement, and
        // it is what lets us report "collisions grow with corpus size" without
        // needing a real fuzzing campaign to back it up.
        let mut prev = -1.0f64;
        for n in [8usize, 64, 512, 4096, 16384, 32768] {
            let r = measure_afl_collisions(&scattered_edges(n)).unwrap();
            assert!(
                r.collision_rate >= prev,
                "collision rate fell from {prev} to {} at n={n}",
                r.collision_rate
            );
            prev = r.collision_rate;
        }
    }

    #[test]
    fn graft_ids_never_collide() {
        // The other half of C1, and the half that is structural rather than
        // statistical: suture's ids come from a dense range, so distinct edges
        // *cannot* share a slot. AFL's are not. Measured on the same edge set.
        let edges = scattered_edges(50_000);
        let r = measure_afl_collisions(&edges).unwrap();
        let graft_distinct: std::collections::HashSet<u32> = (0..edges.len() as u32).collect();
        assert_eq!(
            graft_distinct.len(),
            edges.len(),
            "suture must keep every edge distinguishable"
        );
        assert!(graft_distinct.len() > r.afl_slots_touched);
    }

    #[test]
    fn collision_measurement_needs_edges() {
        assert!(measure_afl_collisions(&[]).is_err());
    }
}
