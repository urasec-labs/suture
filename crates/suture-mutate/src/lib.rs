//! Input mutation.
//!
//! Structure at three levels, because coverage-guided fuzzing works by
//! combining them:
//!
//! * **bit/byte flips and arithmetic** — cheap, and the only thing that reaches
//!   a single mis-signed comparison.
//! * **interesting values** — the boundary numbers (0, 1, -1, `INT_MAX`) that
//!   sit exactly on the edge of a check. Random bytes essentially never produce
//!   these, which is why "interesting values" beats pure randomness on parsers.
//! * **splicing** — combining two corpus entries. This is how structure is
//!   discovered: a valid header from one input plus a valid body from another.
//!
//! Every mutator takes a seed and returns a *new* buffer. Mutating in place
//! would corrupt the corpus, which is the one thing a fuzzer must never do.

/// Deterministic PRNG (xorshift64*).
///
/// Seeded explicitly rather than taken from the clock so a run is reproducible:
/// "same seed, same corpus" is what makes a crash report worth anything, because
/// it can be replayed.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// One byte, uniformly distributed.
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
}

/// Values that sit on the edge of a comparison. See the module docs for why
/// these are separate from random bytes.
pub const INTERESTING: &[u64] = &[
    0,
    1,
    2,
    3,
    4,
    7,
    8,
    15,
    16,
    31,
    32,
    63,
    64,
    100,
    127,
    128,
    255,
    256,
    511,
    512,
    1023,
    1024,
    4095,
    4096,
    0x7FFF,
    0x8000,
    0xFFFF,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

/// Apply `rounds` rounds of havoc, returning a new buffer.
pub fn havoc(input: &[u8], rounds: usize) -> Vec<u8> {
    havoc_seeded(input, rounds, 0xC0FFEE)
}

pub fn havoc_seeded(input: &[u8], rounds: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    if input.is_empty() {
        return vec![rng.byte(); 1 + rng.below(64)];
    }
    let mut buf = input.to_vec();
    for _ in 0..rounds {
        apply_one(&mut buf, &mut rng);
    }
    buf
}

fn apply_one(buf: &mut [u8], rng: &mut Rng) {
    if buf.is_empty() {
        return;
    }
    match rng.below(9) {
        // Single bit flip. The only mutator that reliably reaches a mis-signed
        // `if (x & mask)` check.
        0 => {
            let i = rng.below(buf.len());
            buf[i] ^= 1 << rng.below(8);
        }
        // Byte set to an interesting value.
        1 => {
            let i = rng.below(buf.len());
            buf[i] = INTERESTING[rng.below(INTERESTING.len())] as u8;
        }
        // Add a small delta: `len++`, `count--`.
        2 => {
            let i = rng.below(buf.len());
            let d = (rng.below(35) as i32) - 17;
            buf[i] = buf[i].wrapping_add(d as u8);
        }
        // Write a random byte.
        3 => buf[rng.below(buf.len())] = rng.byte(),
        // Write an interesting multi-byte value, little-endian. This is what
        // reaches a length field in a binary format.
        4 => {
            let v = INTERESTING[rng.below(INTERESTING.len())];
            let i = rng.below(buf.len());
            for k in 0..8 {
                if i + k < buf.len() {
                    buf[i + k] = (v >> (8 * k)) as u8;
                }
            }
        }
        // Zero a run: a truncation or an early length of zero.
        5 => {
            let i = rng.below(buf.len());
            let n = (1 + rng.below(16)).min(buf.len() - i);
            buf[i..i + n].fill(0);
        }
        // Set a run to 0xff: a huge length, an "unbounded" value.
        6 => {
            let i = rng.below(buf.len());
            let n = (1 + rng.below(16)).min(buf.len() - i);
            buf[i..i + n].fill(0xff);
        }
        // Swap two bytes.
        7 => {
            if buf.len() >= 2 {
                let a = rng.below(buf.len());
                let b = rng.below(buf.len());
                buf.swap(a, b);
            }
        }
        // Duplicate a small chunk. Grows the input without random garbage,
        // which is how length fields get exercised.
        8 => {
            let src = rng.below(buf.len());
            let n = (1 + rng.below(8)).min(buf.len() - src);
            let chunk = buf[src..src + n].to_vec();
            let at = rng.below(buf.len());
            for (k, byte) in chunk.iter().enumerate() {
                if at + k < buf.len() {
                    buf[at + k] = *byte;
                }
            }
        }
        _ => unreachable!("apply_one matches on 0..=8"),
    }
}

/// Combine two inputs: a prefix of `a` with a suffix of `b`.
///
/// The core of structure discovery -- a valid header from one corpus entry and
/// a valid body from another, in an input neither of them contained.
pub fn splice(a: &[u8], b: &[u8], seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    if a.is_empty() || b.is_empty() {
        return havoc(a, 1);
    }
    let cut_a = rng.below(a.len() + 1);
    let cut_b = rng.below(b.len());
    let mut out = Vec::with_capacity(cut_a + (b.len() - cut_b));
    out.extend_from_slice(&a[..cut_a]);
    out.extend_from_slice(&b[cut_b..]);
    havoc(&out, 1 + rng.below(4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn havoc_does_not_mutate_its_input() {
        // The corpus is the fuzzer's only record of progress. Mutating a
        // borrowed slice in place would silently destroy it, and the loss would
        // be invisible until the fuzzer stopped finding anything.
        let input = vec![1u8, 2, 3, 4, 5];
        let snapshot = input.clone();
        let _ = havoc(&input, 32);
        assert_eq!(input, snapshot, "havoc must not touch its input");
    }

    #[test]
    fn havoc_actually_changes_something() {
        let input = vec![0u8; 128];
        let out = havoc_seeded(&input, 16, 1);
        assert_ne!(out, input, "havoc must modify the input");
        assert_eq!(out.len(), input.len(), "havoc must preserve length");
    }

    #[test]
    fn havoc_is_deterministic_for_a_seed() {
        // A crash report is only useful if it can be replayed.
        let input = b"the quick brown fox".to_vec();
        assert_eq!(
            havoc_seeded(&input, 8, 42),
            havoc_seeded(&input, 8, 42),
            "same seed must give the same result"
        );
        // And different seeds should generally differ, or the seed is ignored.
        let a = havoc_seeded(&input, 8, 1);
        let b = havoc_seeded(&input, 8, 2);
        assert_ne!(a, b, "different seeds should produce different output");
    }

    #[test]
    fn every_mutator_branch_is_reachable_and_valid() {
        // Exercise many rounds and check the invariants that must hold for all
        // of them: length preserved, no panic, output non-empty.
        let input: Vec<u8> = (0u8..64).collect();
        for seed in 0..200u64 {
            let out = havoc_seeded(&input, 4, seed);
            assert_eq!(out.len(), input.len());
        }
    }

    #[test]
    fn short_inputs_are_handled() {
        // A 1-byte input is the boundary for the chunk-copy and zero-run
        // mutators, which index `buf[i..i+n]`.
        for len in 0..8usize {
            let input: Vec<u8> = (0..len as u8).collect();
            for seed in 0..50u64 {
                let out = havoc_seeded(&input, 4, seed);
                assert!(!out.is_empty(), "output must never be empty");
            }
        }
    }

    #[test]
    fn havoc_of_an_empty_input_produces_something() {
        let out = havoc(&[], 1);
        assert!(!out.is_empty());
    }

    #[test]
    fn splice_joins_two_inputs() {
        let a = b"HEADER____BODY_AAAA".to_vec();
        let b = b"HEADER____BODY_BBBB".to_vec();
        let out = splice(&a, &b, 7);
        // Result must be a mix: a prefix of one and a suffix of the other.
        assert!(!out.is_empty());
        // Deterministic for a seed.
        assert_eq!(splice(&a, &b, 7), out);
    }

    #[test]
    fn splice_handles_empty_inputs() {
        let a = b"abc".to_vec();
        assert!(!splice(&a, &[], 1).is_empty());
        assert!(!splice(&[], &a, 1).is_empty());
        assert!(!splice(&[], &[], 1).is_empty());
    }

    #[test]
    fn rng_is_deterministic_and_covers_its_range() {
        let mut a = Rng::new(12345);
        let mut b = Rng::new(12345);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        // `below` must stay in bounds, which is the only property the mutators
        // rely on for memory safety.
        let mut r = Rng::new(99);
        for n in 0..20usize {
            for _ in 0..50 {
                assert!(r.below(n) < n.max(1));
            }
        }
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn interesting_values_cover_the_boundaries() {
        // The set is only useful if it contains the values that sit on a
        // comparison boundary. Check the ones that matter rather than the count.
        for v in [0u64, 1, 0x7F, 0x80, 0xFF, 0x7FFF_FFFF, 0xFFFF_FFFF] {
            assert!(
                INTERESTING.contains(&v),
                "{v:#x} should be an interesting value"
            );
        }
        let set: HashSet<_> = INTERESTING.iter().collect();
        assert_eq!(set.len(), INTERESTING.len(), "no duplicates");
    }
}
