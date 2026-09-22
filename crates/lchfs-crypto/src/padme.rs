//! Padmé padding (Nikitin et al., "Reducing Metadata Leakage from
//! Encrypted Files and Communication with PURBs", PETS 2019).
//!
//! An encrypted record's length still says roughly how big its plaintext
//! was. Left exact, the sequence of chunk sizes a content-defined chunker
//! produces is a fingerprint of a known file, and a directory object's
//! size is close to a count of its entries. Padmé rounds a length up so
//! that only O(log log L) bits of it survive, for at most ~12% overhead
//! (and typically far less) -- a much better trade than padding to powers
//! of two, which costs up to 100%.

/// The padded length for a plaintext of `len` bytes.
pub fn padded_len(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    // E = floor(log2 L), S = floor(log2 E) + 1: keep the top S bits of
    // precision, zero out (round up) the E - S bits below them.
    let e = 63 - u64::from(len.leading_zeros());
    let s = 64 - u64::from(e.leading_zeros());
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    (len + mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_shrinks_and_overhead_is_bounded() {
        for len in 0..200_000u64 {
            let p = padded_len(len);
            assert!(p >= len);
            if len >= 16 {
                assert!((p - len) as f64 / len as f64 <= 0.12, "len {len} padded to {p}");
            }
        }
    }

    #[test]
    fn matches_the_paper_on_known_values() {
        // Small values are exact; from there, fewer and fewer low bits survive.
        assert_eq!(padded_len(0), 0);
        assert_eq!(padded_len(1), 1);
        assert_eq!(padded_len(7), 7);
        assert_eq!(padded_len(9), 10);
        assert_eq!(padded_len(1000), 1024);
        assert_eq!(padded_len(65_536), 65_536);
        assert_eq!(padded_len(65_537), 67_584);
    }

    #[test]
    fn collapses_many_lengths_into_few() {
        let distinct: std::collections::BTreeSet<u64> = (4096..8192).map(padded_len).collect();
        // Multiples of 256 from 4096 through 8192.
        assert_eq!(distinct.len(), 17, "{distinct:?}");
    }
}
