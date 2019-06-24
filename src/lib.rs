//! A Rust implementation of the [XXHash] algorithm.
//!
//! [XXHash]: https://github.com/Cyan4973/xxHash
//!
//! ### With a fixed seed
//!
//! ```rust
//! use std::hash::BuildHasherDefault;
//! use std::collections::HashMap;
//! use twox_hash::XxHash;
//!
//! let mut hash: HashMap<_, _, BuildHasherDefault<XxHash>> = Default::default();
//! hash.insert(42, "the answer");
//! assert_eq!(hash.get(&42), Some(&"the answer"));
//! ```
//!
//! ### With a random seed
//!
//! ```rust
//! use std::collections::HashMap;
//! use twox_hash::RandomXxHashBuilder;
//!
//! let mut hash: HashMap<_, _, RandomXxHashBuilder> = Default::default();
//! hash.insert(42, "the answer");
//! assert_eq!(hash.get(&42), Some(&"the answer"));
//! ```

#![no_std]

#[cfg(test)]
extern crate std;

use core::{cmp, hash::Hasher};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

mod thirty_two;

#[cfg(feature = "digest")]
mod digest_support;

#[cfg(feature = "std")]
pub use crate::thirty_two::RandomXxHashBuilder as RandomXxHashBuilder32;
pub use crate::thirty_two::XxHash as XxHash32;

trait TransmutingByteSlices {
    fn as_u64_arrays(&self) -> (&[u8], &[[u64; 4]], &[u8]);
    fn as_u64s(&self) -> (&[u8], &[u64], &[u8]);
    fn as_u32_arrays(&self) -> (&[u8], &[[u32; 4]], &[u8]);
    fn as_u32s(&self) -> (&[u8], &[u32], &[u8]);
}

// # Safety
//
// - Interpreting a properly-aligned set of bytes as a `u64` should be
//   valid.
// - `align_to` guarantees to only transmute aligned data.
// - An array is a tightly-packed set of bytes (as shown by `impl
//   TryFrom<&[u8]> for &[u8; N]`)
impl TransmutingByteSlices for [u8] {
    fn as_u64_arrays(&self) -> (&[u8], &[[u64; 4]], &[u8]) {
        unsafe { self.align_to::<[u64; 4]>() }
    }

    fn as_u64s(&self) -> (&[u8], &[u64], &[u8]) {
        unsafe { self.align_to::<u64>() }
    }

    fn as_u32_arrays(&self) -> (&[u8], &[[u32; 4]], &[u8]) {
        unsafe { self.align_to::<[u32; 4]>() }
    }

    fn as_u32s(&self) -> (&[u8], &[u32], &[u8]) {
        unsafe { self.align_to::<u32>() }
    }
}

const CHUNK_SIZE: usize = 32;

const PRIME_1: u64 = 11400714785074694791;
const PRIME_2: u64 = 14029467366897019727;
const PRIME_3: u64 = 1609587929392839161;
const PRIME_4: u64 = 9650029242287828579;
const PRIME_5: u64 = 2870177450012600261;

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, PartialEq)]
struct XxCore {
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
}

/// Calculates the 64-bit hash.
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct XxHash {
    total_len: u64,
    seed: u64,
    core: XxCore,
    #[cfg_attr(feature = "serialize", serde(flatten))]
    buffer: Buffer,
}

impl XxCore {
    fn with_seed(seed: u64) -> XxCore {
        XxCore {
            v1: seed.wrapping_add(PRIME_1).wrapping_add(PRIME_2),
            v2: seed.wrapping_add(PRIME_2),
            v3: seed,
            v4: seed.wrapping_sub(PRIME_1),
        }
    }

    #[inline(always)]
    fn ingest_chunks<'a, I>(&mut self, values: I)
    where
        I: IntoIterator<Item = &'a [u64; 4]>,
    {
        #[inline(always)]
        fn ingest_one_number(mut current_value: u64, mut value: u64) -> u64 {
            value = value.wrapping_mul(PRIME_2);
            current_value = current_value.wrapping_add(value);
            current_value = current_value.rotate_left(31);
            current_value.wrapping_mul(PRIME_1)
        };

        // By drawing these out, we can avoid going back and forth to
        // memory. It only really helps for large files, when we need
        // to iterate multiple times here.

        let mut v1 = self.v1;
        let mut v2 = self.v2;
        let mut v3 = self.v3;
        let mut v4 = self.v4;

        for &[n1, n2, n3, n4] in values {
            v1 = ingest_one_number(v1, n1);
            v2 = ingest_one_number(v2, n2);
            v3 = ingest_one_number(v3, n3);
            v4 = ingest_one_number(v4, n4);
        }

        self.v1 = v1;
        self.v2 = v2;
        self.v3 = v3;
        self.v4 = v4;
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        // The original code pulls out local vars for v[1234]
        // here. Performance tests did not show that to be effective
        // here, presumably because this method is not called in a
        // tight loop.

        let mut hash;

        hash = self.v1.rotate_left(1);
        hash = hash.wrapping_add(self.v2.rotate_left(7));
        hash = hash.wrapping_add(self.v3.rotate_left(12));
        hash = hash.wrapping_add(self.v4.rotate_left(18));

        #[inline(always)]
        fn mix_one(mut hash: u64, mut value: u64) -> u64 {
            value = value.wrapping_mul(PRIME_2);
            value = value.rotate_left(31);
            value = value.wrapping_mul(PRIME_1);
            hash ^= value;
            hash = hash.wrapping_mul(PRIME_1);
            hash.wrapping_add(PRIME_4)
        }

        hash = mix_one(hash, self.v1);
        hash = mix_one(hash, self.v2);
        hash = mix_one(hash, self.v3);
        hash = mix_one(hash, self.v4);

        hash
    }
}

impl core::fmt::Debug for XxCore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "XxCore {{ {:016x} {:016x} {:016x} {:016x} }}",
            self.v1, self.v2, self.v3, self.v4
        )
    }
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, Default, PartialEq)]
struct Buffer {
    #[cfg_attr(feature = "serialize", serde(rename = "buffer"))]
    data: [u8; CHUNK_SIZE],
    #[cfg_attr(feature = "serialize", serde(rename = "buffer_usage"))]
    len: usize,
}

impl Buffer {
    fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Consumes as much of the parameter as it can, returning the unused part.
    fn consume<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        let to_use = cmp::min(self.available(), data.len());
        let (data, remaining) = data.split_at(to_use);
        self.data[self.len..][..to_use].copy_from_slice(data);
        self.len += to_use;
        remaining
    }

    fn available(&self) -> usize {
        CHUNK_SIZE - self.len
    }

    fn is_full(&self) -> bool {
        self.len == CHUNK_SIZE
    }
}

impl XxHash {
    /// Constructs the hash with an initial seed
    pub fn with_seed(seed: u64) -> XxHash {
        XxHash {
            total_len: 0,
            seed: seed,
            core: XxCore::with_seed(seed),
            buffer: Buffer::default(),
        }
    }

    fn buffer_bytes(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            data = self.buffer.consume(data);
            if self.buffer.is_full() {
                let (unaligned_head, aligned, unaligned_tail) =
                    self.buffer.data[..].as_u64_arrays();
                debug_assert!(
                    unaligned_head.is_empty(),
                    "buffer was not aligned for 64-bit numbers"
                );
                debug_assert_eq!(
                    aligned.len(),
                    1,
                    "buffer did not have enough 64-bit numbers"
                );
                debug_assert!(unaligned_tail.is_empty(), "buffer has trailing data");
                self.core.ingest_chunks(aligned);
                self.buffer.len = 0;
            }
        }
    }
}

impl Default for XxHash {
    fn default() -> XxHash {
        XxHash::with_seed(0)
    }
}

impl Hasher for XxHash {
    fn write(&mut self, bytes: &[u8]) {
        let (unaligned_head, aligned, unaligned_tail) = bytes.as_u64_arrays();

        self.buffer_bytes(unaligned_head);

        // Surprisingly, if we still have bytes in the buffer here, we
        // don't do anything with them yet! This matches the C
        // implementation.

        self.core.ingest_chunks(aligned);

        self.buffer_bytes(unaligned_tail);

        self.total_len += bytes.len() as u64;
    }

    fn finish(&self) -> u64 {
        let mut hash;

        // We have processed at least one full chunk
        if self.total_len >= CHUNK_SIZE as u64 {
            hash = self.core.finish();
        } else {
            hash = self.seed.wrapping_add(PRIME_5);
        }

        hash = hash.wrapping_add(self.total_len);

        let buffered = &self.buffer.data();
        let (before, buffered_u64s, buffered) = buffered.as_u64s();
        debug_assert!(
            before.is_empty(),
            "buffer was not aligned for 64-bit numbers"
        );

        for buffered_u64 in buffered_u64s {
            let mut k1 = buffered_u64.wrapping_mul(PRIME_2);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(PRIME_1);
            hash ^= k1;
            hash = hash.rotate_left(27);
            hash = hash.wrapping_mul(PRIME_1);
            hash = hash.wrapping_add(PRIME_4);
        }

        let (before, buffered_u32s, buffered_u8s) = buffered.as_u32s();
        debug_assert!(
            before.is_empty(),
            "buffer was not aligned for 32-bit numbers"
        );

        for &buffered_u32 in buffered_u32s {
            let k1 = (buffered_u32 as u64).wrapping_mul(PRIME_1);
            hash ^= k1;
            hash = hash.rotate_left(23);
            hash = hash.wrapping_mul(PRIME_2);
            hash = hash.wrapping_add(PRIME_3);
        }

        for &buffered_u8 in buffered_u8s {
            let k1 = (buffered_u8 as u64).wrapping_mul(PRIME_5);
            hash ^= k1;
            hash = hash.rotate_left(11);
            hash = hash.wrapping_mul(PRIME_1);
        }

        // The final intermixing
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(PRIME_2);
        hash ^= hash >> 29;
        hash = hash.wrapping_mul(PRIME_3);
        hash ^= hash >> 32;

        hash
    }
}

#[cfg(feature = "std")]
mod std_support;

#[cfg(feature = "std")]
pub use crate::std_support::sixty_four::RandomXxHashBuilder;

#[cfg(test)]
mod test {
    use std::prelude::v1::*;

    use super::{RandomXxHashBuilder, XxHash};
    use std::collections::HashMap;
    use std::hash::{BuildHasherDefault, Hasher};

    #[test]
    fn ingesting_byte_by_byte_is_equivalent_to_large_chunks() {
        let bytes: Vec<_> = (0..32).map(|_| 0).collect();

        let mut byte_by_byte = XxHash::with_seed(0);
        for byte in bytes.chunks(1) {
            byte_by_byte.write(byte);
        }

        let mut one_chunk = XxHash::with_seed(0);
        one_chunk.write(&bytes);

        assert_eq!(byte_by_byte.core, one_chunk.core);
    }

    #[test]
    fn hash_of_nothing_matches_c_implementation() {
        let mut hasher = XxHash::with_seed(0);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0xef46db3751d8e999);
    }

    #[test]
    fn hash_of_single_byte_matches_c_implementation() {
        let mut hasher = XxHash::with_seed(0);
        hasher.write(&[42]);
        assert_eq!(hasher.finish(), 0x0a9edecebeb03ae4);
    }

    #[test]
    fn hash_of_multiple_bytes_matches_c_implementation() {
        let mut hasher = XxHash::with_seed(0);
        hasher.write(b"Hello, world!\0");
        assert_eq!(hasher.finish(), 0x7b06c531ea43e89f);
    }

    #[test]
    fn hash_of_multiple_chunks_matches_c_implementation() {
        let bytes: Vec<_> = (0..100).collect();
        let mut hasher = XxHash::with_seed(0);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x6ac1e58032166597);
    }

    #[test]
    fn hash_with_different_seed_matches_c_implementation() {
        let mut hasher = XxHash::with_seed(0xae0543311b702d91);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0x4b6a04fcdf7a4672);
    }

    #[test]
    fn hash_with_different_seed_and_multiple_chunks_matches_c_implementation() {
        let bytes: Vec<_> = (0..100).collect();
        let mut hasher = XxHash::with_seed(0xae0543311b702d91);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x567e355e0682e1f1);
    }

    #[test]
    fn can_be_used_in_a_hashmap_with_a_default_seed() {
        let mut hash: HashMap<_, _, BuildHasherDefault<XxHash>> = Default::default();
        hash.insert(42, "the answer");
        assert_eq!(hash.get(&42), Some(&"the answer"));
    }

    #[test]
    fn can_be_used_in_a_hashmap_with_a_random_seed() {
        let mut hash: HashMap<_, _, RandomXxHashBuilder> = Default::default();
        hash.insert(42, "the answer");
        assert_eq!(hash.get(&42), Some(&"the answer"));
    }

    #[cfg(feature = "serialize")]
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[cfg(feature = "serialize")]
    #[test]
    fn test_serialization_cycle() -> TestResult {
        let mut hasher = XxHash::with_seed(0);
        hasher.write(b"Hello, world!\0");
        hasher.finish();

        let serialized = serde_json::to_string(&hasher)?;
        let unserialized: XxHash = serde_json::from_str(&serialized)?;
        assert_eq!(hasher, unserialized);
        Ok(())
    }

    #[cfg(feature = "serialize")]
    #[test]
    fn test_serialization_stability() -> TestResult {
        let mut hasher = XxHash::with_seed(0);
        hasher.write(b"Hello, world!\0");
        hasher.finish();

        let serialized = r#"{
            "total_len": 14,
            "seed": 0,
            "core": {
              "v1": 6983438078262162902,
              "v2": 14029467366897019727,
              "v3": 0,
              "v4": 7046029288634856825
            },
            "buffer": [
              72,  101, 108, 108, 111, 44, 32, 119,
              111, 114, 108, 100, 33,  0,  0,  0,
              0,   0,   0,   0,   0,   0,  0,  0,
              0,   0,   0,   0,   0,   0,  0,  0
            ],
            "buffer_usage": 14
        }"#;

        let unserialized: XxHash = serde_json::from_str(serialized).unwrap();
        assert_eq!(hasher, unserialized);
        Ok(())
    }
}
