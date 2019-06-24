use crate::TransmutingByteSlices;
use core::{self, cmp, hash::Hasher};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

const CHUNK_SIZE: usize = 16;

const PRIME_1: u32 = 2654435761;
const PRIME_2: u32 = 2246822519;
const PRIME_3: u32 = 3266489917;
const PRIME_4: u32 = 668265263;
const PRIME_5: u32 = 374761393;

#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
#[derive(Copy, Clone, PartialEq)]
struct XxCore {
    v1: u32,
    v2: u32,
    v3: u32,
    v4: u32,
}

/// Calculates the 32-bit hash. Care should be taken when using this
/// hash.
///
/// Although this struct implements `Hasher`, it only calculates a
/// 32-bit number, leaving the upper bits as 0. This means it is
/// unlikely to be correct to use this in places like a `HashMap`.
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct XxHash {
    total_len: u32,
    seed: u32,
    core: XxCore,
    #[cfg_attr(feature = "serialize", serde(flatten))]
    buffer: Buffer,
}

impl XxCore {
    fn with_seed(seed: u32) -> XxCore {
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
        I: IntoIterator<Item = &'a [u32; 4]>,
    {
        #[inline(always)]
        fn ingest_one_number(mut current_value: u32, mut value: u32) -> u32 {
            value = value.wrapping_mul(PRIME_2);
            current_value = current_value.wrapping_add(value);
            current_value = current_value.rotate_left(13); // DIFF
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
    fn finish(&self) -> u32 {
        // The original code pulls out local vars for v[1234]
        // here. Performance tests did not show that to be effective
        // here, presumably because this method is not called in a
        // tight loop.

        let mut hash;

        hash = self.v1.rotate_left(1);
        hash = hash.wrapping_add(self.v2.rotate_left(7));
        hash = hash.wrapping_add(self.v3.rotate_left(12));
        hash = hash.wrapping_add(self.v4.rotate_left(18));

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
    pub fn with_seed(seed: u32) -> XxHash {
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
                let (unaligned_head, aligned, unaligned_tail) = self.buffer.data.as_u32_arrays();
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
        let (unaligned_head, aligned, unaligned_tail) = bytes.as_u32_arrays();

        self.buffer_bytes(unaligned_head);

        // Surprisingly, if we still have bytes in the buffer here, we
        // don't do anything with them yet! This matches the C
        // implementation.

        self.core.ingest_chunks(aligned);

        self.buffer_bytes(unaligned_tail);

        self.total_len += bytes.len() as u32;
    }

    fn finish(&self) -> u64 {
        let mut hash;

        // We have processed at least one full chunk
        if self.total_len >= CHUNK_SIZE as u32 {
            hash = self.core.finish();
        } else {
            hash = self.seed.wrapping_add(PRIME_5);
        }

        hash = hash.wrapping_add(self.total_len);

        let buffered = self.buffer.data();
        let (before, buffered_u32s, buffered_u8s) = buffered.as_u32s();
        debug_assert!(
            before.is_empty(),
            "buffer was not aligned for 32-bit numbers"
        );

        for buffered_u32 in buffered_u32s {
            let k1 = buffered_u32.wrapping_mul(PRIME_3);
            hash = hash.wrapping_add(k1);
            hash = hash.rotate_left(17);
            hash = hash.wrapping_mul(PRIME_4);
        }

        for buffered_u8 in buffered_u8s {
            let k1 = (*buffered_u8 as u32).wrapping_mul(PRIME_5);
            hash = hash.wrapping_add(k1);
            hash = hash.rotate_left(11);
            hash = hash.wrapping_mul(PRIME_1);
        }

        // The final intermixing
        hash ^= hash >> 15;
        hash = hash.wrapping_mul(PRIME_2);
        hash ^= hash >> 13;
        hash = hash.wrapping_mul(PRIME_3);
        hash ^= hash >> 16;

        hash as u64
    }
}

#[cfg(feature = "std")]
pub use crate::std_support::thirty_two::RandomXxHashBuilder;

#[cfg(test)]
mod test {
    use super::{RandomXxHashBuilder, XxHash};
    use std::collections::HashMap;
    use std::hash::{BuildHasherDefault, Hasher};
    use std::prelude::v1::*;

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
        assert_eq!(hasher.finish(), 0x02cc5d05);
    }

    #[test]
    fn hash_of_single_byte_matches_c_implementation() {
        let mut hasher = XxHash::with_seed(0);
        hasher.write(&[42]);
        assert_eq!(hasher.finish(), 0xe0fe705f);
    }

    #[test]
    fn hash_of_multiple_bytes_matches_c_implementation() {
        let mut hasher = XxHash::with_seed(0);
        hasher.write(b"Hello, world!\0");
        assert_eq!(hasher.finish(), 0x9e5e7e93);
    }

    #[test]
    fn hash_of_multiple_chunks_matches_c_implementation() {
        let bytes: Vec<_> = (0..100).collect();
        let mut hasher = XxHash::with_seed(0);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x7f89ba44);
    }

    #[test]
    fn hash_with_different_seed_matches_c_implementation() {
        let mut hasher = XxHash::with_seed(0x42c91977);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0xd6bf8459);
    }

    #[test]
    fn hash_with_different_seed_and_multiple_chunks_matches_c_implementation() {
        let bytes: Vec<_> = (0..100).collect();
        let mut hasher = XxHash::with_seed(0x42c91977);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x6d2f6c17);
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
              "v1": 606290984,
              "v2": 2246822519,
              "v3": 0,
              "v4": 1640531535
            },
            "buffer": [
              72,  101, 108, 108, 111, 44, 32, 119,
              111, 114, 108, 100, 33,  0,  0,  0
            ],
            "buffer_usage": 14
        }"#;

        let unserialized: XxHash = serde_json::from_str(serialized).unwrap();
        assert_eq!(hasher, unserialized);
        Ok(())
    }
}
