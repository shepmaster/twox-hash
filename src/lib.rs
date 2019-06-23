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

#[cfg(feature = "std")]
extern crate rand;

#[cfg(feature="serialize")]
extern crate serde;
#[cfg(feature="serialize")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "digest")]
extern crate digest;

mod number_streams;
mod thirty_two;

#[cfg(feature = "digest")]
mod digest_support;

pub use thirty_two::XxHash as XxHash32;
#[cfg(feature = "std")]
pub use thirty_two::RandomXxHashBuilder as RandomXxHashBuilder32;

use core::hash::Hasher;
use number_streams::NumberStreams;

const CHUNK_SIZE: usize = 32;

const PRIME_1: u64 = 11400714785074694791;
const PRIME_2: u64 = 14029467366897019727;
const PRIME_3: u64 = 1609587929392839161;
const PRIME_4: u64 = 9650029242287828579;
const PRIME_5: u64 = 2870177450012600261;

#[cfg_attr(feature="serialize", derive(Serialize, Deserialize))] 
#[derive(Copy,Clone,PartialEq)]
struct XxCore {
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
}

/// Calculates the 64-bit hash.
#[cfg_attr(feature="serialize", derive(Serialize, Deserialize))] 
#[derive(PartialEq, Debug,Copy,Clone)]
pub struct XxHash {
    total_len: u64,
    seed: u64,
    core: XxCore,
    buffer: [u8; CHUNK_SIZE],
    buffer_usage: usize,
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
    fn ingest_chunks<I>(&mut self, values: I)
        where I: Iterator<Item=u64>
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

        let mut values = values.peekable();

        while values.peek().is_some() {
            v1 = ingest_one_number(v1, values.next().unwrap());
            v2 = ingest_one_number(v2, values.next().unwrap());
            v3 = ingest_one_number(v3, values.next().unwrap());
            v4 = ingest_one_number(v4, values.next().unwrap());
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

        hash =                   self.v1.rotate_left( 1);
        hash = hash.wrapping_add(self.v2.rotate_left( 7));
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
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(
            f, "XxCore {{ {:016x} {:016x} {:016x} {:016x} }}",
            self.v1, self.v2, self.v3, self.v4
        )
    }
}

impl XxHash {
    /// Constructs the hash with an initial seed
    pub fn with_seed(seed: u64) -> XxHash {
        XxHash {
            total_len: 0,
            seed: seed,
            core: XxCore::with_seed(seed),
            buffer: unsafe { ::core::mem::uninitialized() },
            buffer_usage: 0,
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
        let mut bytes = bytes;

        self.total_len += bytes.len() as u64;

        // Even with new data, we still don't have a full buffer. Wait
        // until we have a full buffer.
        if self.buffer_usage + bytes.len() < self.buffer.len() {
            unsafe {
                let tail = self.buffer.as_mut_ptr().offset(self.buffer_usage as isize);
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), tail, bytes.len());
            }
            self.buffer_usage += bytes.len();
            return;
        }

        // Some data left from previous update. Fill the buffer and
        // consume it first.
        if self.buffer_usage > 0 {
            let bytes_to_use = self.buffer.len() - self.buffer_usage;
            let (to_use, leftover) = bytes.split_at(bytes_to_use);

            unsafe {
                let tail = self.buffer.as_mut_ptr().offset(self.buffer_usage as isize);
                core::ptr::copy_nonoverlapping(to_use.as_ptr(), tail, bytes_to_use);
            }

            let (iter, _) = self.buffer.u64_stream();

            self.core.ingest_chunks(iter);

            bytes = leftover;
            self.buffer_usage = 0;
        }

        // Consume the input data in large chunks
        let (iter, bytes) = bytes.u64_stream_with_stride(4);
        self.core.ingest_chunks(iter);

        // Save any leftover data for the next call
        if bytes.len() > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer.as_mut_ptr(), bytes.len());
            }
            self.buffer_usage = bytes.len();
        }
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

        let buffered = &self.buffer[..self.buffer_usage];
        let (buffered_u64s, buffered) = buffered.u64_stream();

        for mut k1 in buffered_u64s {
            k1 = k1.wrapping_mul(PRIME_2);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(PRIME_1);
            hash ^= k1;
            hash = hash.rotate_left(27);
            hash = hash.wrapping_mul(PRIME_1);
            hash = hash.wrapping_add(PRIME_4);
        }

        let (buffered_u32s, buffered) = buffered.u32_stream();

        for k1 in buffered_u32s {
            let k1 = (k1 as u64).wrapping_mul(PRIME_1);
            hash ^= k1;
            hash = hash.rotate_left(23);
            hash = hash.wrapping_mul(PRIME_2);
            hash = hash.wrapping_add(PRIME_3);
        }

        for buffered_u8 in buffered {
            let k1 = (*buffered_u8 as u64).wrapping_mul(PRIME_5);
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
pub use std_support::sixty_four::RandomXxHashBuilder;

#[cfg(test)]
mod test {
    use std::prelude::v1::*;

    use std::hash::{Hasher, BuildHasherDefault};
    use std::collections::HashMap;
    use super::{XxHash, RandomXxHashBuilder};

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

    #[cfg(feature="serialize")]
    #[test]
    fn test_serialization() {
        let mut hasher = XxHash::with_seed(0);
        hasher.write(b"Hello, world!\0");
        hasher.finish();

        let serialized = serde_json::to_string(&hasher).unwrap();
        let unserialized: XxHash = serde_json::from_str(&serialized).unwrap();
        assert_eq!(hasher, unserialized);
    }
}
