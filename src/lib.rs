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

#![cfg_attr(feature = "unstable", feature(test))]

extern crate rand;

mod number_streams;

use std::hash::{Hasher, BuildHasher};
use rand::Rng;
use number_streams::NumberStreams;

const CHUNK32_SIZE: usize = 16;
const CHUNK64_SIZE: usize = 32;

const PRIME32_1: u32 = 2654435761;
const PRIME32_2: u32 = 2246822519;
const PRIME32_3: u32 = 3266489917;
const PRIME32_4: u32 = 668265263;
const PRIME32_5: u32 = 374761393;

const PRIME64_1: u64 = 11400714785074694791;
const PRIME64_2: u64 = 14029467366897019727;
const PRIME64_3: u64 = 1609587929392839161;
const PRIME64_4: u64 = 9650029242287828579;
const PRIME64_5: u64 = 2870177450012600261;

#[derive(Copy,Clone,PartialEq)]
struct XxCore32 {
    v1: u32,
    v2: u32,
    v3: u32,
    v4: u32,
}

#[derive(Copy,Clone,PartialEq)]
struct XxCore64 {
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
}

#[derive(Debug,Copy,Clone)]
pub struct XxHash32 {
    total_len: u32,
    seed: u32,
    core: XxCore32,
    buffer: [u8; CHUNK32_SIZE],
    buffer_usage: usize,
}

pub use XxHash64 as XxHash;

#[derive(Debug,Copy,Clone)]
pub struct XxHash64 {
    total_len: u64,
    seed: u64,
    core: XxCore64,
    buffer: [u8; CHUNK64_SIZE],
    buffer_usage: usize,
}

impl XxCore32 {
    fn with_seed(seed: u32) -> XxCore32 {
        XxCore32 {
            v1: seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2),
            v2: seed.wrapping_add(PRIME32_2),
            v3: seed,
            v4: seed.wrapping_sub(PRIME32_1),
        }
    }

    #[inline(always)]
    fn ingest_chunks<I>(&mut self, values: I)
        where I: Iterator<Item = u32>
    {
        #[inline(always)]
        fn ingest_one_number(mut current_value: u32, mut value: u32) -> u32 {
            value = value.wrapping_mul(PRIME32_2);
            current_value = current_value.wrapping_add(value);
            current_value = current_value.rotate_left(13);
            current_value.wrapping_mul(PRIME32_1)
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

impl std::fmt::Debug for XxCore32 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f,
               "XxCore64 {{ {:08x} {:08x} {:08x} {:08x} }}",
               self.v1,
               self.v2,
               self.v3,
               self.v4)
    }
}

impl XxCore64 {
    fn with_seed(seed: u64) -> XxCore64 {
        XxCore64 {
            v1: seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2),
            v2: seed.wrapping_add(PRIME64_2),
            v3: seed,
            v4: seed.wrapping_sub(PRIME64_1),
        }
    }

    #[inline(always)]
    fn ingest_chunks<I>(&mut self, values: I)
        where I: Iterator<Item = u64>
    {
        #[inline(always)]
        fn ingest_one_number(mut current_value: u64, mut value: u64) -> u64 {
            value = value.wrapping_mul(PRIME64_2);
            current_value = current_value.wrapping_add(value);
            current_value = current_value.rotate_left(31);
            current_value.wrapping_mul(PRIME64_1)
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

        hash = self.v1.rotate_left(1);
        hash = hash.wrapping_add(self.v2.rotate_left(7));
        hash = hash.wrapping_add(self.v3.rotate_left(12));
        hash = hash.wrapping_add(self.v4.rotate_left(18));

        #[inline(always)]
        fn mix_one(mut hash: u64, mut value: u64) -> u64 {
            value = value.wrapping_mul(PRIME64_2);
            value = value.rotate_left(31);
            value = value.wrapping_mul(PRIME64_1);
            hash ^= value;
            hash = hash.wrapping_mul(PRIME64_1);
            hash.wrapping_add(PRIME64_4)
        }

        hash = mix_one(hash, self.v1);
        hash = mix_one(hash, self.v2);
        hash = mix_one(hash, self.v3);
        hash = mix_one(hash, self.v4);

        hash
    }
}

impl std::fmt::Debug for XxCore64 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f,
               "XxCore64 {{ {:016x} {:016x} {:016x} {:016x} }}",
               self.v1,
               self.v2,
               self.v3,
               self.v4)
    }
}

impl XxHash32 {
    pub fn with_seed(seed: u32) -> XxHash32 {
        XxHash32 {
            total_len: 0,
            seed: seed,
            core: XxCore32::with_seed(seed),
            buffer: unsafe { ::std::mem::uninitialized() },
            buffer_usage: 0,
        }
    }
}

impl Default for XxHash32 {
    fn default() -> XxHash32 {
        XxHash32::with_seed(0)
    }
}

impl Hasher for XxHash32 {
    fn write(&mut self, bytes: &[u8]) {
        let mut bytes = bytes;

        self.total_len += bytes.len() as u32;

        // Even with new data, we still don't have a full buffer. Wait
        // until we have a full buffer.
        if self.buffer_usage + bytes.len() < self.buffer.len() {
            unsafe {
                let tail = self.buffer
                    .as_mut_ptr()
                    .offset(self.buffer_usage as isize);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), tail, bytes.len());
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
                let tail = self.buffer
                    .as_mut_ptr()
                    .offset(self.buffer_usage as isize);
                std::ptr::copy_nonoverlapping(to_use.as_ptr(), tail, bytes_to_use);
            }

            let (iter, _) = self.buffer.u32_stream();

            self.core.ingest_chunks(iter);

            bytes = leftover;
            self.buffer_usage = 0;
        }

        // Consume the input data in large chunks
        let (iter, bytes) = bytes.u32_stream_with_stride(2);
        self.core.ingest_chunks(iter);

        // Save any leftover data for the next call
        if bytes.len() > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(),
                                              self.buffer.as_mut_ptr(),
                                              bytes.len());
            }
            self.buffer_usage = bytes.len();
        }
    }

    fn finish(&self) -> u64 {
        let mut hash;

        // We have processed at least one full chunk
        if self.total_len >= CHUNK32_SIZE as u32 {
            hash = self.core.finish();
        } else {
            hash = self.seed.wrapping_add(PRIME32_5);
        }

        hash = hash.wrapping_add(self.total_len);

        let buffered = &self.buffer[..self.buffer_usage];
        let (buffered_u32s, buffered) = buffered.u32_stream();

        for k1 in buffered_u32s {
            let k1 = (k1 as u32).wrapping_mul(PRIME32_3);
            hash = hash.wrapping_add(k1);
            hash = hash.rotate_left(17);
            hash = hash.wrapping_mul(PRIME32_4);
        }

        for buffered_u8 in buffered {
            let k1 = (*buffered_u8 as u32).wrapping_mul(PRIME32_5);
            hash = hash.wrapping_add(k1);
            hash = hash.rotate_left(11);
            hash = hash.wrapping_mul(PRIME32_1);
        }

        // The final intermixing
        hash ^= hash >> 15;
        hash = hash.wrapping_mul(PRIME32_2);
        hash ^= hash >> 13;
        hash = hash.wrapping_mul(PRIME32_3);
        hash ^= hash >> 16;

        hash as u64
    }
}

impl XxHash64 {
    pub fn with_seed(seed: u64) -> XxHash64 {
        XxHash64 {
            total_len: 0,
            seed: seed,
            core: XxCore64::with_seed(seed),
            buffer: unsafe { ::std::mem::uninitialized() },
            buffer_usage: 0,
        }
    }
}

impl Default for XxHash64 {
    fn default() -> XxHash64 {
        XxHash64::with_seed(0)
    }
}

impl Hasher for XxHash64 {
    fn write(&mut self, bytes: &[u8]) {
        let mut bytes = bytes;

        self.total_len += bytes.len() as u64;

        // Even with new data, we still don't have a full buffer. Wait
        // until we have a full buffer.
        if self.buffer_usage + bytes.len() < self.buffer.len() {
            unsafe {
                let tail = self.buffer
                    .as_mut_ptr()
                    .offset(self.buffer_usage as isize);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), tail, bytes.len());
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
                let tail = self.buffer
                    .as_mut_ptr()
                    .offset(self.buffer_usage as isize);
                std::ptr::copy_nonoverlapping(to_use.as_ptr(), tail, bytes_to_use);
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
                std::ptr::copy_nonoverlapping(bytes.as_ptr(),
                                              self.buffer.as_mut_ptr(),
                                              bytes.len());
            }
            self.buffer_usage = bytes.len();
        }
    }

    fn finish(&self) -> u64 {
        let mut hash;

        // We have processed at least one full chunk
        if self.total_len >= CHUNK64_SIZE as u64 {
            hash = self.core.finish();
        } else {
            hash = self.seed.wrapping_add(PRIME64_5);
        }

        hash = hash.wrapping_add(self.total_len);

        let buffered = &self.buffer[..self.buffer_usage];
        let (buffered_u64s, buffered) = buffered.u64_stream();

        for mut k1 in buffered_u64s {
            k1 = k1.wrapping_mul(PRIME64_2);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(PRIME64_1);
            hash ^= k1;
            hash = hash.rotate_left(27);
            hash = hash.wrapping_mul(PRIME64_1);
            hash = hash.wrapping_add(PRIME64_4);
        }

        let (buffered_u32s, buffered) = buffered.u32_stream();

        for k1 in buffered_u32s {
            let k1 = (k1 as u64).wrapping_mul(PRIME64_1);
            hash ^= k1;
            hash = hash.rotate_left(23);
            hash = hash.wrapping_mul(PRIME64_2);
            hash = hash.wrapping_add(PRIME64_3);
        }

        for buffered_u8 in buffered {
            let k1 = (*buffered_u8 as u64).wrapping_mul(PRIME64_5);
            hash ^= k1;
            hash = hash.rotate_left(11);
            hash = hash.wrapping_mul(PRIME64_1);
        }

        // The final intermixing
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(PRIME64_2);
        hash ^= hash >> 29;
        hash = hash.wrapping_mul(PRIME64_3);
        hash ^= hash >> 32;

        hash
    }
}

#[derive(Clone)]
pub struct RandomXxHash32Builder(u32);

impl RandomXxHash32Builder {
    fn new() -> RandomXxHash32Builder {
        RandomXxHash32Builder(rand::thread_rng().gen())
    }
}

impl Default for RandomXxHash32Builder {
    fn default() -> RandomXxHash32Builder {
        RandomXxHash32Builder::new()
    }
}

impl BuildHasher for RandomXxHash32Builder {
    type Hasher = XxHash32;

    fn build_hasher(&self) -> XxHash32 {
        XxHash32::with_seed(self.0)
    }
}

pub use RandomXxHash64Builder as RandomXxHashBuilder;

#[derive(Clone)]
pub struct RandomXxHash64Builder(u64);

impl RandomXxHash64Builder {
    fn new() -> RandomXxHash64Builder {
        RandomXxHash64Builder(rand::thread_rng().gen())
    }
}

impl Default for RandomXxHash64Builder {
    fn default() -> RandomXxHash64Builder {
        RandomXxHash64Builder::new()
    }
}

impl BuildHasher for RandomXxHash64Builder {
    type Hasher = XxHash64;

    fn build_hasher(&self) -> XxHash64 {
        XxHash64::with_seed(self.0)
    }
}

#[cfg(test)]
mod test {
    extern crate xxhash2;

    use std::hash::{Hasher, BuildHasherDefault};
    use std::collections::HashMap;
    use super::{XxHash32, XxHash64, RandomXxHash32Builder, RandomXxHash64Builder};

    #[test]
    fn ingesting_byte_by_byte_is_equivalent_to_large_chunks() {
        let bytes: Vec<_> = (0..32).map(|_| 0).collect();

        let mut byte_by_byte = XxHash64::with_seed(0);
        for byte in bytes.chunks(1) {
            byte_by_byte.write(byte);
        }

        let mut one_chunk = XxHash64::with_seed(0);
        one_chunk.write(&bytes);

        assert_eq!(byte_by_byte.core, one_chunk.core);
    }

    #[test]
    fn hash_of_nothing_matches_c_implementation() {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0xef46db3751d8e999);
        assert_eq!(hasher.finish(), xxhash2::hash64(&[], 0));

        let mut hasher = XxHash32::with_seed(0);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0x2cc5d05);
        assert_eq!(hasher.finish(), xxhash2::hash32(&[], 0) as u64);
    }

    #[test]
    fn hash_of_single_byte_matches_c_implementation() {
        let bytes = &[42];

        let mut hasher = XxHash64::with_seed(0);
        hasher.write(bytes);
        assert_eq!(hasher.finish(), 0x0a9edecebeb03ae4);
        assert_eq!(hasher.finish(), xxhash2::hash64(bytes, 0));

        let mut hasher = XxHash32::with_seed(0);
        hasher.write(bytes);
        assert_eq!(hasher.finish(), 3774771295);
        assert_eq!(hasher.finish(), xxhash2::hash32(bytes, 0) as u64);
    }

    #[test]
    fn hash_of_multiple_bytes_matches_c_implementation() {
        let bytes = b"Hello, world!\0";

        let mut hasher = XxHash64::with_seed(0);
        hasher.write(bytes);
        assert_eq!(hasher.finish(), 0x7b06c531ea43e89f);
        assert_eq!(hasher.finish(), xxhash2::hash64(bytes, 0));

        let mut hasher = XxHash32::with_seed(0);
        hasher.write(bytes);
        assert_eq!(hasher.finish(), 2656992915);
        assert_eq!(hasher.finish(), xxhash2::hash32(bytes, 0) as u64);
    }

    #[test]
    fn hash_of_multiple_chunks_matches_c_implementation() {
        let bytes: Vec<_> = (0..100).collect();

        let mut hasher = XxHash64::with_seed(0);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x6ac1e58032166597);
        assert_eq!(hasher.finish(), xxhash2::hash64(&bytes[..], 0));

        let mut hasher = XxHash32::with_seed(0);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 2139732548);
        assert_eq!(hasher.finish(), xxhash2::hash32(&bytes[..], 0) as u64);
    }

    #[test]
    fn hash_with_different_seed_matches_c_implementation() {
        let mut hasher = XxHash64::with_seed(0xae0543311b702d91);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0x4b6a04fcdf7a4672);
        assert_eq!(hasher.finish(), xxhash2::hash64(&[], 0xae0543311b702d91));

        let mut hasher = XxHash32::with_seed(0xae054331);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 1602139305);
        assert_eq!(hasher.finish(), xxhash2::hash32(&[], 0xae054331) as u64);
    }

    #[test]
    fn hash_with_different_seed_and_multiple_chunks_matches_c_implementation() {
        let bytes: Vec<_> = (0..100).collect();
        let mut hasher = XxHash64::with_seed(0xae0543311b702d91);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x567e355e0682e1f1);
        assert_eq!(hasher.finish(),
                   xxhash2::hash64(&bytes[..], 0xae0543311b702d91));

        let mut hasher = XxHash32::with_seed(0xae054331);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 3817749625);
        assert_eq!(hasher.finish(),
                   xxhash2::hash32(&bytes[..], 0xae054331) as u64);
    }

    #[test]
    fn can_be_used_in_a_hashmap_with_a_default_seed() {
        let mut hash: HashMap<_, _, BuildHasherDefault<XxHash64>> = Default::default();
        hash.insert(42, "the answer");
        assert_eq!(hash.get(&42), Some(&"the answer"));

        let mut hash: HashMap<_, _, BuildHasherDefault<XxHash32>> = Default::default();
        hash.insert(42, "the answer");
        assert_eq!(hash.get(&42), Some(&"the answer"));
    }

    #[test]
    fn can_be_used_in_a_hashmap_with_a_random_seed() {
        let mut hash: HashMap<_, _, RandomXxHash64Builder> = Default::default();
        hash.insert(42, "the answer");
        assert_eq!(hash.get(&42), Some(&"the answer"));

        let mut hash: HashMap<_, _, RandomXxHash32Builder> = Default::default();
        hash.insert(42, "the answer");
        assert_eq!(hash.get(&42), Some(&"the answer"));
    }
}

#[cfg(all(feature = "unstable", test))]
mod bench {
    extern crate test;
    extern crate fnv;

    use std::hash::{Hasher, SipHasher};
    use super::{XxHash32, XxHash64};

    fn hasher_bench<H>(b: &mut test::Bencher, mut hasher: H, len: usize)
        where H: Hasher
    {
        let bytes: Vec<_> = (0..100).cycle().take(len).collect();
        b.bytes = bytes.len() as u64;
        b.iter(|| {
                   hasher.write(&bytes);
                   hasher.finish()
               });
    }

    fn XxHash32_bench(b: &mut test::Bencher, len: usize) {
        hasher_bench(b, XxHash32::with_seed(0), len)
    }

    fn XxHash64_bench(b: &mut test::Bencher, len: usize) {
        hasher_bench(b, XxHash64::with_seed(0), len)
    }

    fn siphash_bench(b: &mut test::Bencher, len: usize) {
        hasher_bench(b, SipHasher::new(), len)
    }

    fn fnvhash_bench(b: &mut test::Bencher, len: usize) {
        hasher_bench(b, <fnv::FnvHasher as Default>::default(), len)
    }

    #[bench]
    fn siphash_megabyte(b: &mut test::Bencher) {
        siphash_bench(b, 1024 * 1024)
    }

    #[bench]
    fn siphash_1024_byte(b: &mut test::Bencher) {
        siphash_bench(b, 1024)
    }

    #[bench]
    fn siphash_512_byte(b: &mut test::Bencher) {
        siphash_bench(b, 512)
    }

    #[bench]
    fn siphash_256_byte(b: &mut test::Bencher) {
        siphash_bench(b, 256)
    }

    #[bench]
    fn siphash_128_byte(b: &mut test::Bencher) {
        siphash_bench(b, 128)
    }

    #[bench]
    fn siphash_32_byte(b: &mut test::Bencher) {
        siphash_bench(b, 32)
    }

    #[bench]
    fn siphash_16_byte(b: &mut test::Bencher) {
        siphash_bench(b, 16)
    }

    #[bench]
    fn siphash_4_byte(b: &mut test::Bencher) {
        siphash_bench(b, 4)
    }

    #[bench]
    fn siphash_1_byte(b: &mut test::Bencher) {
        siphash_bench(b, 1)
    }

    #[bench]
    fn siphash_0_byte(b: &mut test::Bencher) {
        siphash_bench(b, 0)
    }

    #[bench]
    fn fnvhash_megabyte(b: &mut test::Bencher) {
        fnvhash_bench(b, 1024 * 1024)
    }

    #[bench]
    fn fnvhash_1024_byte(b: &mut test::Bencher) {
        fnvhash_bench(b, 1024)
    }

    #[bench]
    fn fnvhash_512_byte(b: &mut test::Bencher) {
        fnvhash_bench(b, 512)
    }

    #[bench]
    fn fnvhash_256_byte(b: &mut test::Bencher) {
        fnvhash_bench(b, 256)
    }

    #[bench]
    fn fnvhash_128_byte(b: &mut test::Bencher) {
        fnvhash_bench(b, 128)
    }

    #[bench]
    fn fnvhash_32_byte(b: &mut test::Bencher) {
        fnvhash_bench(b, 32)
    }

    #[bench]
    fn fnvhash_16_byte(b: &mut test::Bencher) {
        fnvhash_bench(b, 16)
    }

    #[bench]
    fn fnvhash_4_byte(b: &mut test::Bencher) {
        fnvhash_bench(b, 4)
    }

    #[bench]
    fn fnvhash_1_byte(b: &mut test::Bencher) {
        fnvhash_bench(b, 1)
    }

    #[bench]
    fn fnvhash_0_byte(b: &mut test::Bencher) {
        fnvhash_bench(b, 0)
    }

    #[bench]
    fn XxHash32_megabyte(b: &mut test::Bencher) {
        XxHash32_bench(b, 1024 * 1024)
    }

    #[bench]
    fn XxHash32_1024_byte(b: &mut test::Bencher) {
        XxHash32_bench(b, 1024)
    }

    #[bench]
    fn XxHash32_512_byte(b: &mut test::Bencher) {
        XxHash32_bench(b, 512)
    }

    #[bench]
    fn XxHash32_256_byte(b: &mut test::Bencher) {
        XxHash32_bench(b, 256)
    }

    #[bench]
    fn XxHash32_128_byte(b: &mut test::Bencher) {
        XxHash32_bench(b, 128)
    }

    #[bench]
    fn XxHash32_32_byte(b: &mut test::Bencher) {
        XxHash32_bench(b, 32)
    }

    #[bench]
    fn XxHash32_16_byte(b: &mut test::Bencher) {
        XxHash32_bench(b, 16)
    }

    #[bench]
    fn XxHash32_4_byte(b: &mut test::Bencher) {
        XxHash32_bench(b, 4)
    }

    #[bench]
    fn XxHash32_1_byte(b: &mut test::Bencher) {
        XxHash32_bench(b, 1)
    }

    #[bench]
    fn XxHash32_0_byte(b: &mut test::Bencher) {
        XxHash32_bench(b, 0)
    }

    #[bench]
    fn XxHash64_megabyte(b: &mut test::Bencher) {
        XxHash64_bench(b, 1024 * 1024)
    }

    #[bench]
    fn XxHash64_1024_byte(b: &mut test::Bencher) {
        XxHash64_bench(b, 1024)
    }

    #[bench]
    fn XxHash64_512_byte(b: &mut test::Bencher) {
        XxHash64_bench(b, 512)
    }

    #[bench]
    fn XxHash64_256_byte(b: &mut test::Bencher) {
        XxHash64_bench(b, 256)
    }

    #[bench]
    fn XxHash64_128_byte(b: &mut test::Bencher) {
        XxHash64_bench(b, 128)
    }

    #[bench]
    fn XxHash64_32_byte(b: &mut test::Bencher) {
        XxHash64_bench(b, 32)
    }

    #[bench]
    fn XxHash64_16_byte(b: &mut test::Bencher) {
        XxHash64_bench(b, 16)
    }

    #[bench]
    fn XxHash64_4_byte(b: &mut test::Bencher) {
        XxHash64_bench(b, 4)
    }

    #[bench]
    fn XxHash64_1_byte(b: &mut test::Bencher) {
        XxHash64_bench(b, 1)
    }

    #[bench]
    fn XxHash64_0_byte(b: &mut test::Bencher) {
        XxHash64_bench(b, 0)
    }
}
