#![feature(core)]
#![cfg_attr(test, feature(test))]

extern crate byteorder;

use std::io::{Read,Cursor};
use byteorder::{LittleEndian,ReadBytesExt};

const CHUNK_SIZE: usize = 32;

const PRIME64_1: u64 = 11400714785074694791;
const PRIME64_2: u64 = 14029467366897019727;
const PRIME64_3: u64 = 1609587929392839161;
const PRIME64_4: u64 = 9650029242287828579;
const PRIME64_5: u64 = 2870177450012600261;

#[derive(Copy,Clone,PartialEq)]
struct XxCore {
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
}

#[derive(Debug,Copy,Clone)]
pub struct XxHash {
    total_len: u64,
    seed: u64,
    core: XxCore,
    buffer: [u8; CHUNK_SIZE],
    buffer_usage: usize,
}

impl XxCore {
    fn from_seed(seed: u64) -> XxCore {
        XxCore {
            v1: seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2),
            v2: seed.wrapping_add(PRIME64_2),
            v3: seed,
            v4: seed.wrapping_sub(PRIME64_1),
        }
    }

    #[inline(always)]
    fn ingest_one_chunk(&mut self, bytes: &[u8]) {
        let mut rdr = Cursor::new(bytes);

        #[inline(always)]
        fn ingest_one_number<R>(mut current_value: u64, rdr: &mut R) -> u64
            where R: Read
        {
            let value = rdr.read_u64::<LittleEndian>().unwrap();
            let value = value.wrapping_mul(PRIME64_2);
            current_value = current_value.wrapping_add(value);
            current_value = current_value.rotate_left(31);
            current_value.wrapping_mul(PRIME64_1)
        };

        self.v1 = ingest_one_number(self.v1, &mut rdr);
        self.v2 = ingest_one_number(self.v2, &mut rdr);
        self.v3 = ingest_one_number(self.v3, &mut rdr);
        self.v4 = ingest_one_number(self.v4, &mut rdr);
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        let mut hash;

        hash =                   self.v1.rotate_left( 1);
        hash = hash.wrapping_add(self.v2.rotate_left( 7));
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

impl std::fmt::Debug for XxCore {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f, "XxCore {{ {:016x} {:016x} {:016x} {:016x} }}",
            self.v1, self.v2, self.v3, self.v4
        )
    }
}

impl XxHash {
    pub fn from_seed(seed: u64) -> XxHash {
        XxHash {
            total_len: 0,
            seed: seed,
            core: XxCore::from_seed(seed),
            buffer: [0; CHUNK_SIZE],
            buffer_usage: 0,
        }
    }
}

#[inline(always)]
fn split_at_maximum_chunk_size(bytes: &[u8], chunk_size: usize) -> (&[u8], &[u8]) {
    let full_chunks = bytes.len() / chunk_size;
    bytes.split_at(full_chunks * chunk_size)
}

impl XxHash {
    pub fn write(&mut self, bytes: &[u8]) {
        let mut bytes = bytes;

        self.total_len += bytes.len() as u64;

        // Even with new data, we still don't have a full buffer. Wait
        // until we have a full buffer.
        if self.buffer_usage + bytes.len() < self.buffer.len() {
            unsafe {
                let tail = self.buffer.as_mut_ptr().offset(self.buffer_usage as isize);
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
                let tail = self.buffer.as_mut_ptr().offset(self.buffer_usage as isize);
                std::ptr::copy_nonoverlapping(to_use.as_ptr(), tail, bytes_to_use);
            }

            self.core.ingest_one_chunk(&self.buffer);

            bytes = leftover;
            self.buffer_usage = 0;
        }

        // Consume the input data in large chunks
        if bytes.len() >= CHUNK_SIZE {
            // TODO: The original code pulls out local vars for
            // v[1234], presumably for performance
            // reasons. Investigate.

            let (to_use, leftover) = split_at_maximum_chunk_size(bytes, CHUNK_SIZE);

            for chunk in to_use.chunks(CHUNK_SIZE) {
                self.core.ingest_one_chunk(chunk);
            }

            bytes = leftover;
        }

        // Save any leftover data for the next call
        if bytes.len() > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer.as_mut_ptr(), bytes.len());
            }
            self.buffer_usage = bytes.len();
        }
    }

    pub fn finish(&self) -> u64 {
        let mut hash;

        // We have processed at least one full chunk
        if self.total_len >= CHUNK_SIZE as u64 {
            // TODO: The original code pulls out local vars for
            // v[1234], presumably for performance
            // reasons. Investigate.

            hash = self.core.finish();
        } else {
            hash = self.seed.wrapping_add(PRIME64_5);
        }

        hash = hash.wrapping_add(self.total_len);

        let buffered = &self.buffer[..self.buffer_usage];
        let (buffered_u64s, buffered) = split_at_maximum_chunk_size(buffered, 8);

        // TODO: Should we create the cursor out here and just iterate
        // until not enough?
        for buffered_u64 in buffered_u64s.chunks(8) {
            let mut rdr = Cursor::new(buffered_u64);
            let mut k1 = rdr.read_u64::<LittleEndian>().unwrap();
            k1 = k1.wrapping_mul(PRIME64_2);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(PRIME64_1);
            hash ^= k1;
            hash = hash.rotate_left(27);
            hash = hash.wrapping_mul(PRIME64_1);
            hash = hash.wrapping_add(PRIME64_4);
        }

        let (buffered_u32s, buffered) = split_at_maximum_chunk_size(buffered, 4);

        for buffered_u32 in buffered_u32s.chunks(4) {
            let mut rdr = Cursor::new(buffered_u32);
            let mut k1 = rdr.read_u32::<LittleEndian>().unwrap() as u64;
            k1 = k1.wrapping_mul(PRIME64_1);
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
        hash ^= hash.wrapping_shr(33);
        hash = hash.wrapping_mul(PRIME64_2);
        hash ^= hash.wrapping_shr(29);
        hash = hash.wrapping_mul(PRIME64_3);
        hash ^= hash.wrapping_shr(32);

        hash
    }
}

#[cfg(test)]
mod test {
    use super::XxHash;

    #[test]
    fn ingesting_byte_by_byte_is_equivalent_to_large_chunks() {
        let bytes: Vec<_> = (0..32).map(|_| 0).collect();

        let mut byte_by_byte = XxHash::from_seed(0);
        for byte in bytes.chunks(1) {
            byte_by_byte.write(byte);
        }

        let mut one_chunk = XxHash::from_seed(0);
        one_chunk.write(&bytes);

        assert_eq!(byte_by_byte.core, one_chunk.core);
    }

    #[test]
    fn hash_of_nothing_matches_c_implementation() {
        let mut hasher = XxHash::from_seed(0);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0xef46db3751d8e999);
    }

    #[test]
    fn hash_of_single_byte_matches_c_implementation() {
        let mut hasher = XxHash::from_seed(0);
        hasher.write(&[42]);
        assert_eq!(hasher.finish(), 0x0a9edecebeb03ae4);
    }

    #[test]
    fn hash_of_multiple_bytes_matches_c_implementation() {
        let mut hasher = XxHash::from_seed(0);
        hasher.write(b"Hello, world!\0");
        assert_eq!(hasher.finish(), 0x7b06c531ea43e89f);
    }

    #[test]
    fn hash_of_multiple_chunks_matches_c_implementation() {
        let bytes: Vec<_> = (0..100).collect();
        let mut hasher = XxHash::from_seed(0);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x6ac1e58032166597);
    }

    #[test]
    fn hash_with_different_seed_matches_c_implementation() {
        let mut hasher = XxHash::from_seed(0xae0543311b702d91);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0x4b6a04fcdf7a4672);
    }

    #[test]
    fn hash_with_different_seed_and_multiple_chunks_matches_c_implementation() {
        let bytes: Vec<_> = (0..100).collect();
        let mut hasher = XxHash::from_seed(0xae0543311b702d91);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x567e355e0682e1f1);
    }
}

#[cfg(test)]
mod bench {
    extern crate test;

    use super::XxHash;

    #[inline(always)]
    fn straight_line_slice_bench(b: &mut test::Bencher, len: usize) {
        let bytes: Vec<_> = (0..100).cycle().take(len).collect();
        b.bytes = bytes.len() as u64;
        b.iter(|| {
            let mut hasher = XxHash::from_seed(0);
            hasher.write(&bytes);
            hasher.finish()
        });
    }

    #[bench]
    fn straight_line_megabyte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 1024*1024);
    }

    #[bench]
    fn straight_line_1024_byte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 1024);
    }

    #[bench]
    fn straight_line_512_byte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 512);
    }

    #[bench]
    fn straight_line_256_byte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 256);
    }

    #[bench]
    fn straight_line_128_byte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 128);
    }

    #[bench]
    fn straight_line_32_byte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 32);
    }

    #[bench]
    fn straight_line_16_byte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 16);
    }

    #[bench]
    fn straight_line_4_byte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 4);
    }

    #[bench]
    fn straight_line_1_byte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 1);
    }

    #[bench]
    fn straight_line_0_byte(b: &mut test::Bencher) {
        straight_line_slice_bench(b, 0);
    }
}
