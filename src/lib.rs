extern crate byteorder;

use std::io::Cursor;
use byteorder::{LittleEndian,ReadBytesExt};

const CHUNK_SIZE: usize = 32;

const PRIME64_1: u64 = 11400714785074694791;
const PRIME64_2: u64 = 14029467366897019727;
const PRIME64_3: u64 = 1609587929392839161;
const PRIME64_4: u64 = 9650029242287828579;
const PRIME64_5: u64 = 2870177450012600261;

#[derive(Debug,Copy,Clone,PartialEq)]
struct XxCore {
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
}

#[derive(Debug,Copy,Clone)]
struct XxHash {
    total_len: u64,
    seed: u64,
    core: XxCore,
    buffer: [u8; CHUNK_SIZE],
    buffer_usage: usize,
}

impl XxCore {
    fn from_seed(seed: u64) -> XxCore {
        XxCore {
            v1: seed + PRIME64_1 + PRIME64_2,
            v2: seed + PRIME64_2,
            v3: seed + 0,
            v4: seed - PRIME64_1,
        }
    }

    #[inline(always)]
    fn ingest_one_chunk(&mut self, bytes: &[u8]) {
        let mut rdr = Cursor::new(bytes);

        let v = rdr.read_u64::<LittleEndian>().unwrap();
        self.v1 += v * PRIME64_2;
        self.v1 = self.v1.rotate_left(31);
        self.v1 *= PRIME64_1;

        let v = rdr.read_u64::<LittleEndian>().unwrap();
        self.v2 += v * PRIME64_2;
        self.v2 = self.v2.rotate_left(31);
        self.v2 *= PRIME64_1;

        let v = rdr.read_u64::<LittleEndian>().unwrap();
        self.v3 += v * PRIME64_2;
        self.v3 = self.v3.rotate_left(31);
        self.v3 *= PRIME64_1;

        let v = rdr.read_u64::<LittleEndian>().unwrap();
        self.v4 += v * PRIME64_2;
        self.v4 = self.v4.rotate_left(31);
        self.v4 *= PRIME64_1;
    }
}

impl XxHash {
    fn from_seed(seed: u64) -> XxHash {
        XxHash {
            total_len: 0,
            seed: seed,
            core: XxCore::from_seed(seed),
            buffer: [0; CHUNK_SIZE],
            buffer_usage: 0,
        }
    }
}

impl XxHash {
    fn write(&mut self, bytes: &[u8]) {
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
        if bytes.len() <= CHUNK_SIZE {
            // TODO: The original code pulls out local vars for
            // v[1234], presumably for performance
            // reasons. Investigate.

            let full_chunks = bytes.len() % CHUNK_SIZE;
            let (to_use, leftover) = bytes.split_at(full_chunks * CHUNK_SIZE);

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
}

#[cfg(test)]
mod test {
    use super::XxHash;

    #[test]
    fn it_works() {
        let mut byte_by_byte = XxHash::from_seed(0);
        let mut one_chunk = XxHash::from_seed(0);

        for _ in 0..32 {
            byte_by_byte.write(&[0]);
        }

        one_chunk.write(&[0; 32]);

        assert_eq!(byte_by_byte.core, one_chunk.core);
    }
}
