use std;
use rand;

use std::hash::{Hasher, BuildHasher};
use rand::Rng;
use number_streams::NumberStreams;

const CHUNK_SIZE: usize = 16;

const PRIME_1: u32 = 2654435761;
const PRIME_2: u32 = 2246822519;
const PRIME_3: u32 = 3266489917;
const PRIME_4: u32 =  668265263;
const PRIME_5: u32 =  374761393;

#[derive(Copy,Clone,PartialEq)]
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
#[derive(Debug,Copy,Clone)]
pub struct XxHash {
    total_len: u32,
    seed: u32,
    core: XxCore,
    buffer: [u8; CHUNK_SIZE],
    buffer_usage: usize,
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
    fn ingest_chunks<I>(&mut self, values: I)
        where I: Iterator<Item=u32>
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

        hash =                   self.v1.rotate_left( 1);
        hash = hash.wrapping_add(self.v2.rotate_left( 7));
        hash = hash.wrapping_add(self.v3.rotate_left(12));
        hash = hash.wrapping_add(self.v4.rotate_left(18));

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
    /// Constructs the hash with an initial seed
    pub fn with_seed(seed: u32) -> XxHash {
        XxHash {
            total_len: 0,
            seed: seed,
            core: XxCore::with_seed(seed),
            buffer: unsafe { ::std::mem::uninitialized() },
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

        self.total_len += bytes.len() as u32;

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

            let (iter, _) = self.buffer.u32_stream();

            self.core.ingest_chunks(iter);

            bytes = leftover;
            self.buffer_usage = 0;
        }

        // Consume the input data in large chunks
        let (iter, bytes) = bytes.u32_stream_with_stride(4);
        self.core.ingest_chunks(iter);

        // Save any leftover data for the next call
        if bytes.len() > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer.as_mut_ptr(), bytes.len());
            }
            self.buffer_usage = bytes.len();
        }
    }

    fn finish(&self) -> u64 { // NODIFF
        let mut hash;

        // We have processed at least one full chunk
        if self.total_len >= CHUNK_SIZE as u32 {
            hash = self.core.finish();
        } else {
            hash = self.seed.wrapping_add(PRIME_5);
        }

        hash = hash.wrapping_add(self.total_len);

        let buffered = &self.buffer[..self.buffer_usage];
        let (buffered_u32s, buffered) = buffered.u32_stream();

        for k1 in buffered_u32s {
            let k1 = k1.wrapping_mul(PRIME_3);
            hash = hash.wrapping_add(k1);
            hash = hash.rotate_left(17);
            hash = hash.wrapping_mul(PRIME_4);
        }

        for buffered_u8 in buffered {
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

#[derive(Clone)]
/// Constructs a randomized seed and reuses it for multiple hasher instances. See the usage warning on `XxHash32`.
pub struct RandomXxHashBuilder(u32);

impl RandomXxHashBuilder {
    fn new() -> RandomXxHashBuilder {
        RandomXxHashBuilder(rand::thread_rng().gen())
    }
}

impl Default for RandomXxHashBuilder {
    fn default() -> RandomXxHashBuilder { RandomXxHashBuilder::new() }
}

impl BuildHasher for RandomXxHashBuilder {
    type Hasher = XxHash;

    fn build_hasher(&self) -> XxHash { XxHash::with_seed(self.0) }
}

#[cfg(test)]
mod test {
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
}
