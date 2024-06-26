#![no_std]
#![deny(rust_2018_idioms)]

#[cfg(test)]
extern crate std;

use core::{fmt, hash::Hasher, mem};

// Keeping these constants in this form to match the C code.
const PRIME64_1: u64 = 0x9E3779B185EBCA87;
const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME64_3: u64 = 0x165667B19E3779F9;
const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
const PRIME64_5: u64 = 0x27D4EB2F165667C5;

#[derive(PartialEq)]
struct BufferData([u64; 4]);

impl BufferData {
    const fn new() -> Self {
        Self([0; 4])
    }

    fn bytes(&self) -> &[u8; 32] {
        const { assert!(mem::align_of::<u8>() <= mem::align_of::<u64>()) }
        // SAFETY[bytes]: The alignment of `u64` is at least that of
        // `u8` and all the values are initialized.
        unsafe { &*self.0.as_ptr().cast() }
    }

    fn bytes_mut(&mut self) -> &mut [u8; 32] {
        // SAFETY: See SAFETY[bytes]
        unsafe { &mut *self.0.as_mut_ptr().cast() }
    }
}

impl fmt::Debug for BufferData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

#[derive(Debug, PartialEq)]
struct Buffer {
    offset: usize,
    data: BufferData,
}

impl Buffer {
    const fn new() -> Self {
        Self {
            offset: 0,
            data: BufferData::new(),
        }
    }

    fn extend<'d>(&mut self, data: &'d [u8]) -> (Option<&[u64; 4]>, &'d [u8]) {
        // Most of the slice methods we use here have `_unchecked` variants, but
        //
        // 1. this method is called one time per `XxHash64::write` call
        // 2. this method early exits if we don't have anything in the buffer
        //
        // Because of this, removing the panics via `unsafe` doesn't
        // have much benefit other than reducing code size by a tiny
        // bit.

        if self.offset == 0 {
            return (None, data);
        };

        let bytes = self.data.bytes_mut();
        debug_assert!(self.offset <= bytes.len());

        let empty = &mut bytes[self.offset..];
        let n_to_copy = usize::min(empty.len(), data.len());

        let dst = &mut empty[..n_to_copy];

        let (src, rest) = data.split_at(n_to_copy);

        dst.copy_from_slice(src);
        self.offset += n_to_copy;

        debug_assert!(self.offset <= bytes.len());

        if self.offset == bytes.len() {
            self.offset = 0;
            (Some(&self.data.0), rest)
        } else {
            (None, rest)
        }
    }

    fn set(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        debug_assert_eq!(self.offset, 0);

        let n_to_copy = data.len();

        let bytes = self.data.bytes_mut();
        debug_assert!(n_to_copy < bytes.len());

        bytes[..n_to_copy].copy_from_slice(data);
        self.offset = data.len();
    }

    fn remaining(&self) -> &[u8] {
        &self.data.bytes()[..self.offset]
    }
}

#[derive(PartialEq)]
struct Accumulators([u64; 4]);

impl Accumulators {
    const fn new(seed: u64) -> Self {
        Self([
            seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2),
            seed.wrapping_add(PRIME64_2),
            seed,
            seed.wrapping_sub(PRIME64_1),
        ])
    }

    fn write(&mut self, lanes: [u64; 4]) {
        let [acc1, acc2, acc3, acc4] = &mut self.0;
        let [lane1, lane2, lane3, lane4] = lanes;

        *acc1 = round(*acc1, lane1.to_le());
        *acc2 = round(*acc2, lane2.to_le());
        *acc3 = round(*acc3, lane3.to_le());
        *acc4 = round(*acc4, lane4.to_le());
    }

    fn write_many<'d>(&mut self, mut data: &'d [u8]) -> &'d [u8] {
        while let Some((chunk, rest)) = data.split_first_chunk::<32>() {
            // SAFETY: We have the right number of bytes and are
            // handling the unaligned case.
            let lanes = unsafe { chunk.as_ptr().cast::<[u64; 4]>().read_unaligned() };
            self.write(lanes);
            data = rest;
        }
        data
    }

    const fn finish(&self) -> u64 {
        let [acc1, acc2, acc3, acc4] = self.0;

        let mut acc = {
            let acc1 = acc1.rotate_left(1);
            let acc2 = acc2.rotate_left(7);
            let acc3 = acc3.rotate_left(12);
            let acc4 = acc4.rotate_left(18);

            acc1.wrapping_add(acc2)
                .wrapping_add(acc3)
                .wrapping_add(acc4)
        };

        acc = Self::merge_accumulator(acc, acc1);
        acc = Self::merge_accumulator(acc, acc2);
        acc = Self::merge_accumulator(acc, acc3);
        acc = Self::merge_accumulator(acc, acc4);

        acc
    }

    const fn merge_accumulator(mut acc: u64, acc_n: u64) -> u64 {
        acc ^= round(0, acc_n);
        acc = acc.wrapping_mul(PRIME64_1);
        acc.wrapping_add(PRIME64_4)
    }
}

impl fmt::Debug for Accumulators {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [acc1, acc2, acc3, acc4] = self.0;
        f.debug_struct("Accumulators")
            .field("acc1", &acc1)
            .field("acc2", &acc2)
            .field("acc3", &acc3)
            .field("acc4", &acc4)
            .finish()
    }
}

#[derive(Debug, PartialEq)]
pub struct XxHash64 {
    seed: u64,
    accumulators: Accumulators,
    buffer: Buffer,
    length: u64,
}

impl Default for XxHash64 {
    fn default() -> Self {
        Self::with_seed(0)
    }
}

impl XxHash64 {
    /// Hash all data at once. If you can use this function, you may
    /// see noticable speed gains for certain types of input.
    #[must_use]
    // RATIONALE[inline]: In one case [1], this `inline` helps unlock a
    // speedup from ~900µs to ~200µs.
    //
    // [1]: https://github.com/apache/datafusion-comet/pull/575
    #[inline]
    pub fn oneshot(seed: u64, data: &[u8]) -> u64 {
        let len = data.len();

        // Since we know that there's no more data coming, we don't
        // need to construct the intermediate buffers or copy data to
        // or from the buffers.

        let mut accumulators = Accumulators::new(seed);

        let data = accumulators.write_many(data);

        Self::finish_with(seed, len.into_u64(), &accumulators, data)
    }

    #[must_use]
    pub const fn with_seed(seed: u64) -> Self {
        // Step 1. Initialize internal accumulators
        Self {
            seed,
            accumulators: Accumulators::new(seed),
            buffer: Buffer::new(),
            length: 0,
        }
    }

    #[must_use]
    // RATIONALE: See RATIONALE[inline]
    #[inline(always)]
    fn finish_with(seed: u64, len: u64, accumulators: &Accumulators, mut remaining: &[u8]) -> u64 {
        // Step 3. Accumulator convergence
        let mut acc = if len < 32 {
            seed.wrapping_add(PRIME64_5)
        } else {
            accumulators.finish()
        };

        // Step 4. Add input length
        acc += len;

        // Step 5. Consume remaining input
        while let Some((chunk, rest)) = remaining.split_first_chunk::<8>() {
            let lane = u64::from_ne_bytes(*chunk).to_le();

            acc ^= round(0, lane);
            acc = acc.rotate_left(27).wrapping_mul(PRIME64_1);
            acc = acc.wrapping_add(PRIME64_4);
            remaining = rest;
        }

        while let Some((chunk, rest)) = remaining.split_first_chunk::<4>() {
            let lane = u32::from_ne_bytes(*chunk).to_le().into_u64();

            acc ^= lane.wrapping_mul(PRIME64_1);
            acc = acc.rotate_left(23).wrapping_mul(PRIME64_2);
            acc = acc.wrapping_add(PRIME64_3);

            remaining = rest;
        }

        while let Some((chunk, rest)) = remaining.split_first_chunk::<1>() {
            let lane = chunk[0].into_u64();

            acc ^= lane.wrapping_mul(PRIME64_5);
            acc = acc.rotate_left(11).wrapping_mul(PRIME64_1);

            remaining = rest;
        }

        // Step 6. Final mix (avalanche)
        acc ^= acc >> 33;
        acc = acc.wrapping_mul(PRIME64_2);
        acc ^= acc >> 29;
        acc = acc.wrapping_mul(PRIME64_3);
        acc ^= acc >> 32;

        acc
    }
}

impl Hasher for XxHash64 {
    fn write(&mut self, data: &[u8]) {
        let len = data.len();

        // Step 2. Process stripes
        let (buffered_lanes, data) = self.buffer.extend(data);

        if let Some(&lanes) = buffered_lanes {
            self.accumulators.write(lanes);
        }

        let data = self.accumulators.write_many(data);

        self.buffer.set(data);

        self.length += len.into_u64();
    }

    #[must_use]
    fn finish(&self) -> u64 {
        Self::finish_with(
            self.seed,
            self.length,
            &self.accumulators,
            self.buffer.remaining(),
        )
    }
}

const fn round(mut acc: u64, lane: u64) -> u64 {
    acc = acc.wrapping_add(lane.wrapping_mul(PRIME64_2));
    acc = acc.rotate_left(31);
    acc.wrapping_mul(PRIME64_1)
}

trait IntoU64 {
    fn into_u64(self) -> u64;
}

impl IntoU64 for u8 {
    fn into_u64(self) -> u64 {
        self.into()
    }
}

impl IntoU64 for u32 {
    fn into_u64(self) -> u64 {
        self.into()
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl IntoU64 for usize {
    fn into_u64(self) -> u64 {
        self as u64
    }
}

#[cfg(test)]
mod test {
    use core::array;

    use super::*;

    #[test]
    fn ingesting_byte_by_byte_is_equivalent_to_large_chunks() {
        let bytes = [0x9c; 32];

        let mut byte_by_byte = XxHash64::with_seed(0);
        for byte in bytes.chunks(1) {
            byte_by_byte.write(byte);
        }
        let byte_by_byte = byte_by_byte.finish();

        let mut one_chunk = XxHash64::with_seed(0);
        one_chunk.write(&bytes);
        let one_chunk = one_chunk.finish();

        assert_eq!(byte_by_byte, one_chunk);
    }

    #[test]
    fn hash_of_nothing_matches_c_implementation() {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0xef46_db37_51d8_e999);
    }

    #[test]
    fn hash_of_single_byte_matches_c_implementation() {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(&[42]);
        assert_eq!(hasher.finish(), 0x0a9e_dece_beb0_3ae4);
    }

    #[test]
    fn hash_of_multiple_bytes_matches_c_implementation() {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(b"Hello, world!\0");
        assert_eq!(hasher.finish(), 0x7b06_c531_ea43_e89f);
    }

    #[test]
    fn hash_of_multiple_chunks_matches_c_implementation() {
        let bytes: [u8; 100] = array::from_fn(|i| i as u8);
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x6ac1_e580_3216_6597);
    }

    #[test]
    fn hash_with_different_seed_matches_c_implementation() {
        let mut hasher = XxHash64::with_seed(0xae05_4331_1b70_2d91);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0x4b6a_04fc_df7a_4672);
    }

    #[test]
    fn hash_with_different_seed_and_multiple_chunks_matches_c_implementation() {
        let bytes: [u8; 100] = array::from_fn(|i| i as u8);
        let mut hasher = XxHash64::with_seed(0xae05_4331_1b70_2d91);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x567e_355e_0682_e1f1);
    }
}

#[cfg(feature = "std")]
mod std_impl {
    use core::hash::BuildHasher;

    use super::*;

    pub struct RandomXxHashBuilder64(u64);

    impl Default for RandomXxHashBuilder64 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RandomXxHashBuilder64 {
        fn new() -> Self {
            Self(rand::random())
        }
    }

    impl BuildHasher for RandomXxHashBuilder64 {
        type Hasher = XxHash64;

        fn build_hasher(&self) -> Self::Hasher {
            XxHash64::with_seed(self.0)
        }
    }

    #[cfg(test)]
    mod test {
        use core::hash::BuildHasherDefault;
        use std::collections::HashMap;

        use super::*;

        #[test]
        fn can_be_used_in_a_hashmap_with_a_default_seed() {
            let mut hash: HashMap<_, _, BuildHasherDefault<XxHash64>> = Default::default();
            hash.insert(42, "the answer");
            assert_eq!(hash.get(&42), Some(&"the answer"));
        }

        #[test]
        fn can_be_used_in_a_hashmap_with_a_random_seed() {
            let mut hash: HashMap<_, _, RandomXxHashBuilder64> = Default::default();
            hash.insert(42, "the answer");
            assert_eq!(hash.get(&42), Some(&"the answer"));
        }
    }
}

#[cfg(feature = "std")]
pub use std_impl::RandomXxHashBuilder64;

#[cfg(feature = "serialize")]
mod serialize_impl {
    use serde::{Deserialize, Serialize};

    use super::*;

    impl<'de> Deserialize<'de> for XxHash64 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let shim = Deserialize::deserialize(deserializer)?;

            let Shim {
                total_len,
                seed,
                core,
                buffer,
                buffer_usage,
            } = shim;
            let Core { v1, v2, v3, v4 } = core;

            Ok(XxHash64 {
                seed,
                accumulators: Accumulators([v1, v2, v3, v4]),
                buffer: Buffer {
                    offset: buffer_usage,
                    data: AlignedData(buffer),
                },
                length: total_len,
            })
        }
    }

    impl Serialize for XxHash64 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let XxHash64 {
                seed,
                ref accumulators,
                ref buffer,
                length,
            } = *self;
            let [v1, v2, v3, v4] = accumulators.0;
            let Buffer { offset, ref data } = *buffer;

            let shim = Shim {
                total_len: length,
                seed,
                core: Core { v1, v2, v3, v4 },
                buffer: data.0,
                buffer_usage: offset,
            };

            shim.serialize(serializer)
        }
    }

    #[derive(Serialize, Deserialize)]
    struct Shim {
        total_len: u64,
        seed: u64,
        core: Core,
        buffer: [u8; 32],
        buffer_usage: usize,
    }

    #[derive(Serialize, Deserialize)]
    struct Core {
        v1: u64,
        v2: u64,
        v3: u64,
        v4: u64,
    }

    #[cfg(test)]
    mod test {
        use super::*;

        type Result<T = (), E = serde_json::Error> = core::result::Result<T, E>;

        #[test]
        fn test_serialization_cycle() -> Result {
            let mut hasher = XxHash64::with_seed(0);
            hasher.write(b"Hello, world!\0");
            hasher.finish();

            let serialized = serde_json::to_string(&hasher)?;
            let unserialized: XxHash64 = serde_json::from_str(&serialized)?;
            assert_eq!(hasher, unserialized);
            Ok(())
        }

        #[test]
        fn test_serialization_stability() -> Result {
            let mut hasher = XxHash64::with_seed(0);
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

            let unserialized: XxHash64 = serde_json::from_str(serialized).unwrap();
            assert_eq!(hasher, unserialized);
            Ok(())
        }
    }
}
