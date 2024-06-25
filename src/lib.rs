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

#[repr(align(32))]
struct AlignedData([u8; Self::LEN]);

impl AlignedData {
    const LEN: usize = 32;

    const fn new() -> Self {
        Self([0; Self::LEN])
    }

    const fn len(&self) -> usize {
        Self::LEN
    }

    const fn as_u64s(&self) -> &[u64; 4] {
        // SAFETY: We are guaranteed to be aligned
        unsafe { mem::transmute(&self.0) }
    }
}

impl fmt::Debug for AlignedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

#[derive(Debug)]
struct Buffer {
    offset: usize,
    data: AlignedData,
}

impl Buffer {
    const fn new() -> Self {
        Self {
            offset: 0,
            data: AlignedData::new(),
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

        debug_assert!(self.offset <= self.data.len());

        if self.offset == 0 {
            return (None, data);
        };

        let empty = &mut self.data.0[self.offset..];
        let n_to_copy = usize::min(empty.len(), data.len());

        let dst = &mut empty[..n_to_copy];

        let (src, rest) = data.split_at(n_to_copy);

        dst.copy_from_slice(src);
        self.offset += n_to_copy;

        debug_assert!(self.offset <= self.data.len());

        if self.offset == self.data.len() {
            self.offset = 0;
            (Some(self.data.as_u64s()), rest)
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

        debug_assert!(n_to_copy < self.data.len());

        self.data.0[..n_to_copy].copy_from_slice(data);
        self.offset = data.len();
    }

    fn remaining(&self) -> &[u8] {
        &self.data.0[..self.offset]
    }
}

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

#[derive(Debug)]
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
    pub fn oneshot(seed: u64, data: &[u8]) -> u64 {
        let len = data.len();

        // Notably, since we know that there's no more data coming, we
        // don't need to construct the intermediate buffers or copy
        // data to / from them.

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
