#![no_std]
#![deny(rust_2018_idioms)]

use core::mem;

const PRIME64_1: u64 = 0x9E3779B185EBCA87;
const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME64_3: u64 = 0x165667B19E3779F9;
const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
const PRIME64_5: u64 = 0x27D4EB2F165667C5;

#[repr(align(32))]
struct AlignedData([u8; 32]);

impl AlignedData {
    const fn new() -> Self {
        Self([0; 32])
    }

    const fn as_u64s(&self) -> &[u64; 4] {
        // SAFETY: We are guaranteed to be aligned
        unsafe { mem::transmute(&self.0) }
    }
}

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
        if self.offset == 0 {
            return (None, data);
        };

        let (_filled, empty) = self.data.0.split_at_mut(self.offset); // todo unchecked?
        let n_to_copy = usize::min(empty.len(), data.len());

        let dst = &mut empty[..n_to_copy];
        let (src, rest) = data.split_at(n_to_copy);

        dst.copy_from_slice(src);
        self.offset += n_to_copy;

        if self.offset == self.data.0.len() {
            (Some(self.data.as_u64s()), rest)
        } else {
            (None, rest)
        }
    }

    fn set(&mut self, data: &[u8]) {
        let n_to_copy = data.len();

        debug_assert!(n_to_copy < self.data.0.len());

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
        // todo: little-endian transform

        *acc1 = round(*acc1, lane1);
        *acc2 = round(*acc2, lane2);
        *acc3 = round(*acc3, lane3);
        *acc4 = round(*acc4, lane4);
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

pub struct XxHash64 {
    seed: u64,
    accumulators: Accumulators,
    buffer: Buffer,
    length: u64,
}

impl XxHash64 {
    pub fn oneshot(seed: u64, data: &[u8]) -> u64 {
        let mut this = Self::with_seed(seed);
        this.write(data);
        this.finish()
    }

    pub const fn with_seed(seed: u64) -> Self {
        // Step 1. Initialize internal accumulators

        Self {
            seed,
            accumulators: Accumulators::new(seed),
            buffer: Buffer::new(),
            length: 0,
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        let len = data.len();

        // Step 2. Process stripes
        let (buffered_lanes, data) = self.buffer.extend(data);

        if let Some(&lanes) = buffered_lanes {
            self.accumulators.write(lanes);
        }

        let mut data = data;
        while let Some((chunk, rest)) = data.split_first_chunk::<32>() {
            // SAFETY: We have the right number of bytes and are
            // handling the unaligned case.
            let lanes = unsafe { chunk.as_ptr().cast::<[u64; 4]>().read_unaligned() };
            self.accumulators.write(lanes);
            data = rest;
        }
        let data = data;

        self.buffer.set(data);

        self.length += len.into_u64();
    }

    pub fn finish(&mut self) -> u64 {
        // Step 3. Accumulator convergence
        let mut acc = if self.length < 32 {
            self.seed.wrapping_add(PRIME64_5)
        } else {
            self.accumulators.finish()
        };

        // Step 4. Add input length
        acc += self.length;

        // Step 5. Consume remaining input
        let mut remaining = self.buffer.remaining();

        while let Some((chunk, rest)) = remaining.split_first_chunk::<8>() {
            let lane = u64::from_ne_bytes(*chunk);
            // todo: little-endian

            acc ^= round(0, lane);
            acc = acc.rotate_left(27).wrapping_mul(PRIME64_1);
            acc = acc.wrapping_add(PRIME64_4);
            remaining = rest;
        }

        while let Some((chunk, rest)) = remaining.split_first_chunk::<4>() {
            let lane = u32::from_ne_bytes(*chunk).into_u64();
            // todo: little-endian

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
    use super::*;

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
    fn hash_of_exactly_32_bytes() {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(&[0; 32]);
        assert_eq!(hasher.finish(), 0xf6e9_be5d_7063_2cf5);
    }
}
