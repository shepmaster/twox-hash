use core::{fmt, hash::Hasher, mem};

use crate::{IntoU32, IntoU64};

// Keeping these constants in this form to match the C code.
const PRIME32_1: u32 = 0x9E3779B1;
const PRIME32_2: u32 = 0x85EBCA77;
const PRIME32_3: u32 = 0xC2B2AE3D;
const PRIME32_4: u32 = 0x27D4EB2F;
const PRIME32_5: u32 = 0x165667B1;

type Lane = u32;
type Lanes = [Lane; 4];
type Bytes = [u8; 16];

const BYTES_IN_LANE: usize = mem::size_of::<Bytes>();

#[derive(PartialEq)]
struct BufferData(Lanes);

impl BufferData {
    const fn new() -> Self {
        Self([0; 4])
    }

    const fn bytes(&self) -> &Bytes {
        const _: () = assert!(mem::align_of::<u8>() <= mem::align_of::<Lane>());
        // SAFETY[bytes]: The alignment of `u32` is at least that of
        // `u8` and all the values are initialized.
        unsafe { &*self.0.as_ptr().cast() }
    }

    fn bytes_mut(&mut self) -> &mut Bytes {
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

    fn extend<'d>(&mut self, data: &'d [u8]) -> (Option<&Lanes>, &'d [u8]) {
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
struct Accumulators(Lanes);

impl Accumulators {
    const fn new(seed: u32) -> Self {
        Self([
            seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2),
            seed.wrapping_add(PRIME32_2),
            seed,
            seed.wrapping_sub(PRIME32_1),
        ])
    }

    fn write(&mut self, lanes: Lanes) {
        let [acc1, acc2, acc3, acc4] = &mut self.0;
        let [lane1, lane2, lane3, lane4] = lanes;

        *acc1 = round(*acc1, lane1.to_le());
        *acc2 = round(*acc2, lane2.to_le());
        *acc3 = round(*acc3, lane3.to_le());
        *acc4 = round(*acc4, lane4.to_le());
    }

    fn write_many<'d>(&mut self, mut data: &'d [u8]) -> &'d [u8] {
        while let Some((chunk, rest)) = data.split_first_chunk::<BYTES_IN_LANE>() {
            // SAFETY: We have the right number of bytes and are
            // handling the unaligned case.
            let lanes = unsafe { chunk.as_ptr().cast::<Lanes>().read_unaligned() };
            self.write(lanes);
            data = rest;
        }
        data
    }

    const fn finish(&self) -> u32 {
        let [acc1, acc2, acc3, acc4] = self.0;

        let acc1 = acc1.rotate_left(1);
        let acc2 = acc2.rotate_left(7);
        let acc3 = acc3.rotate_left(12);
        let acc4 = acc4.rotate_left(18);

        acc1.wrapping_add(acc2)
            .wrapping_add(acc3)
            .wrapping_add(acc4)
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
pub struct XxHash32 {
    seed: u32,
    accumulators: Accumulators,
    buffer: Buffer,
    length: u64,
}

impl Default for XxHash32 {
    fn default() -> Self {
        Self::with_seed(0)
    }
}

impl XxHash32 {
    /// Hash all data at once. If you can use this function, you may
    /// see noticable speed gains for certain types of input.
    #[must_use]
    // RATIONALE[inline]: Keeping parallel to the XxHash64
    // implementation, even though the performance gains for XxHash32
    // haven't been tested.
    #[inline]
    pub fn oneshot(seed: u32, data: &[u8]) -> u32 {
        let len = data.len();

        // Since we know that there's no more data coming, we don't
        // need to construct the intermediate buffers or copy data to
        // or from the buffers.

        let mut accumulators = Accumulators::new(seed);

        let data = accumulators.write_many(data);

        Self::finish_with(seed, len.into_u64(), &accumulators, data)
    }

    #[must_use]
    pub const fn with_seed(seed: u32) -> Self {
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
    pub fn finish_32(&self) -> u32 {
        Self::finish_with(
            self.seed,
            self.length,
            &self.accumulators,
            self.buffer.remaining(),
        )
    }

    #[must_use]
    // RATIONALE: See RATIONALE[inline]
    #[inline(always)]
    fn finish_with(seed: u32, len: u64, accumulators: &Accumulators, mut remaining: &[u8]) -> u32 {
        // Step 3. Accumulator convergence
        let mut acc = if len < BYTES_IN_LANE.into_u64() {
            seed.wrapping_add(PRIME32_5)
        } else {
            accumulators.finish()
        };

        // Step 4. Add input length
        //
        // "Note that, if input length is so large that it requires
        // more than 32-bits, only the lower 32-bits are added to the
        // accumulator."
        acc += len as u32;

        // Step 5. Consume remaining input
        while let Some((chunk, rest)) = remaining.split_first_chunk::<{ mem::size_of::<u32>() }>() {
            let lane = u32::from_ne_bytes(*chunk).to_le();

            acc = acc.wrapping_add(lane.wrapping_mul(PRIME32_3));
            acc = acc.rotate_left(17).wrapping_mul(PRIME32_4);

            remaining = rest;
        }

        while let Some((chunk, rest)) = remaining.split_first_chunk::<{ mem::size_of::<u8>() }>() {
            let lane = chunk[0].into_u32();

            acc = acc.wrapping_add(lane.wrapping_mul(PRIME32_5));
            acc = acc.rotate_left(11).wrapping_mul(PRIME32_1);

            remaining = rest;
        }

        // Step 6. Final mix (avalanche)
        acc ^= acc >> 15;
        acc = acc.wrapping_mul(PRIME32_2);
        acc ^= acc >> 13;
        acc = acc.wrapping_mul(PRIME32_3);
        acc ^= acc >> 16;

        acc
    }
}

impl Hasher for XxHash32 {
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
        XxHash32::finish_32(self).into()
    }
}

const fn round(mut acc: u32, lane: u32) -> u32 {
    acc = acc.wrapping_add(lane.wrapping_mul(PRIME32_2));
    acc = acc.rotate_left(13);
    acc.wrapping_mul(PRIME32_1)
}

#[cfg(test)]
mod test {
    use core::array;

    use super::*;

    #[test]
    fn ingesting_byte_by_byte_is_equivalent_to_large_chunks() {
        let bytes = [0; 32];

        let mut byte_by_byte = XxHash32::with_seed(0);
        for byte in bytes.chunks(1) {
            byte_by_byte.write(byte);
        }
        let byte_by_byte = byte_by_byte.finish();

        let mut one_chunk = XxHash32::with_seed(0);
        one_chunk.write(&bytes);
        let one_chunk = one_chunk.finish();

        assert_eq!(byte_by_byte, one_chunk);
    }

    #[test]
    fn hash_of_nothing_matches_c_implementation() {
        let mut hasher = XxHash32::with_seed(0);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0x02cc_5d05);
    }

    #[test]
    fn hash_of_single_byte_matches_c_implementation() {
        let mut hasher = XxHash32::with_seed(0);
        hasher.write(&[42]);
        assert_eq!(hasher.finish(), 0xe0fe_705f);
    }

    #[test]
    fn hash_of_multiple_bytes_matches_c_implementation() {
        let mut hasher = XxHash32::with_seed(0);
        hasher.write(b"Hello, world!\0");
        assert_eq!(hasher.finish(), 0x9e5e_7e93);
    }

    #[test]
    fn hash_of_multiple_chunks_matches_c_implementation() {
        let bytes: [u8; 100] = array::from_fn(|i| i as u8);
        let mut hasher = XxHash32::with_seed(0);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x7f89_ba44);
    }

    #[test]
    fn hash_with_different_seed_matches_c_implementation() {
        let mut hasher = XxHash32::with_seed(0x42c9_1977);
        hasher.write(&[]);
        assert_eq!(hasher.finish(), 0xd6bf_8459);
    }

    #[test]
    fn hash_with_different_seed_and_multiple_chunks_matches_c_implementation() {
        let bytes: [u8; 100] = array::from_fn(|i| i as u8);
        let mut hasher = XxHash32::with_seed(0x42c9_1977);
        hasher.write(&bytes);
        assert_eq!(hasher.finish(), 0x6d2f_6c17);
    }
}
