#![allow(missing_docs, dead_code, non_snake_case)]

use core::{mem, slice};

use crate::{IntoU128, IntoU32, IntoU64};

const PRIME32_1: u64 = 0x9E3779B1;
const PRIME32_2: u64 = 0x85EBCA77;
const PRIME32_3: u64 = 0xC2B2AE3D;
const PRIME64_1: u64 = 0x9E3779B185EBCA87;
const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME64_3: u64 = 0x165667B19E3779F9;
const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
const PRIME64_5: u64 = 0x27D4EB2F165667C5;
const PRIME_MX1: u64 = 0x165667919E3779F9;
const PRIME_MX2: u64 = 0x9FB21C651E98DF25;

const DEFAULT_SECRET: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

pub struct XxHash3_64;

type Stripe = [u64; 8];

impl XxHash3_64 {
    #[inline(never)]
    pub fn oneshot(input: &[u8]) -> u64 {
        let seed = 0;
        let secret = DEFAULT_SECRET;

        match input.len() {
            0 => {
                let secret_words =
                    unsafe { secret.as_ptr().add(56).cast::<[u64; 2]>().read_unaligned() };
                avalanche_xxh64(seed ^ secret_words[0] ^ secret_words[1])
            }

            1..=3 => {
                let input_length = input.len() as u8; // OK as we checked that the length fits

                let combined = input[input.len() - 1].into_u32()
                    | input_length.into_u32() << 8
                    | input[0].into_u32() << 16
                    | input[input.len() >> 1].into_u32() << 24;

                let secret_words = unsafe { secret.as_ptr().cast::<[u32; 2]>().read_unaligned() };
                let value =
                    ((secret_words[0] ^ secret_words[1]).into_u64() + seed) ^ combined.into_u64();

                // FUTURE: TEST: "Note that the XXH3-64 result is the lower half of XXH3-128 result."
                avalanche_xxh64(value)
            }

            4..=8 => {
                let input_first = unsafe { input.as_ptr().cast::<u32>().read_unaligned() };
                let input_last = unsafe {
                    input
                        .as_ptr()
                        .add(input.len())
                        .sub(mem::size_of::<u32>())
                        .cast::<u32>()
                        .read_unaligned()
                };
                let modified_seed = seed ^ (seed.lower_half().swap_bytes().into_u64() << 32);

                let secret_words =
                    unsafe { secret.as_ptr().add(8).cast::<[u64; 2]>().read_unaligned() };
                let combined = input_last.into_u64() | (input_first.into_u64() << 32);

                let mut value = ((secret_words[0] ^ secret_words[1]) - modified_seed) ^ combined;
                value ^= value.rotate_left(49) ^ value.rotate_left(24);
                value = value.wrapping_mul(PRIME_MX2);
                value ^= (value >> 35).wrapping_add(input.len().into_u64());
                value = value.wrapping_mul(PRIME_MX2);
                value ^= value >> 28;
                value
            }

            9..=16 => {
                let input_first = unsafe { input.as_ptr().cast::<u64>().read_unaligned() };
                let input_last = unsafe {
                    input
                        .as_ptr()
                        .add(input.len())
                        .sub(mem::size_of::<u64>())
                        .cast::<u64>()
                        .read_unaligned()
                };

                let secret_words =
                    unsafe { secret.as_ptr().add(24).cast::<[u64; 4]>().read_unaligned() };
                let low = ((secret_words[0] ^ secret_words[1]).wrapping_add(seed)) ^ input_first;
                let high = ((secret_words[2] ^ secret_words[3]).wrapping_sub(seed)) ^ input_last;
                let mul_result = low.into_u128().wrapping_mul(high.into_u128());
                let value = input
                    .len()
                    .into_u64()
                    .wrapping_add(low.swap_bytes())
                    .wrapping_add(high)
                    .wrapping_add(mul_result.lower_half() ^ mul_result.upper_half());

                avalanche(value)
            }

            17..=128 => {
                let mut acc = input.len().into_u64().wrapping_mul(PRIME64_1);

                let num_rounds = ((input.len() - 1) >> 5) + 1;

                let (fwd, _) = input.bp_as_chunks();
                let (_, bwd) = input.bp_as_rchunks();

                let fwd = fwd.iter();
                let bwd = bwd.iter().rev();

                for (i, (fwd_chunk, bwd_chunk)) in fwd.zip(bwd).enumerate().take(num_rounds) {
                    acc = acc.wrapping_add(mix_step(fwd_chunk, &secret, i * 32, seed));
                    acc = acc.wrapping_add(mix_step(bwd_chunk, &secret, i * 32 + 16, seed));
                }

                avalanche(acc)
            }

            129..=240 => {
                let mut acc = input.len().into_u64().wrapping_mul(PRIME64_1);

                let (head, _tail) = input.bp_as_chunks();
                let mut head = head.iter();

                for (i, chunk) in head.by_ref().take(8).enumerate() {
                    acc = acc.wrapping_add(mix_step(chunk, &secret, i * 16, seed));
                }

                acc = avalanche(acc);

                for (i, chunk) in head.enumerate() {
                    acc = acc.wrapping_add(mix_step(chunk, &secret, i * 16 + 3, seed));
                }

                acc = acc.wrapping_add(mix_step(input.last_chunk().unwrap(), &secret, 119, seed));

                avalanche(acc)
            }

            _ => {
                #[rustfmt::skip]
                let mut acc = [
                    PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3,
                    PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1,
                ];

                let stripes_per_block = (secret.len() - 64) / 8;
                let block_size = 64 * stripes_per_block;

                let mut blocks = input.chunks(block_size).fuse();
                let last_block = blocks.next_back().unwrap();

                for block in blocks {
                    round(&mut acc, block, &secret);
                }

                let last_stripe = unsafe {
                    input
                        .as_ptr()
                        .add(input.len())
                        .sub(mem::size_of::<Stripe>())
                        .cast::<Stripe>()
                        .read_unaligned()
                };

                last_round(&mut acc, last_block, last_stripe, &secret);

                final_merge(
                    &mut acc,
                    input.len().into_u64().wrapping_mul(PRIME64_1),
                    &secret,
                    11,
                )
            }
        }
    }
}

fn avalanche(mut x: u64) -> u64 {
    x ^= x >> 37;
    x = x.wrapping_mul(PRIME_MX1);
    x ^= x >> 32;
    x
}

fn avalanche_xxh64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(PRIME64_2);
    x ^= x >> 29;
    x = x.wrapping_mul(PRIME64_3);
    x ^= x >> 32;
    x
}

#[inline]
fn mix_step(data: &[u8; 16], secret: &[u8], secret_offset: usize, seed: u64) -> u64 {
    // TODO: Should these casts / reads happen outside this function?
    let data_words = unsafe { data.as_ptr().cast::<[u64; 2]>().read_unaligned() };
    let secret_words = unsafe {
        secret
            .as_ptr()
            .add(secret_offset)
            .cast::<[u64; 2]>()
            .read_unaligned()
    };

    let mul_result = {
        let a = (data_words[0] ^ secret_words[0].wrapping_add(seed)).into_u128();
        let b = (data_words[1] ^ secret_words[1].wrapping_sub(seed)).into_u128();

        a.wrapping_mul(b)
    };

    mul_result.lower_half() ^ mul_result.upper_half()
}

// fn mix_two_chunks(
//     acc: &mut [u64; 2],
//     data1: &[u8; 16],
//     data2: &[u8; 16],
//     secret: &[u8],
//     secret_offset: usize,
//     seed: u64,
// ) {
//     // TODO: Should these casts / reads happen outside this function?
//     let data_words1 = unsafe { data1.as_ptr().cast::<[u64; 2]>().read_unaligned() }; // TODO:little-endian conversion
//     let data_words2 = unsafe { data2.as_ptr().cast::<[u64; 2]>().read_unaligned() }; // TODO:little-endian conversion

//     acc[0] = acc[0] + mix_step(data1, secret, secret_offset, seed);
//     acc[1] = acc[1] + mix_step(data2, secret, secret_offset + 16, seed);
//     acc[0] = acc[0] ^ data_words2[0].wrapping_add(data_words2[1]);
//     acc[1] = acc[1] ^ data_words1[0].wrapping_add(data_words1[1]);
// }

// Step 2-1. Process stripes in the block
#[inline]
fn accumulate(acc: &mut [u64; 8], stripe: Stripe, secret: &[u8], secret_offset: usize) {
    // TODO: Should these casts / reads happen outside this function?
    let secret = &secret[secret_offset..];
    let secret_words = unsafe { secret.as_ptr().cast::<[u64; 8]>().read_unaligned() };

    for i in 0..8 {
        let value = stripe[i] ^ secret_words[i];
        acc[i ^ 1] = acc[i ^ 1].wrapping_add(stripe[i]);
        acc[i] = acc[i].wrapping_add({
            let a = value.lower_half().into_u64();
            let b = value.upper_half().into_u64();
            a.wrapping_mul(b)
        });
    }
}

#[inline]
fn round_accumulate(acc: &mut [u64; 8], block: &[u8], secret: &[u8]) {
    let (stripes, _) = block.bp_as_chunks::<{ mem::size_of::<Stripe>() }>();
    for (n, stripe) in stripes.iter().enumerate() {
        let stripe = unsafe { stripe.as_ptr().cast::<Stripe>().read_unaligned() };
        accumulate(acc, stripe, secret, n * 8);
    }
}

#[inline]
fn round_scramble(acc: &mut [u64; 8], secret: &[u8]) {
    let secret_words = unsafe {
        secret
            .as_ptr()
            .add(secret.len())
            .sub(mem::size_of::<[u64; 8]>())
            .cast::<[u64; 8]>()
            .read_unaligned()
    };

    for i in 0..8 {
        acc[i] ^= acc[i] >> 47;
        acc[i] ^= secret_words[i];
        acc[i] = acc[i].wrapping_mul(PRIME32_1);
    }
}

#[inline]
fn round(acc: &mut [u64; 8], block: &[u8], secret: &[u8]) {
    round_accumulate(acc, block, secret);
    round_scramble(acc, secret);
}

#[inline]
fn last_round(acc: &mut [u64; 8], block: &[u8], last_stripe: Stripe, secret: &[u8]) {
    let n_full_stripes = (block.len() - 1) / 64;
    for n in 0..n_full_stripes {
        let stripe = unsafe { block.as_ptr().add(n * 64).cast::<Stripe>().read_unaligned() };
        accumulate(acc, stripe, secret, n * 8);
    }
    accumulate(acc, last_stripe, secret, secret.len() - 71);
}

#[inline]
fn final_merge(acc: &mut [u64; 8], init_value: u64, secret: &[u8], secret_offset: usize) -> u64 {
    let secret_words = unsafe { secret.as_ptr().add(secret_offset).cast::<[u64; 8]>().read_unaligned() };
    let mut result = init_value;
    for i in 0..4 {
        // 64-bit by 64-bit multiplication to 128-bit full result
        let mul_result = {
            let a = (acc[i * 2] ^ secret_words[i * 2]).into_u128();
            let b = (acc[i * 2 + 1] ^ secret_words[i * 2 + 1]).into_u128();
            a.wrapping_mul(b)
        };
        result = result.wrapping_add(mul_result.lower_half() ^ mul_result.upper_half());
    }
    avalanche(result)
}

trait Halves {
    type Output;

    fn upper_half(self) -> Self::Output;
    fn lower_half(self) -> Self::Output;
}

impl Halves for u64 {
    type Output = u32;

    #[inline]
    fn upper_half(self) -> Self::Output {
        (self >> 32) as _
    }

    #[inline]
    fn lower_half(self) -> Self::Output {
        self as _
    }
}

impl Halves for u128 {
    type Output = u64;

    #[inline]
    fn upper_half(self) -> Self::Output {
        (self >> 64) as _
    }

    #[inline]
    fn lower_half(self) -> Self::Output {
        self as _
    }
}

trait SliceBackport<T> {
    fn bp_as_chunks<const N: usize>(&self) -> (&[[T; N]], &[T]);
    fn bp_as_rchunks<const N: usize>(&self) -> (&[T], &[[T; N]]);
}

impl<T> SliceBackport<T> for [T] {
    fn bp_as_chunks<const N: usize>(&self) -> (&[[T; N]], &[T]) {
        assert_ne!(N, 0);
        let len = self.len() / N;
        let (head, tail) = unsafe { self.split_at_unchecked(len * N) };
        let head = unsafe { slice::from_raw_parts(head.as_ptr().cast(), len) };
        (head, tail)
    }

    fn bp_as_rchunks<const N: usize>(&self) -> (&[T], &[[T; N]]) {
        assert_ne!(N, 0);
        let len = self.len() / N;
        let (head, tail) = unsafe { self.split_at_unchecked(self.len() - len * N) };
        let tail = unsafe { slice::from_raw_parts(tail.as_ptr().cast(), len) };
        (head, tail)
    }
}

#[cfg(test)]
mod test {
    use std::array;

    use super::*;

    macro_rules! bytes {
        ($($n: literal),* $(,)?) => {
            &[$(&gen_bytes::<$n>() as &[u8],)*] as &[&[u8]]
        };
    }

    fn gen_bytes<const N: usize>() -> [u8; N] {
        // Picking 251 as it's a prime number, which will hopefully
        // help avoid incidental power-of-two alignment.
        array::from_fn(|i| (i % 251) as u8)
    }

    #[test]
    fn hash_empty() {
        let hash = XxHash3_64::oneshot(&[]);
        assert_eq!(hash, 0x2d06_8005_38d3_94c2);
    }

    #[test]
    fn hash_1_to_3_bytes() {
        let inputs = bytes![1, 2, 3];

        let expected = [
            0xc44b_dff4_074e_ecdb,
            0xd664_5fc3_051a_9457,
            0x5f42_99fc_161c_9cbb,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_4_to_8_bytes() {
        let inputs = bytes![4, 5, 6, 7, 8];

        let expected = [
            0x60da_b036_a582_11f2,
            0xb075_753a_84ca_0fbe,
            0xa658_4d1d_9a6a_e704,
            0x0cd2_084a_6240_6b69,
            0x3a1c_2d7c_85af_88f8,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_9_to_16_bytes() {
        let inputs = bytes![9, 10, 11, 12, 13, 14, 15, 16];

        let expected = [
            0xe961_2598_145b_b9dc,
            0xab69_a08e_f83d_8f77,
            0x1cf3_96aa_4de6_198d,
            0x5ace_6a51_1c10_894b,
            0xb7a5_d8a8_309a_2cb9,
            0x4cf4_5c94_4a9a_2237,
            0x55ec_edc2_b87b_b042,
            0x8355_e3a6_f617_70db,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_17_to_128_bytes() {
        let lower_boundary = bytes![17, 18, 19];
        let chunk_boundary = bytes![31, 32, 33];
        let upper_boundary = bytes![126, 127, 128];

        let inputs = lower_boundary
            .iter()
            .chain(chunk_boundary)
            .chain(upper_boundary);

        let expected = [
            // lower_boundary
            0x9ef3_41a9_9de3_7328,
            0xf691_2490_d4c0_eed5,
            0x60e7_2614_3cf5_0312,
            // chunk_boundary
            0x4f36_db8e_4df3_78fd,
            0x3523_581f_e96e_4c05,
            0xe68c_56ba_8899_1e58,
            // upper_boundary
            0x6c2a_9eb7_459c_dc61,
            0x120b_9787_f842_5f2f,
            0x85c6_174c_7ff4_c46b,
        ];

        for (input, expected) in inputs.zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_129_to_240_bytes() {
        let lower_boundary = bytes![129, 130, 131];
        let upper_boundary = bytes![238, 239, 240];

        let inputs = lower_boundary.iter().chain(upper_boundary);

        let expected = [
            // lower_boundary
            0xec76_42b4_31ba_3e5a,
            0x4d32_24b1_0090_8a87,
            0xe57f_7ea6_741f_e3a0,
            // upper_boundary
            0x3044_9a0b_4899_dee9,
            0x972b_14e3_c46f_214b,
            0x375a_384d_957f_e865,
        ];

        for (input, expected) in inputs.zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_240_plus_bytes() {
        let inputs = bytes![241, 242, 243, 244];

        let expected = [
            0x02e8_cd95_421c_6d02,
            0xddcb_33c4_9405_1832,
            0x8835_f952_9193_e3dc,
            0xbc17_c91e_c3cf_8d7f,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn backported_as_chunks() {
        let x = [1, 2, 3, 4, 5];

        let (a, b) = x.bp_as_chunks::<1>();
        assert_eq!(a, &[[1], [2], [3], [4], [5]]);
        assert_eq!(b, &[]);

        let (a, b) = x.bp_as_chunks::<2>();
        assert_eq!(a, &[[1, 2], [3, 4]]);
        assert_eq!(b, &[5]);

        let (a, b) = x.bp_as_chunks::<3>();
        assert_eq!(a, &[[1, 2, 3]]);
        assert_eq!(b, &[4, 5]);

        let (a, b) = x.bp_as_chunks::<4>();
        assert_eq!(a, &[[1, 2, 3, 4]]);
        assert_eq!(b, &[5]);

        let (a, b) = x.bp_as_chunks::<5>();
        assert_eq!(a, &[[1, 2, 3, 4, 5]]);
        assert_eq!(b, &[]);

        let (a, b) = x.bp_as_chunks::<6>();
        assert_eq!(a, &[] as &[[i32; 6]]);
        assert_eq!(b, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn backported_as_rchunks() {
        let x = [1, 2, 3, 4, 5];

        let (a, b) = x.bp_as_rchunks::<1>();
        assert_eq!(a, &[]);
        assert_eq!(b, &[[1], [2], [3], [4], [5]]);

        let (a, b) = x.bp_as_rchunks::<2>();
        assert_eq!(a, &[1]);
        assert_eq!(b, &[[2, 3], [4, 5]]);

        let (a, b) = x.bp_as_rchunks::<3>();
        assert_eq!(a, &[1, 2]);
        assert_eq!(b, &[[3, 4, 5]]);

        let (a, b) = x.bp_as_rchunks::<4>();
        assert_eq!(a, &[1]);
        assert_eq!(b, &[[2, 3, 4, 5]]);

        let (a, b) = x.bp_as_rchunks::<5>();
        assert_eq!(a, &[]);
        assert_eq!(b, &[[1, 2, 3, 4, 5]]);

        let (a, b) = x.bp_as_rchunks::<6>();
        assert_eq!(a, &[1, 2, 3, 4, 5]);
        assert_eq!(b, &[] as &[[i32; 6]]);
    }
}
