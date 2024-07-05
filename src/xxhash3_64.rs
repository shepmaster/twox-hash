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

impl XxHash3_64 {
    #[inline]
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
                let input_first: u64 = unsafe { input.as_ptr().cast::<u64>().read_unaligned() };
                let input_last: u64 = unsafe {
                    input
                        .as_ptr()
                        .add(input.len())
                        .sub(mem::size_of::<u64>())
                        .cast::<u64>()
                        .read_unaligned()
                };

                let secret_words =
                    unsafe { secret.as_ptr().add(24).cast::<[u64; 4]>().read_unaligned() };
                let low: u64 =
                    ((secret_words[0] ^ secret_words[1]).wrapping_add(seed)) ^ input_first;
                let high: u64 =
                    ((secret_words[2] ^ secret_words[3]).wrapping_sub(seed)) ^ input_last;
                let mul_result: u128 = low.into_u128().wrapping_mul(high.into_u128());
                let value: u64 = input
                    .len()
                    .into_u64()
                    .wrapping_add(low.swap_bytes())
                    .wrapping_add(high)
                    .wrapping_add(mul_result.lower_half() ^ mul_result.upper_half());

                avalanche(value)
            }

            17..=128 => {
                let mut acc: u64 = input.len().into_u64().wrapping_mul(PRIME64_1);

                let num_rounds = ((input.len() - 1) >> 5) + 1;

                // TODO: use some chunks
                let mut ff = input;
                let mut rr = input;

                for i in (0..num_rounds).rev() {
                    let (ffc, ffn) = ff.split_first_chunk().unwrap();
                    let (rrn, rrc) = rr.split_last_chunk().unwrap();

                    acc = acc.wrapping_add(mix_step(ffc, &secret, i * 32, seed));
                    acc = acc.wrapping_add(mix_step(rrc, &secret, i * 32 + 16, seed));

                    ff = ffn;
                    rr = rrn;
                }

                avalanche(acc)
            }

            129..=240 => {
                let mut acc = input.len().into_u64().wrapping_mul(PRIME64_1);

                let (head, _tail) = input.bp_as_chunks();
                let mut head = head.into_iter();

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

                let secret_length = secret.len();
                let stripes_per_block = (secret_length - 64) / 8;
                let block_size = 64 * stripes_per_block;

                let mut cc = input.chunks(block_size).fuse();

                let last_block = cc.next_back().unwrap();

                for block in cc {
                    round(&mut acc, block, &secret);
                }

                let last_stripe = unsafe {
                    &*input
                        .as_ptr()
                        .add(input.len())
                        .sub(mem::size_of::<[u64; 8]>())
                        .cast::<[u64; 8]>()
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
fn accumulate(acc: &mut [u64; 8], stripe: &[u64; 8], secret: &[u8], secret_offset: usize) {
    // TODO: Should these casts / reads happen outside this function?
    let secret_words = unsafe { &*secret.as_ptr().add(secret_offset).cast::<[u64; 8]>() };

    for i in 0..8 {
        let value = stripe[i] ^ secret_words[i];
        acc[i ^ 1] = acc[i ^ 1].wrapping_add(stripe[i]);
        acc[i] = acc[i].wrapping_add(
            value
                .lower_half()
                .into_u64()
                .wrapping_mul(value.upper_half().into_u64()),
        );
    }
}

fn round_accumulate(acc: &mut [u64; 8], block: &[u8], secret: &[u8]) {
    let (stripes, _) = block.bp_as_chunks::<{ mem::size_of::<[u64; 8]>() }>();
    for (n, stripe) in stripes.iter().enumerate() {
        let stripe = unsafe { &*stripe.as_ptr().cast() };
        accumulate(acc, stripe, secret, n * 8);
    }
}

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
        acc[i] = acc[i] * PRIME32_1;
    }
}

fn round(acc: &mut [u64; 8], block: &[u8], secret: &[u8]) {
    round_accumulate(acc, block, secret);
    round_scramble(acc, secret);
}

fn last_round(acc: &mut [u64; 8], block: &[u8], last_stripe: &[u64; 8], secret: &[u8]) {
    let n_full_stripes: usize = (block.len() - 1) / 64;
    for n in 0..n_full_stripes {
        let stripe = unsafe { &*block.as_ptr().add(n * 64).cast::<[u64; 8]>() };
        accumulate(acc, stripe, secret, n * 8);
    }
    accumulate(acc, last_stripe, secret, secret.len() - 71);
}

fn final_merge(acc: &mut [u64; 8], init_value: u64, secret: &[u8], secret_offset: usize) -> u64 {
    let secret_words = unsafe { &*secret.as_ptr().add(secret_offset).cast::<[u64; 8]>() };
    let mut result: u64 = init_value;
    for i in 0..4 {
        // 64-bit by 64-bit multiplication to 128-bit full result
        let mul_result: u128 = (acc[i * 2] ^ secret_words[i * 2]).into_u128()
            * (acc[i * 2 + 1] ^ secret_words[i * 2 + 1]).into_u128();
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
    // fn bp_as_rchunks<const N: usize>(&self) -> (&[T], &[[T; N]]);
}

impl<T> SliceBackport<T> for [T] {
    fn bp_as_chunks<const N: usize>(&self) -> (&[[T; N]], &[T]) {
        assert_ne!(N, 0);
        let len = self.len() / N;
        let (head, tail) = unsafe { self.split_at_unchecked(len) };
        let head = unsafe { slice::from_raw_parts(head.as_ptr().cast(), len) };
        (head, tail)
    }

    // fn bp_as_rchunks<const N: usize>(&self) -> (&[T], &[[T; N]]) {
    //     assert_ne!(N, 0);
    //     let len = self.len() / N;
    //     let (head, tail) = unsafe { self.split_at_unchecked(self.len() - len * N) };
    //     let tail = unsafe { slice::from_raw_parts(tail.as_ptr().cast(), len) };
    //     (head, tail)
    // }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hash_64bit_empty_matches_c_implementation() {
        let hash = XxHash3_64::oneshot(&[]);
        assert_eq!(hash, 0x2d06_8005_38d3_94c2);
    }

    #[test]
    fn hash_64bit_1_to_3_bytes_matches_c_implementation() {
        let inputs: &[&[u8]] = &[&[0; 1], &[0; 2], &[0; 3]];
        let expected = [
            0xc44b_dff4_074e_ecdb,
            0x3325_230e_1f28_5505,
            0xeb5d_658b_b22f_286b,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_64bit_4_to_8_bytes_matches_c_implementation() {
        let inputs: &[&[u8]] = &[&[0; 4], &[0; 5], &[0; 6], &[0; 7], &[0; 8]];

        let expected = [
            0x48b2_c926_16fc_193d,
            0xe864_e589_3a27_3242,
            0x06df_7381_3892_fde7,
            0xa691_8fec_1ae6_5b70,
            0xc77b_3abb_6f87_acd9,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_64bit_9_to_16_bytes_matches_c_implementation() {
        let inputs: &[&[u8]] = &[
            &[0; 9], &[0; 10], &[0; 11], &[0; 12], &[0; 13], &[0; 14], &[0; 15], &[0; 16],
        ];

        let expected = [
            0x3449_9569_f039_1857,
            0x4a9f_fcfb_2837_fbcc,
            0xae43_2800_a160_9968,
            0xc499_8f91_69c2_a4f0,
            0xdaef_f723_917d_5279,
            0xf146_5eb4_188c_41e7,
            0xba50_02d3_c3ed_6bc7,
            0xd0a6_6a65_c752_8968,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_64bit_17_to_128_bytes_matches_c_implementation() {
        let inputs: &[&[u8]] = &[
            &[0; 17], &[0; 18], &[0; 19], &[0; 126], &[0; 127], &[0; 128],
        ];

        let expected = [
            0xc291_5ca0_df7a_d4c1,
            0xff78_21dd_f836_d020,
            0x8711_2824_6eb4_52b8,
            0x3133_805e_2401_c842,
            0x759e_ea08_c3b7_7cae,
            0x093c_29f2_7ecf_cf21,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_64bit_129_to_240_bytes_matches_c_implementation() {
        let inputs: &[&[u8]] = &[
            &[0; 129], &[0; 130], &[0; 131], &[0; 238], &[0; 239], &[0; 240],
        ];

        let expected = [
            0x37f7_943e_b2f5_1359,
            0x9cc8_599a_c6e3_f7c5,
            0x9a3c_cf6f_257e_b24d,
            0xb980_bcaf_ae82_6b6a,
            0xf01b_b3be_cb26_4837,
            0x053f_0744_4f70_da08,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }

    #[test]
    fn hash_64bit_240_plus_bytes_matches_c_implementation() {
        let inputs: &[&[u8]] = &[&[0; 241], &[0; 242], &[0; 243], &[0; 244]];

        let expected = [
            0x5c5b_5d5d_40c5_9ce3,
            0xd619_7ac3_0eb7_e67b,
            0x6a04_3c8a_cf2e_dfe5,
            0x83cf_eefc_38e1_35af,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {input:?}");
        }
    }
}
