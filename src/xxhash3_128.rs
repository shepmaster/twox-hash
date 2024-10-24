//! The implementation of XXH3_128.

#![deny(
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks,
    unsafe_op_in_unsafe_fn
)]

use crate::{
    xxhash3::{primes::*, *},
    IntoU128 as _, IntoU64 as _,
};

pub use crate::xxhash3::{DEFAULT_SECRET_LENGTH, SECRET_MINIMUM_LENGTH};

/// Calculates the 128-bit hash.
#[derive(Clone)]
pub struct Hasher;

impl Hasher {
    /// Hash all data at once. If you can use this function, you may
    /// see noticable speed gains for certain types of input.
    #[must_use]
    #[inline]
    pub fn oneshot(input: &[u8]) -> u128 {
        impl_oneshot(DEFAULT_SECRET, DEFAULT_SEED, input)
    }
}

#[inline(always)]
fn impl_oneshot(secret: &Secret, seed: u64, input: &[u8]) -> u128 {
    match input.len() {
        9..=16 => impl_9_to_16_bytes(secret, seed, input),

        4..=8 => impl_4_to_8_bytes(secret, seed, input),

        1..=3 => impl_1_to_3_bytes(secret, seed, input),

        0 => impl_0_bytes(secret, seed),

        _ => unimplemented!(),
    }
}

#[derive(Copy, Clone)]
struct X128 {
    low: u64,
    high: u64,
}

impl From<X128> for u128 {
    fn from(value: X128) -> Self {
        value.high.into_u128() << 64 | value.low.into_u128()
    }
}

impl crate::IntoU128 for X128 {
    fn into_u128(self) -> u128 {
        self.into()
    }
}

#[inline(always)]
fn impl_0_bytes(secret: &Secret, seed: u64) -> u128 {
    let secret_words = secret.for_128().words_for_0();

    let low = avalanche_xxh64(seed ^ secret_words[0] ^ secret_words[1]);
    let high = avalanche_xxh64(seed ^ secret_words[2] ^ secret_words[3]);

    X128 { low, high }.into()
}

#[inline(always)]
fn impl_1_to_3_bytes(secret: &Secret, seed: u64, input: &[u8]) -> u128 {
    assert_input_range!(1..=3, input.len());

    let combined = impl_1_to_3_bytes_combined(input);
    let secret_words = secret.for_128().words_for_1_to_3();

    let low = {
        let secret = (secret_words[0] ^ secret_words[1]).into_u64();
        secret.wrapping_add(seed) ^ combined.into_u64()
    };
    let high = {
        let secret = (secret_words[2] ^ secret_words[3]).into_u64();
        secret.wrapping_sub(seed) ^ combined.swap_bytes().rotate_left(13).into_u64()
    };

    let low = avalanche_xxh64(low);
    let high = avalanche_xxh64(high);

    X128 { low, high }.into()
}

#[inline(always)]
fn impl_4_to_8_bytes(secret: &Secret, seed: u64, input: &[u8]) -> u128 {
    assert_input_range!(4..=8, input.len());
    let input_first = input.first_u32().unwrap();
    let input_last = input.last_u32().unwrap();

    let modified_seed = seed ^ (seed.lower_half().swap_bytes().into_u64() << 32);
    let secret_words = secret.for_128().words_for_4_to_8();

    let combined = input_first.into_u64() | (input_last.into_u64() << 32);
    let lhs = {
        let a = secret_words[0] ^ secret_words[1];
        let b = a.wrapping_add(modified_seed);
        b ^ combined
    };
    let rhs = PRIME64_1.wrapping_add(input.len().into_u64() << 2);
    let mul_result = lhs.into_u128().wrapping_mul(rhs.into_u128());

    let mut high = mul_result.upper_half();
    let mut low = mul_result.lower_half();

    high = high.wrapping_add(low << 1);

    low ^= high >> 3;
    low ^= low >> 35;
    low = low.wrapping_mul(PRIME_MX2);
    low ^= low >> 28;

    high = avalanche(high);

    X128 { low, high }.into()
}

#[inline(always)]
fn impl_9_to_16_bytes(secret: &Secret, seed: u64, input: &[u8]) -> u128 {
    assert_input_range!(9..=16, input.len());
    let input_first = input.first_u64().unwrap();
    let input_last = input.last_u64().unwrap();

    let secret_words = secret.for_128().words_for_9_to_16();
    let val1 = ((secret_words[0] ^ secret_words[1]).wrapping_sub(seed)) ^ input_first ^ input_last;
    let val2 = ((secret_words[2] ^ secret_words[3]).wrapping_add(seed)) ^ input_last;
    let mul_result = val1.into_u128().wrapping_mul(PRIME64_1.into_u128());
    let low = mul_result
        .lower_half()
        .wrapping_add((input.len() - 1).into_u64() << 54);

    // Algorithm describes this in two ways
    let high = mul_result
        .upper_half()
        .wrapping_add(val2.upper_half().into_u64() << 32)
        .wrapping_add(val2.lower_half().into_u64().wrapping_mul(PRIME32_2));

    let low = low ^ high.swap_bytes();

    // Algorithm describes this multiplication in two ways.
    let q = X128 { low, high }
        .into_u128()
        .wrapping_mul(PRIME64_2.into_u128());

    let low = avalanche(q.lower_half());
    let high = avalanche(q.upper_half());

    X128 { low, high }.into()
}

#[cfg(test)]
mod test {
    use crate::xxhash3::test::bytes;

    use super::*;

    const _: () = {
        const fn is_clone<T: Clone>() {}
        is_clone::<Hasher>();
    };

    const EMPTY_BYTES: [u8; 0] = [];

    #[test]
    fn oneshot_empty() {
        let hash = Hasher::oneshot(&EMPTY_BYTES);
        assert_eq!(hash, 0x99aa_06d3_0147_98d8_6001_c324_468d_497f);
    }

    #[test]
    fn oneshot_1_to_3_bytes() {
        test_1_to_3_bytes(Hasher::oneshot)
    }

    #[track_caller]
    fn test_1_to_3_bytes(mut f: impl FnMut(&[u8]) -> u128) {
        let inputs = bytes![1, 2, 3];

        let expected = [
            0xa6cd_5e93_9200_0f6a_c44b_dff4_074e_ecdb,
            0x6a4a_5274_c1b0_d3ad_d664_5fc3_051a_9457,
            0xe3b5_5f57_945a_17cf_5f42_99fc_161c_9cbb,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = f(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn oneshot_4_to_8_bytes() {
        test_4_to_8_bytes(Hasher::oneshot)
    }

    #[track_caller]
    fn test_4_to_8_bytes(mut f: impl FnMut(&[u8]) -> u128) {
        let inputs = bytes![4, 5, 6, 7, 8];

        let expected = [
            0xeb70_bf5f_c779_e9e6_a611_1d53_e80a_3db5,
            0x9434_5321_06a7_c141_c920_d234_7a85_929b,
            0x545f_093d_32b1_68fe_a6b5_2f4d_ea38_96a3,
            0x61ce_291b_c3a4_357d_dbb2_0782_1e6d_5efe,
            0xe1e4_432a_6221_7fe4_cfd5_0c61_c8bb_98c1,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = f(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn oneshot_9_to_16_bytes() {
        test_9_to_16_bytes(Hasher::oneshot)
    }

    #[track_caller]
    fn test_9_to_16_bytes(mut f: impl FnMut(&[u8]) -> u128) {
        let inputs = bytes![9, 10, 11, 12, 13, 14, 15, 16];

        let expected = [
            0x16c7_69d8_3e4a_ebce_9079_3197_9dca_3746,
            0xbd93_0669_a87b_4b37_e67b_f1ad_8dcf_73a8,
            0xacad_8071_8f47_d494_7d67_cfc1_730f_22a3,
            0x38f9_2247_a7f7_3cc5_7780_eb31_198f_13ca,
            0xae92_e123_e947_2408_bd79_5526_1902_66c0,
            0x5f91_e6bf_7418_cfaa_55d6_5715_e2a5_7c31,
            0x301a_9f75_4e8f_569a_0017_ea4b_e19b_c787,
            0x7295_0631_8276_07e2_8428_12cc_870d_cae2,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = f(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }
}
