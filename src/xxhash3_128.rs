//! The implementation of XXH3_128.

#![deny(
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks,
    unsafe_op_in_unsafe_fn
)]

use crate::{xxhash3::*, IntoU128 as _, IntoU64 as _};

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
}
