//! The implementation of XXH3_128.

#![deny(
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks,
    unsafe_op_in_unsafe_fn
)]

use crate::{xxhash3::*, IntoU128 as _};

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
        0 => impl_0_bytes(secret, seed),

        _ => unimplemented!(),
    }
}

#[inline(always)]
fn impl_0_bytes(secret: &Secret, seed: u64) -> u128 {
    let secret_words = secret.for_128().words_for_0();

    let low = avalanche_xxh64(seed ^ secret_words[0] ^ secret_words[1]);
    let high = avalanche_xxh64(seed ^ secret_words[2] ^ secret_words[3]);

    high.into_u128() << 64 | low.into_u128()
}

#[cfg(test)]
mod test {
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
}
