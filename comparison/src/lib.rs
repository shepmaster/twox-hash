#![deny(rust_2018_idioms)]

use proptest::prelude::*;
use std::hash::Hasher;
#[cfg(test)]
use twox_hash::{XxHash, XxHash32};

pub mod c_xxhash;

pub fn hash_once(mut hasher: impl Hasher, data: &[u8]) -> u64 {
    hasher.write(&data);
    hasher.finish()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    #[test]
    fn same_results_as_c_for_64_bit(seed: u64, data: Vec<u8>) {
        let our_result = hash_once(XxHash::with_seed(seed), &data);
        let their_result = c_xxhash::hash64(&data, seed);

        our_result == their_result
    }

    #[test]
    fn same_results_as_c_for_32_bit(seed: u32, data: Vec<u8>) {
        let our_result = hash_once(XxHash32::with_seed(seed), &data);
        let their_result = c_xxhash::hash32(&data, seed);

        our_result == their_result as u64
    }
}
