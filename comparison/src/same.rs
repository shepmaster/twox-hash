use std::hash::Hasher;

use quickcheck::{QuickCheck, StdGen};
use rand::ThreadRng;
use twox_hash::{XxHash, XxHash32};
use c_xxhash;

fn qc() -> QuickCheck<StdGen<ThreadRng>> {
    QuickCheck::new()
        .tests(100_000)
        .max_tests(10_000_000)
}

#[test]
fn same_results_as_c_for_64_bit() {
    fn prop(seed: u64, data: Vec<u8>) -> bool {
        let mut hasher = XxHash::with_seed(seed);
        hasher.write(&data);
        let our_result = hasher.finish();

        let their_result = c_xxhash::hash64(&data, seed);

        our_result == their_result
    }

    qc().quickcheck(prop as fn(_, _) -> _);
}

#[test]
fn same_results_as_c_for_32_bit() {
    fn prop(seed: u32, data: Vec<u8>) -> bool {
        let mut hasher = XxHash32::with_seed(seed);
        hasher.write(&data);
        let our_result = hasher.finish();

        let their_result = c_xxhash::hash32(&data, seed);

        our_result == their_result as u64
    }

    qc().quickcheck(prop as fn(_, _) -> _);
}
