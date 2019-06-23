#![deny(rust_2018_idioms)]

use proptest::{prelude::*, collection::vec as propvec};
use std::hash::Hasher;
#[cfg(test)]
use twox_hash::{XxHash, XxHash32};

pub mod c_xxhash;

pub fn hash_once(mut hasher: impl Hasher, data: &[u8]) -> u64 {
    hasher.write(&data);
    hasher.finish()
}

#[cfg(test)]
fn hash_by_chunks(mut hasher: impl Hasher, mut data: &[u8], chunk_sizes: &[usize]) -> u64 {
    for &chunk_size in chunk_sizes {
        let (this_chunk, remaining) = data.split_at(chunk_size);
        hasher.write(this_chunk);
        data = remaining;
    }

    hasher.finish()
}

prop_compose! {
    fn data_and_offset
        ()
        (data in any::<Vec<u8>>())
        (index in 0..=data.len(), data in Just(data))
         -> (Vec<u8>, usize)
    {
        (data, index)
    }
}

prop_compose! {
    fn data_and_chunk_sizes
        ()
        (sizes in propvec(1..=256usize, 0..=100))
        (data in propvec(any::<u8>(), sizes.iter().sum::<usize>()), sizes in Just(sizes))
         -> (Vec<u8>, Vec<usize>)
    {
        (data, sizes)
    }
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
    fn same_results_as_c_with_offset_for_64_bit(seed: u64, (data, offset) in data_and_offset()) {
        let data = &data[offset..];
        let our_result = hash_once(XxHash::with_seed(seed), data);
        let their_result = c_xxhash::hash64(data, seed);

        our_result == their_result
    }

    #[test]
    fn same_results_as_c_for_32_bit(seed: u32, data: Vec<u8>) {
        let our_result = hash_once(XxHash32::with_seed(seed), &data);
        let their_result = c_xxhash::hash32(&data, seed);

        our_result == their_result as u64
    }

   #[test]
    fn same_results_as_c_with_offset_for_32_bit(seed: u32, (data, offset) in data_and_offset()) {
        let data = &data[offset..];
        let our_result = hash_once(XxHash32::with_seed(seed), data);
        let their_result = c_xxhash::hash32(data, seed);

        our_result == their_result as u64
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn same_results_with_many_chunks_as_one_for_64_bit(seed: u64, (data, chunk_sizes) in data_and_chunk_sizes()) {
        let chunked_result = hash_by_chunks(XxHash::with_seed(seed), &data, &chunk_sizes);
        let monolithic_result = hash_once(XxHash::with_seed(seed), &data);

        chunked_result == monolithic_result
    }

    #[test]
    fn same_results_with_many_chunks_as_one_for_32_bit(seed: u32, (data, chunk_sizes) in data_and_chunk_sizes()) {
        let chunked_result = hash_by_chunks(XxHash32::with_seed(seed), &data, &chunk_sizes);
        let monolithic_result = hash_once(XxHash32::with_seed(seed), &data);

        chunked_result == monolithic_result
    }
}
