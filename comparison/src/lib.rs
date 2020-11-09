#![deny(rust_2018_idioms)]

use proptest::{collection::vec as propvec, prelude::*};
use std::hash::Hasher;
#[cfg(test)]
use twox_hash::{xxh3, HasherExt, XxHash32, XxHash64};

pub mod c_xxhash;

pub fn hash_once(mut hasher: impl Hasher, data: &[u8]) -> u64 {
    hasher.write(&data);
    hasher.finish()
}

#[cfg(test)]
pub fn hash_once_ext(mut hasher: impl HasherExt, data: &[u8]) -> u128 {
    hasher.write(&data);
    hasher.finish_ext()
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

#[cfg(test)]
fn hash_by_chunks_ext(mut hasher: impl HasherExt, mut data: &[u8], chunk_sizes: &[usize]) -> u128 {
    for &chunk_size in chunk_sizes {
        let (this_chunk, remaining) = data.split_at(chunk_size);
        hasher.write(this_chunk);
        data = remaining;
    }

    hasher.finish_ext()
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
        let our_result = hash_once(XxHash64::with_seed(seed), &data);
        let their_result = c_xxhash::hash64(&data, seed);

        prop_assert_eq!(our_result, their_result);
    }

   #[test]
    fn same_results_as_c_with_offset_for_64_bit(seed: u64, (data, offset) in data_and_offset()) {
        let data = &data[offset..];
        let our_result = hash_once(XxHash64::with_seed(seed), data);
        let their_result = c_xxhash::hash64(data, seed);

        prop_assert_eq!(our_result, their_result);
    }

    #[test]
    fn same_results_as_c_for_32_bit(seed: u32, data: Vec<u8>) {
        let our_result = hash_once(XxHash32::with_seed(seed), &data);
        let their_result = c_xxhash::hash32(&data, seed);

        prop_assert_eq!(our_result, their_result as u64);
    }

   #[test]
    fn same_results_as_c_with_offset_for_32_bit(seed: u32, (data, offset) in data_and_offset()) {
        let data = &data[offset..];
        let our_result = hash_once(XxHash32::with_seed(seed), data);
        let their_result = c_xxhash::hash32(data, seed);

        prop_assert_eq!(our_result, their_result as u64);
    }

    #[test]
    fn same_results_as_c_for_xxh3_64_bit(seed: u64, data: Vec<u8>) {
        let our_result = hash_once(xxh3::Hash64::with_seed(seed), &data);
        let their_result = c_xxhash::xxh3_hash64(&data, seed);

        prop_assert_eq!(our_result, their_result);
    }

    #[test]
    fn same_results_as_c_with_offset_for_xxh3_64_bit(seed: u64, (data, offset) in data_and_offset()) {
        let data = &data[offset..];
        let our_result = hash_once(xxh3::Hash64::with_seed(seed), data);
        let their_result = c_xxhash::xxh3_hash64(data, seed);

        prop_assert_eq!(our_result, their_result);
    }

    #[test]
    fn same_results_as_c_for_xxh3_128_bit(seed: u64, data: Vec<u8>) {
        let our_result = hash_once_ext(xxh3::Hash128::with_seed(seed), &data);
        let their_result = c_xxhash::xxh3_hash128(&data, seed);

        prop_assert_eq!(our_result, their_result);
    }

    #[test]
    fn same_results_as_c_with_offset_for_xxh3_128_bit(seed: u64, (data, offset) in data_and_offset()) {
        let data = &data[offset..];
        let our_result = hash_once_ext(xxh3::Hash128::with_seed(seed), data);
        let their_result = c_xxhash::xxh3_hash128(data, seed);

        prop_assert_eq!(our_result, their_result);
    }

}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn same_results_with_many_chunks_as_one_for_64_bit(seed: u64, (data, chunk_sizes) in data_and_chunk_sizes()) {
        let chunked_result = hash_by_chunks(XxHash64::with_seed(seed), &data, &chunk_sizes);
        let monolithic_result = hash_once(XxHash64::with_seed(seed), &data);

        prop_assert_eq!(chunked_result, monolithic_result);
    }

    #[test]
    fn same_results_with_many_chunks_as_one_for_32_bit(seed: u32, (data, chunk_sizes) in data_and_chunk_sizes()) {
        let chunked_result = hash_by_chunks(XxHash32::with_seed(seed), &data, &chunk_sizes);
        let monolithic_result = hash_once(XxHash32::with_seed(seed), &data);

        prop_assert_eq!(chunked_result, monolithic_result);
    }

    #[test]
    fn same_results_with_many_chunks_as_one_for_xxh3_64_bit(seed: u64, (data, chunk_sizes) in data_and_chunk_sizes()) {
        let chunked_result = hash_by_chunks(xxh3::Hash64::with_seed(seed), &data, &chunk_sizes);
        let monolithic_result = hash_once(xxh3::Hash64::with_seed(seed), &data);

        prop_assert_eq!(chunked_result, monolithic_result);
    }

    #[test]
    fn same_results_with_many_chunks_as_one_for_xxh3_128_bit(seed: u64, (data, chunk_sizes) in data_and_chunk_sizes()) {
        let chunked_result = hash_by_chunks_ext(xxh3::Hash128::with_seed(seed), &data, &chunk_sizes);
        let monolithic_result = hash_once_ext(xxh3::Hash128::with_seed(seed), &data);

        prop_assert_eq!(chunked_result, monolithic_result);
    }

}
