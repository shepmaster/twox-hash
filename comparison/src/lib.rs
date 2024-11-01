#![cfg(test)]

use proptest::{num, prelude::*};

use twox_hash as rust;
use xx_hash_sys as c;

mod xxhash32 {
    use proptest::{prelude::*, test_runner::TestCaseResult};
    use std::hash::Hasher as _;

    use super::*;

    proptest! {
        #[test]
        fn oneshot_same_as_one_chunk(seed in seed_32(), data: Vec<u8>) {
            oneshot_same_as_one_chunk_impl(seed, &data)?;
        }

        #[test]
        fn oneshot_same_as_one_chunk_with_an_offset(seed in seed_32(), (data, offset) in vec_and_index()) {
            oneshot_same_as_one_chunk_impl(seed, &data[offset..])?;
        }

        #[test]
        fn oneshot_same_as_many_chunks(seed in seed_32(), (data, chunks) in data_and_chunks()) {
            oneshot_same_as_many_chunks_impl(seed, &data, &chunks)?;
        }

        #[test]
        fn oneshot(seed in seed_32(), data: Vec<u8>) {
            oneshot_impl(seed, &data)?;
        }

        #[test]
        fn oneshot_with_an_offset(seed in seed_32(), (data, offset) in vec_and_index()) {
            oneshot_impl(seed, &data[offset..])?;
        }

        #[test]
        fn streaming_one_chunk(seed in seed_32(), data: Vec<u8>) {
            streaming_one_chunk_impl(seed, &data)?;
        }

        #[test]
        fn streaming_one_chunk_with_an_offset(seed in seed_32(), (data, offset) in vec_and_index()) {
            streaming_one_chunk_impl(seed, &data[offset..])?;
        }
    }

    fn oneshot_same_as_one_chunk_impl(seed: u32, data: &[u8]) -> TestCaseResult {
        let oneshot = rust::XxHash32::oneshot(seed, data);
        let one_chunk = {
            let mut hasher = rust::XxHash32::with_seed(seed);
            hasher.write(data);
            hasher.finish_32()
        };

        prop_assert_eq!(oneshot, one_chunk);
        Ok(())
    }

    fn oneshot_same_as_many_chunks_impl(
        seed: u32,
        data: &[u8],
        chunks: &[Vec<u8>],
    ) -> TestCaseResult {
        let oneshot = rust::XxHash32::oneshot(seed, data);
        let many_chunks = {
            let mut hasher = rust::XxHash32::with_seed(seed);
            for chunk in chunks {
                hasher.write(chunk);
            }
            hasher.finish_32()
        };

        prop_assert_eq!(oneshot, many_chunks);
        Ok(())
    }

    fn oneshot_impl(seed: u32, data: &[u8]) -> TestCaseResult {
        let native = c::XxHash32::oneshot(seed, data);
        let rust = rust::XxHash32::oneshot(seed, data);

        prop_assert_eq!(native, rust);
        Ok(())
    }

    fn streaming_one_chunk_impl(seed: u32, data: &[u8]) -> TestCaseResult {
        let native = {
            let mut hasher = c::XxHash32::with_seed(seed);
            hasher.write(data);
            hasher.finish()
        };

        let rust = {
            let mut hasher = rust::XxHash32::with_seed(seed);
            hasher.write(data);
            hasher.finish_32()
        };

        prop_assert_eq!(native, rust);
        Ok(())
    }
}

mod xxhash64 {
    use proptest::{prelude::*, test_runner::TestCaseResult};
    use std::hash::Hasher as _;

    use super::*;

    proptest! {
        #[test]
        fn oneshot_same_as_one_chunk(seed in seed_64(), data: Vec<u8>) {
            oneshot_same_as_one_chunk_impl(seed, &data)?;
        }

        #[test]
        fn oneshot_same_as_one_chunk_with_an_offset(seed in seed_64(), (data, offset) in vec_and_index()) {
            oneshot_same_as_one_chunk_impl(seed, &data[offset..])?;
        }

        #[test]
        fn oneshot_same_as_many_chunks(seed in seed_64(), (data, chunks) in data_and_chunks()) {
            oneshot_same_as_many_chunks_impl(seed, &data, &chunks)?;
        }

        #[test]
        fn oneshot(seed in seed_64(), data: Vec<u8>) {
            oneshot_impl(seed, &data)?;
        }

        #[test]
        fn oneshot_with_an_offset(seed in seed_64(), (data, offset) in vec_and_index()) {
            oneshot_impl(seed, &data[offset..])?;
        }

        #[test]
        fn streaming_one_chunk(seed in seed_64(), data: Vec<u8>) {
            streaming_one_chunk_impl(seed, &data)?;
        }

        #[test]
        fn streaming_one_chunk_with_an_offset(seed in seed_64(), (data, offset) in vec_and_index()) {
            streaming_one_chunk_impl(seed, &data[offset..])?;
        }
    }

    fn oneshot_same_as_one_chunk_impl(seed: u64, data: &[u8]) -> TestCaseResult {
        let oneshot = rust::XxHash64::oneshot(seed, data);
        let one_chunk = {
            let mut hasher = rust::XxHash64::with_seed(seed);
            hasher.write(data);
            hasher.finish()
        };

        prop_assert_eq!(oneshot, one_chunk);
        Ok(())
    }

    fn oneshot_same_as_many_chunks_impl(
        seed: u64,
        data: &[u8],
        chunks: &[Vec<u8>],
    ) -> TestCaseResult {
        let oneshot = rust::XxHash64::oneshot(seed, data);
        let many_chunks = {
            let mut hasher = rust::XxHash64::with_seed(seed);
            for chunk in chunks {
                hasher.write(chunk);
            }
            hasher.finish()
        };

        prop_assert_eq!(oneshot, many_chunks);
        Ok(())
    }

    fn oneshot_impl(seed: u64, data: &[u8]) -> TestCaseResult {
        let native = c::XxHash64::oneshot(seed, data);
        let rust = rust::XxHash64::oneshot(seed, data);

        prop_assert_eq!(native, rust);
        Ok(())
    }

    fn streaming_one_chunk_impl(seed: u64, data: &[u8]) -> TestCaseResult {
        let native = {
            let mut hasher = c::XxHash64::with_seed(seed);
            hasher.write(data);
            hasher.finish()
        };

        let rust = {
            let mut hasher = rust::XxHash64::with_seed(seed);
            hasher.write(data);
            hasher.finish()
        };

        prop_assert_eq!(native, rust);
        Ok(())
    }
}

mod xxhash3_64 {
    use proptest::{prelude::*, test_runner::TestCaseResult};
    use std::hash::Hasher as _;
    use twox_hash::xxhash3_64::SECRET_MINIMUM_LENGTH;

    use super::*;

    proptest! {
        #[test]
        fn oneshot_same_as_one_chunk(seed in seed_64(), data: Vec<u8>) {
            oneshot_same_as_one_chunk_impl(seed, &data)?;
        }

        #[test]
        fn oneshot_same_as_one_chunk_with_an_offset(seed in seed_64(), (data, offset) in vec_and_index()) {
            oneshot_same_as_one_chunk_impl(seed, &data[offset..])?;
        }

        #[test]
        fn oneshot_same_as_many_chunks(seed in seed_64(), (data, chunks) in data_and_chunks()) {
            oneshot_same_as_many_chunks_impl(seed, &data, &chunks)?;
        }

        #[test]
        fn oneshot(seed in seed_64(), data: Vec<u8>) {
            oneshot_impl(seed, &data)?;
        }

        #[test]
        fn oneshot_with_an_offset(seed in seed_64(), (data, offset) in vec_and_index()) {
            oneshot_impl(seed, &data[offset..])?;
        }

        #[test]
        fn oneshot_with_a_secret(secret in secret(), data: Vec<u8>) {
            oneshot_with_secret_impl(&secret, &data)?;
        }

        #[test]
        fn oneshot_with_a_seed_and_secret(seed in seed_64(), secret in secret(), data: Vec<u8>) {
            oneshot_with_seed_and_secret_impl(seed, &secret, &data)?;
        }

        #[test]
        fn streaming_one_chunk(seed in seed_64(), data: Vec<u8>) {
            streaming_one_chunk_impl(seed, &data)?;
        }

        #[test]
        fn streaming_one_chunk_with_an_offset(seed in seed_64(), (data, offset) in vec_and_index()) {
            streaming_one_chunk_impl(seed, &data[offset..])?;
        }

        #[test]
        fn streaming_with_a_seed_and_secret(seed in seed_64(), secret in secret(), data: Vec<u8>) {
            streaming_with_seed_and_secret_impl(seed, &secret, &data)?;
        }
    }

    fn oneshot_same_as_one_chunk_impl(seed: u64, data: &[u8]) -> TestCaseResult {
        let oneshot = rust::XxHash3_64::oneshot_with_seed(seed, data);
        let one_chunk = {
            let mut hasher = rust::XxHash3_64::with_seed(seed);
            hasher.write(data);
            hasher.finish()
        };

        prop_assert_eq!(oneshot, one_chunk);
        Ok(())
    }

    fn oneshot_same_as_many_chunks_impl(
        seed: u64,
        data: &[u8],
        chunks: &[Vec<u8>],
    ) -> TestCaseResult {
        let oneshot = rust::XxHash3_64::oneshot_with_seed(seed, data);
        let many_chunks = {
            let mut hasher = rust::XxHash3_64::with_seed(seed);
            for chunk in chunks {
                hasher.write(chunk);
            }
            hasher.finish()
        };

        prop_assert_eq!(oneshot, many_chunks);
        Ok(())
    }

    fn oneshot_impl(seed: u64, data: &[u8]) -> TestCaseResult {
        let native = c::XxHash3_64::oneshot_with_seed(seed, data);
        let rust = rust::XxHash3_64::oneshot_with_seed(seed, data);

        prop_assert_eq!(native, rust);
        Ok(())
    }

    fn oneshot_with_secret_impl(secret: &[u8], data: &[u8]) -> TestCaseResult {
        let native = c::XxHash3_64::oneshot_with_secret(secret, data);
        let rust = rust::XxHash3_64::oneshot_with_secret(secret, data).unwrap();

        prop_assert_eq!(native, rust);
        Ok(())
    }

    fn oneshot_with_seed_and_secret_impl(seed: u64, secret: &[u8], data: &[u8]) -> TestCaseResult {
        let native = c::XxHash3_64::oneshot_with_seed_and_secret(seed, secret, data);
        let rust = rust::XxHash3_64::oneshot_with_seed_and_secret(seed, secret, data).unwrap();

        prop_assert_eq!(native, rust);
        Ok(())
    }

    fn streaming_one_chunk_impl(seed: u64, data: &[u8]) -> TestCaseResult {
        let native = {
            let mut hasher = c::XxHash3_64::with_seed(seed);
            hasher.write(data);
            hasher.finish()
        };

        let rust = {
            let mut hasher = rust::XxHash3_64::with_seed(seed);
            hasher.write(data);
            hasher.finish()
        };

        prop_assert_eq!(native, rust);
        Ok(())
    }

    fn streaming_with_seed_and_secret_impl(
        seed: u64,
        secret: &[u8],
        data: &[u8],
    ) -> TestCaseResult {
        let native = {
            let mut hasher = c::XxHash3_64::with_seed_and_secret(seed, secret);
            for chunk in data.chunks(256) {
                hasher.write(chunk);
            }
            hasher.finish()
        };

        let rust = {
            let mut hasher = rust::XxHash3_64::with_seed_and_secret(seed, secret).unwrap();
            for chunk in data.chunks(256) {
                hasher.write(chunk);
            }
            hasher.finish()
        };

        prop_assert_eq!(native, rust);
        Ok(())
    }

    fn secret() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(num::u8::ANY, SECRET_MINIMUM_LENGTH..1024)
    }
}

fn seed_32() -> impl Strategy<Value = u32> {
    prop_oneof![Just(0), Just(u32::MAX), num::u32::ANY]
}

fn seed_64() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0), Just(u64::MAX), num::u64::ANY]
}

fn vec_and_index() -> impl Strategy<Value = (Vec<u8>, usize)> {
    prop::collection::vec(num::u8::ANY, 0..=32 * 1024).prop_flat_map(|vec| {
        let len = vec.len();
        (Just(vec), 0..=len)
    })
}

fn data_and_chunks() -> impl Strategy<Value = (Vec<u8>, Vec<Vec<u8>>)> {
    prop::collection::vec(prop::collection::vec(num::u8::ANY, 0..100), 0..100).prop_map(|vs| {
        let data = vs.iter().flatten().copied().collect();
        (data, vs)
    })
}
