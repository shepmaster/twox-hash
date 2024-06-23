#![cfg(test)]

use proptest::{num, prelude::*, test_runner::TestCaseResult};

proptest! {
    #[test]
    fn it_works(seed: u64, data: Vec<u8>) {
        it_works_impl(seed, &data)?;
    }

    #[test]
    fn it_works_with_an_offset(seed: u64, (data, offset) in vec_and_index()) {
        it_works_impl(seed, &data[offset..])?;
    }
}

fn it_works_impl(seed: u64, data: &[u8]) -> TestCaseResult {
    let native = {
        let mut hasher = xx_hash_sys::Stream::with_seed(seed);
        hasher.write(data);
        hasher.finish()
    };

    let rust = {
        let mut hasher = xx_renu::XxHash64::with_seed(seed);
        hasher.write(data);
        hasher.finish()
    };

    prop_assert_eq!(native, rust);
    Ok(())
}

fn vec_and_index() -> impl Strategy<Value = (Vec<u8>, usize)> {
    prop::collection::vec(num::u8::ANY, 0..=32 * 1024).prop_flat_map(|vec| {
        let len = vec.len();
        (Just(vec), 0..len)
    })
}
