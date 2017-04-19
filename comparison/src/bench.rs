use std::hash::{Hasher,SipHasher};

use test;
use fnv;
use twox_hash::{XxHash, XxHash32};

fn hasher_bench<H>(b: &mut test::Bencher, mut hasher: H, len: usize)
    where H: Hasher
{
    let bytes: Vec<_> = (0..100).cycle().take(len).collect();
    b.bytes = bytes.len() as u64;
    b.iter(|| {
        hasher.write(&bytes);
        hasher.finish()
    });
}

fn xxhash_bench(b: &mut test::Bencher, len: usize) {
    hasher_bench(b, XxHash::with_seed(0), len)
}

fn xxhash32_bench(b: &mut test::Bencher, len: usize) {
    hasher_bench(b, XxHash32::with_seed(0), len)
}

fn siphash_bench(b: &mut test::Bencher, len: usize) {
    hasher_bench(b, SipHasher::new(), len)
}

fn fnvhash_bench(b: &mut test::Bencher, len: usize) {
    hasher_bench(b, <fnv::FnvHasher as Default>::default(), len)
}

#[bench]
fn siphash_megabyte(b: &mut test::Bencher) { siphash_bench(b, 1024*1024) }

#[bench]
fn siphash_1024_byte(b: &mut test::Bencher) { siphash_bench(b, 1024) }

#[bench]
fn siphash_512_byte(b: &mut test::Bencher) { siphash_bench(b, 512) }

#[bench]
fn siphash_256_byte(b: &mut test::Bencher) { siphash_bench(b, 256) }

#[bench]
fn siphash_128_byte(b: &mut test::Bencher) { siphash_bench(b, 128) }

#[bench]
fn siphash_32_byte(b: &mut test::Bencher) { siphash_bench(b, 32) }

#[bench]
fn siphash_16_byte(b: &mut test::Bencher) { siphash_bench(b, 16) }

#[bench]
fn siphash_4_byte(b: &mut test::Bencher) { siphash_bench(b, 4) }

#[bench]
fn siphash_1_byte(b: &mut test::Bencher) { siphash_bench(b, 1) }

#[bench]
fn siphash_0_byte(b: &mut test::Bencher) { siphash_bench(b, 0) }

#[bench]
fn fnvhash_megabyte(b: &mut test::Bencher) { fnvhash_bench(b, 1024*1024) }

#[bench]
fn fnvhash_1024_byte(b: &mut test::Bencher) { fnvhash_bench(b, 1024) }

#[bench]
fn fnvhash_512_byte(b: &mut test::Bencher) { fnvhash_bench(b, 512) }

#[bench]
fn fnvhash_256_byte(b: &mut test::Bencher) { fnvhash_bench(b, 256) }

#[bench]
fn fnvhash_128_byte(b: &mut test::Bencher) { fnvhash_bench(b, 128) }

#[bench]
fn fnvhash_32_byte(b: &mut test::Bencher) { fnvhash_bench(b, 32) }

#[bench]
fn fnvhash_16_byte(b: &mut test::Bencher) { fnvhash_bench(b, 16) }

#[bench]
fn fnvhash_4_byte(b: &mut test::Bencher) { fnvhash_bench(b, 4) }

#[bench]
fn fnvhash_1_byte(b: &mut test::Bencher) { fnvhash_bench(b, 1) }

#[bench]
fn fnvhash_0_byte(b: &mut test::Bencher) { fnvhash_bench(b, 0) }

#[bench]
fn xxhash_megabyte(b: &mut test::Bencher) { xxhash_bench(b, 1024*1024) }

#[bench]
fn xxhash_1024_byte(b: &mut test::Bencher) { xxhash_bench(b, 1024) }

#[bench]
fn xxhash_512_byte(b: &mut test::Bencher) { xxhash_bench(b, 512) }

#[bench]
fn xxhash_256_byte(b: &mut test::Bencher) { xxhash_bench(b, 256) }

#[bench]
fn xxhash_128_byte(b: &mut test::Bencher) { xxhash_bench(b, 128) }

#[bench]
fn xxhash_32_byte(b: &mut test::Bencher) { xxhash_bench(b, 32) }

#[bench]
fn xxhash_16_byte(b: &mut test::Bencher) { xxhash_bench(b, 16) }

#[bench]
fn xxhash_4_byte(b: &mut test::Bencher) { xxhash_bench(b, 4) }

#[bench]
fn xxhash_1_byte(b: &mut test::Bencher) { xxhash_bench(b, 1) }

#[bench]
fn xxhash_0_byte(b: &mut test::Bencher) { xxhash_bench(b, 0) }

#[bench]
fn xxhash32_megabyte(b: &mut test::Bencher) { xxhash32_bench(b, 1024*1024) }

#[bench]
fn xxhash32_1024_byte(b: &mut test::Bencher) { xxhash32_bench(b, 1024) }

#[bench]
fn xxhash32_512_byte(b: &mut test::Bencher) { xxhash32_bench(b, 512) }

#[bench]
fn xxhash32_256_byte(b: &mut test::Bencher) { xxhash32_bench(b, 256) }

#[bench]
fn xxhash32_128_byte(b: &mut test::Bencher) { xxhash32_bench(b, 128) }

#[bench]
fn xxhash32_32_byte(b: &mut test::Bencher) { xxhash32_bench(b, 32) }

#[bench]
fn xxhash32_16_byte(b: &mut test::Bencher) { xxhash32_bench(b, 16) }

#[bench]
fn xxhash32_4_byte(b: &mut test::Bencher) { xxhash32_bench(b, 4) }

#[bench]
fn xxhash32_1_byte(b: &mut test::Bencher) { xxhash32_bench(b, 1) }

#[bench]
fn xxhash32_0_byte(b: &mut test::Bencher) { xxhash32_bench(b, 0) }
