use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::{Rng, RngCore, SeedableRng};
use std::{hash::Hasher, hint::black_box, iter};

use xx_hash_sys as c;
use xx_renu as rust;

const TINY_DATA_SIZE: usize = 32;
const BIG_DATA_SIZE: usize = 100 * 1024 * 1024;

fn tiny_data(c: &mut Criterion) {
    let (seed, data) = gen_data(TINY_DATA_SIZE);
    let mut g = c.benchmark_group("tiny_data");

    for size in 0..=data.len() {
        let data = &data[..size];
        g.throughput(Throughput::Bytes(data.len() as _));

        let id = format!("c/oneshot/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let hash = c::XxHash64::oneshot(seed, data);
                black_box(hash);
            })
        });

        let id = format!("c/streaming/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let hash = {
                    let mut hasher = c::XxHash64::with_seed(seed);
                    hasher.write(data);
                    hasher.finish()
                };
                black_box(hash);
            })
        });

        let id = format!("rust/oneshot/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let hash = rust::XxHash64::oneshot(seed, data);
                black_box(hash);
            })
        });

        let id = format!("rust/streaming/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let hash = {
                    let mut hasher = rust::XxHash64::with_seed(seed);
                    hasher.write(data);
                    hasher.finish()
                };
                black_box(hash);
            })
        });
    }

    g.finish();
}

fn oneshot(c: &mut Criterion) {
    let (seed, data) = gen_data(BIG_DATA_SIZE);
    let mut g = c.benchmark_group("oneshot");

    for size in half_sizes(&data).take(10) {
        let data = &data[..size];
        g.throughput(Throughput::Bytes(data.len() as _));

        let id = format!("c/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let hash = c::XxHash64::oneshot(seed, data);
                black_box(hash);
            })
        });

        let id = format!("rust/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let hash = rust::XxHash64::oneshot(seed, data);
                black_box(hash);
            })
        });
    }

    g.finish();
}

fn streaming_one_chunk(c: &mut Criterion) {
    let (seed, data) = gen_data(BIG_DATA_SIZE);
    let mut g = c.benchmark_group("streaming_one_chunk");

    for size in half_sizes(&data).take(10) {
        let data = &data[..size];
        g.throughput(Throughput::Bytes(data.len() as _));

        let id = format!("c/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let mut hasher = c::XxHash64::with_seed(seed);
                hasher.write(data);
                let hash = hasher.finish();
                black_box(hash);
            })
        });

        let id = format!("rust/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let mut hasher = rust::XxHash64::with_seed(seed);
                hasher.write(data);
                let hash = hasher.finish();
                black_box(hash);
            })
        });
    }

    g.finish();
}

const SEED: u64 = 0xc651_4843_1995_363f;

fn gen_data(length: usize) -> (u64, Vec<u8>) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(SEED);

    let seed = rng.gen();

    let mut data = vec![0; length];
    rng.fill_bytes(&mut data);

    (seed, data)
}

fn half_sizes(data: &[u8]) -> impl Iterator<Item = usize> {
    iter::successors(
        Some(data.len()),
        |&v| {
            if v == 1 {
                None
            } else {
                Some(v / 2)
            }
        },
    )
}

criterion_group!(benches, tiny_data, oneshot, streaming_one_chunk);
criterion_main!(benches);
