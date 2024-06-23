use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::{Rng, RngCore, SeedableRng};
use std::{hint::black_box, iter};
use xx_hash_sys::Stream;
use xx_renu::XxHash64;

fn oneshot(c: &mut Criterion) {
    let (seed, data) = gen_data();
    let mut g = c.benchmark_group("oneshot");

    for size in half_sizes(&data).take(10) {
        let data = &data[..size];
        g.throughput(Throughput::Bytes(data.len() as _));

        let id = format!("xxHash/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let hash = Stream::oneshot(seed, &data);
                black_box(hash);
            })
        });

        let id = format!("renu/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let hash = XxHash64::oneshot(seed, &data);
                black_box(hash);
            })
        });
    }

    g.finish();
}

fn streaming_one_chunk(c: &mut Criterion) {
    let (seed, data) = gen_data();
    let mut g = c.benchmark_group("streaming_one_chunk");

    for size in half_sizes(&data).take(10) {
        let data = &data[..size];
        g.throughput(Throughput::Bytes(data.len() as _));

        let id = format!("xxHash/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let mut hasher = Stream::with_seed(seed);
                hasher.write(&data);
                let hash = hasher.finish();
                black_box(hash);
            })
        });

        let id = format!("renu/{size}");
        g.bench_function(id, |b| {
            b.iter(|| {
                let mut hasher = XxHash64::with_seed(seed);
                hasher.write(&data);
                let hash = hasher.finish();
                black_box(hash);
            })
        });
    }

    g.finish();
}

const SEED: u64 = 0xc651_4843_1995_363f;
const DATA_SIZE: usize = 100 * 1024 * 1024;

fn gen_data() -> (u64, Vec<u8>) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(SEED);

    let seed = rng.gen();

    let mut data = vec![0; DATA_SIZE];
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

criterion_group!(benches, oneshot, streaming_one_chunk);
criterion_main!(benches);
