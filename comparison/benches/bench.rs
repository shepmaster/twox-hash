#![deny(rust_2018_idioms)]

use comparison::{
    c_xxhash::{hash32, hash64},
    hash_once,
};
use criterion::{
    criterion_group, criterion_main, AxisScale, Bencher, Criterion, ParameterizedBenchmark,
    PlotConfiguration, Throughput,
};
use fnv::FnvHasher;
use std::{
    fmt,
    hash::{Hasher, SipHasher},
    ops,
};
use twox_hash::{XxHash, XxHash32};

const INPUT_SIZES: &[usize] = &[0, 1, 4, 16, 32, 128, 256, 512, 1024, 1024 * 1024];

fn bench_hasher<H>(hasher: impl Fn() -> H) -> impl FnMut(&mut Bencher, &Data)
where
    H: Hasher,
{
    move |b, data| b.iter(|| hash_once(hasher(), data))
}

fn bench_c<R>(hasher: impl Fn(&[u8]) -> R) -> impl FnMut(&mut Bencher, &Data) {
    move |b, data| b.iter(|| hasher(data))
}

fn bench_everything(c: &mut Criterion) {
    let data: Vec<_> = INPUT_SIZES.iter().map(|&l| Data::new(l)).collect();

    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);

    let bench =
        ParameterizedBenchmark::new("XxHash64", bench_hasher(|| XxHash::with_seed(0)), data)
            .with_function("XxHash32", bench_hasher(|| XxHash32::with_seed(0)))
            .with_function("XxHash64 (C)", bench_c(|d| hash64(d, 0)))
            .with_function("XxHash32 (C)", bench_c(|d| hash32(d, 0)))
            .with_function("SipHasher", bench_hasher(|| SipHasher::new()))
            .with_function("FnvHasher", bench_hasher(|| FnvHasher::default()))
            .throughput(|data| Throughput::Elements(data.0.len() as u32))
            .plot_config(plot_config);

    c.bench("All Hashers", bench);
}

struct Data(Vec<u8>);

impl Data {
    fn new(len: usize) -> Self {
        Self(vec![0; len])
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl ops::Deref for Data {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", self.len())
    }
}

criterion_group!(benches, bench_everything);
criterion_main!(benches);
