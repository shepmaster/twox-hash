use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion, Throughput,
};
use rand::{Rng, RngCore, SeedableRng};
use std::{env::consts::ARCH, hash::Hasher as _, iter};

use twox_hash as rust;
use xx_hash_sys as c;

const BIG_DATA_SIZE: usize = 4 * 1024 * 1024;
const MIN_BIG_DATA_SIZE: usize = 256 * 1024;
const SEED: u64 = 0xc651_4843_1995_363f;

trait CriterionExt {
    fn my_benchmark_group(&mut self, algo: &str, bench: &str) -> BenchmarkGroup<'_, WallTime>;
}

impl CriterionExt for Criterion {
    fn my_benchmark_group(&mut self, algo: &str, bench: &str) -> BenchmarkGroup<'_, WallTime> {
        self.benchmark_group(format!("arch-{ARCH}/algo-{algo}/bench-{bench}"))
    }
}

fn gen_data(length: usize) -> (u64, Vec<u8>) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(SEED);

    let seed = rng.random();

    let mut data = vec![0; length];
    rng.fill_bytes(&mut data);

    (seed, data)
}

fn half_sizes(max: usize) -> impl Iterator<Item = usize> {
    iter::successors(Some(max), |&v| if v == 1 { None } else { Some(v / 2) })
}

mod xxhash64 {
    use std::time::Duration;

    use super::*;

    const TINY_DATA_SIZE: usize = 32;

    fn tiny_data(c: &mut Criterion) {
        let (seed, data) = gen_data(TINY_DATA_SIZE);
        let mut g = c.my_benchmark_group("xxhash64", "tiny_data");

        // These tests take ~5ns, so reducing the testing times
        // doesn't affect accuracy but does improve code iteration
        // time.
        g.warm_up_time(Duration::from_millis(10))
            .measurement_time(Duration::from_millis(100));

        for size in 0..=data.len() {
            let data = &data[..size];
            g.throughput(Throughput::Bytes(data.len() as _));

            let id = format!("impl-c/size-{size:02}");
            g.bench_function(id, |b| b.iter(|| c::XxHash64::oneshot(seed, data)));

            let id = format!("impl-rust/size-{size:02}");
            g.bench_function(id, |b| b.iter(|| rust::XxHash64::oneshot(seed, data)));
        }

        g.finish();
    }

    fn oneshot(c: &mut Criterion) {
        let (seed, data) = gen_data(BIG_DATA_SIZE);
        let mut g = c.my_benchmark_group("xxhash64", "oneshot");

        for size in half_sizes(data.len()).take_while(|&s| s >= MIN_BIG_DATA_SIZE) {
            let data = &data[..size];
            g.throughput(Throughput::Bytes(data.len() as _));

            let id = format!("impl-c/size-{size:07}");
            g.bench_function(id, |b| b.iter(|| c::XxHash64::oneshot(seed, data)));

            let id = format!("impl-rust/size-{size:07}");
            g.bench_function(id, |b| b.iter(|| rust::XxHash64::oneshot(seed, data)));
        }

        g.finish();
    }

    fn streaming(c: &mut Criterion) {
        let mut g = c.my_benchmark_group("xxhash64", "streaming");

        let size = 1024 * 1024;
        let (seed, data) = gen_data(size);

        for chunk_size in half_sizes(size) {
            let chunks = data.chunks(chunk_size).collect::<Vec<_>>();

            g.throughput(Throughput::Bytes(size as _));

            let id = format!("impl-c/size-{size:07}/chunk_size-{chunk_size:02}");
            g.bench_function(id, |b| {
                b.iter(|| {
                    let mut hasher = c::XxHash64::with_seed(seed);
                    for chunk in &chunks {
                        hasher.write(chunk);
                    }
                    hasher.finish()
                })
            });

            let id = format!("impl-rust/size-{size:07}/chunk_size-{chunk_size:02}");
            g.bench_function(id, |b| {
                b.iter(|| {
                    let mut hasher = rust::XxHash64::with_seed(seed);
                    for chunk in &chunks {
                        hasher.write(chunk);
                    }
                    hasher.finish()
                })
            });
        }

        g.finish();
    }

    criterion_group!(benches, tiny_data, oneshot, streaming);
}

mod xxhash3 {
    use std::{collections::BTreeSet, time::Duration};

    use super::*;

    pub trait OneshotFamily {
        type Output;

        fn name(&self) -> &'static str;

        fn c_oneshot(&self, seed: u64, data: &[u8]) -> Self::Output;

        fn c_scalar_oneshot(&self, seed: u64, data: &[u8]) -> Self::Output;

        #[cfg(target_arch = "aarch64")]
        fn c_neon_oneshot(&self, seed: u64, data: &[u8]) -> Self::Output;

        #[cfg(target_arch = "x86_64")]
        fn c_avx2_oneshot(&self, seed: u64, data: &[u8]) -> Self::Output;

        #[cfg(target_arch = "x86_64")]
        fn c_sse2_oneshot(&self, seed: u64, data: &[u8]) -> Self::Output;

        fn rust_oneshot(&self, seed: u64, data: &[u8]) -> Self::Output;
    }

    pub fn tiny_data(c: &mut Criterion, algo: &str, family: impl OneshotFamily) {
        let mut g = c.my_benchmark_group(algo, "tiny_data");
        let name = family.name();
        let (seed, data) = gen_data(240);

        // These tests take ~15ns, so reducing the testing times
        // doesn't affect accuracy but does improve code iteration
        // time.
        g.warm_up_time(Duration::from_millis(10))
            .measurement_time(Duration::from_millis(100));

        // Every datapoint before we get to
        // let categories = 0..=data.len();

        // Inspection of the code as well as visual inspection of all
        // the datapoints showed these as examples of thier nearby
        // neighbors.
        let category_ranges = [
            0..=0_usize,
            1..=3,
            4..=8,
            9..=16,
            17..=32,
            33..=64,
            65..=96,
            97..=128,
            129..=143,
            144..=159,
            160..=175,
            176..=191,
            192..=207,
            208..=223,
            224..=239,
            240..=240,
        ];
        // let categories = category_ranges
        //     .iter()
        //     .flat_map(|r| [*r.start(), *r.end()])
        //     .collect::<BTreeSet<_>>();

        // Midpoints of those levels, useful for faster iteration
        let categories = category_ranges
            .iter()
            .map(|r| r.start() + (r.end() - r.start()) / 2)
            .collect::<Vec<_>>();

        for size in categories {
            let data = &data[..size];
            g.throughput(Throughput::Bytes(data.len() as _));

            let id = format!("impl-c/function-{name}/size-{size:03}");
            g.bench_function(id, |b| b.iter(|| family.c_oneshot(seed, data)));

            let id = format!("impl-c-scalar/function-{name}/size-{size:03}");
            g.bench_function(id, |b| b.iter(|| family.c_scalar_oneshot(seed, data)));

            #[cfg(target_arch = "aarch64")]
            {
                let id = format!("impl-c-neon/function-{name}/size-{size:03}");
                g.bench_function(id, |b| b.iter(|| family.c_neon_oneshot(seed, data)));
            }

            #[cfg(target_arch = "x86_64")]
            {
                let id = format!("impl-c-avx2/function-{name}/size-{size:03}");
                g.bench_function(id, |b| b.iter(|| family.c_avx2_oneshot(seed, data)));

                let id = format!("impl-c-sse2/function-{name}/size-{size:03}");
                g.bench_function(id, |b| b.iter(|| family.c_sse2_oneshot(seed, data)));
            }

            let id = format!("impl-rust/function-{name}/size-{size:03}");
            g.bench_function(id, |b| b.iter(|| family.rust_oneshot(seed, data)));
        }

        g.finish();
    }
}

mod xxhash3_64 {
    use super::*;

    struct Oneshot;

    impl xxhash3::OneshotFamily for Oneshot {
        type Output = u64;

        fn name(&self) -> &'static str {
            "oneshot"
        }

        #[inline(always)]
        fn c_oneshot(&self, _seed: u64, data: &[u8]) -> u64 {
            c::XxHash3_64::oneshot(data)
        }

        #[inline(always)]
        fn c_scalar_oneshot(&self, _seed: u64, data: &[u8]) -> u64 {
            c::scalar::XxHash3_64::oneshot(data)
        }

        #[cfg(target_arch = "aarch64")]
        #[inline(always)]
        fn c_neon_oneshot(&self, _seed: u64, data: &[u8]) -> u64 {
            c::neon::XxHash3_64::oneshot(data)
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        fn c_avx2_oneshot(&self, _seed: u64, data: &[u8]) -> u64 {
            c::avx2::XxHash3_64::oneshot(data)
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        fn c_sse2_oneshot(&self, _seed: u64, data: &[u8]) -> u64 {
            c::sse2::XxHash3_64::oneshot(data)
        }

        #[inline(always)]
        fn rust_oneshot(&self, _seed: u64, data: &[u8]) -> u64 {
            rust::XxHash3_64::oneshot(data)
        }
    }

    struct OneshotWithSeed;

    impl xxhash3::OneshotFamily for OneshotWithSeed {
        type Output = u64;

        fn name(&self) -> &'static str {
            "oneshot_with_seed"
        }

        #[inline(always)]
        fn c_oneshot(&self, seed: u64, data: &[u8]) -> u64 {
            c::XxHash3_64::oneshot_with_seed(seed, data)
        }

        #[inline(always)]
        fn c_scalar_oneshot(&self, seed: u64, data: &[u8]) -> u64 {
            c::scalar::XxHash3_64::oneshot_with_seed(seed, data)
        }

        #[cfg(target_arch = "aarch64")]
        #[inline(always)]
        fn c_neon_oneshot(&self, seed: u64, data: &[u8]) -> u64 {
            c::neon::XxHash3_64::oneshot_with_seed(seed, data)
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        fn c_avx2_oneshot(&self, seed: u64, data: &[u8]) -> u64 {
            c::avx2::XxHash3_64::oneshot_with_seed(seed, data)
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        fn c_sse2_oneshot(&self, seed: u64, data: &[u8]) -> u64 {
            c::sse2::XxHash3_64::oneshot_with_seed(seed, data)
        }

        #[inline(always)]
        fn rust_oneshot(&self, seed: u64, data: &[u8]) -> u64 {
            rust::XxHash3_64::oneshot_with_seed(seed, data)
        }
    }

    fn tiny_data(c: &mut Criterion) {
        xxhash3::tiny_data(c, "xxhash3_64", Oneshot);
        xxhash3::tiny_data(c, "xxhash3_64", OneshotWithSeed);
    }

    fn oneshot(c: &mut Criterion) {
        let (seed, data) = gen_data(BIG_DATA_SIZE);
        let mut g = c.my_benchmark_group("xxhash3_64", "oneshot");

        for size in half_sizes(data.len()).take_while(|&s| s >= MIN_BIG_DATA_SIZE) {
            let data = &data[..size];
            g.throughput(Throughput::Bytes(data.len() as _));

            let id = format!("impl-c/size-{size:07}");
            g.bench_function(id, |b| {
                b.iter(|| c::XxHash3_64::oneshot_with_seed(seed, data))
            });

            let id = format!("impl-c-scalar/size-{size:07}");
            g.bench_function(id, |b| {
                b.iter(|| c::scalar::XxHash3_64::oneshot_with_seed(seed, data))
            });

            #[cfg(target_arch = "aarch64")]
            {
                let id = format!("impl-c-neon/size-{size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| c::neon::XxHash3_64::oneshot_with_seed(seed, data))
                });
            }

            #[cfg(target_arch = "x86_64")]
            {
                let id = format!("impl-c-avx2/size-{size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| c::avx2::XxHash3_64::oneshot_with_seed(seed, data))
                });

                let id = format!("impl-c-sse2/size-{size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| c::sse2::XxHash3_64::oneshot_with_seed(seed, data))
                });
            }

            let id = format!("impl-rust/size-{size:07}");
            g.bench_function(id, |b| {
                b.iter(|| rust::XxHash3_64::oneshot_with_seed(seed, data))
            });
        }

        g.finish();
    }

    fn streaming(c: &mut Criterion) {
        let mut g = c.my_benchmark_group("xxhash3_64", "streaming");

        let size = 1024 * 1024;
        let (seed, data) = gen_data(size);

        for chunk_size in half_sizes(size) {
            let chunks = data.chunks(chunk_size).collect::<Vec<_>>();

            g.throughput(Throughput::Bytes(size as _));

            let id = format!("impl-c/size-{size:07}/chunk_size-{chunk_size:07}");
            g.bench_function(id, |b| {
                b.iter(|| {
                    let mut hasher = c::XxHash3_64::with_seed(seed);
                    for chunk in &chunks {
                        hasher.write(chunk);
                    }
                    hasher.finish()
                })
            });

            let id = format!("impl-c-scalar/size-{size:07}/chunk_size-{chunk_size:07}");
            g.bench_function(id, |b| {
                b.iter(|| {
                    let mut hasher = c::scalar::XxHash3_64::with_seed(seed);
                    for chunk in &chunks {
                        hasher.write(chunk);
                    }
                    hasher.finish()
                })
            });

            #[cfg(target_arch = "aarch64")]
            {
                let id = format!("impl-c-neon/size-{size:07}/chunk_size-{chunk_size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| {
                        let mut hasher = c::neon::XxHash3_64::with_seed(seed);
                        for chunk in &chunks {
                            hasher.write(chunk);
                        }
                        hasher.finish()
                    })
                });
            }

            #[cfg(target_arch = "x86_64")]
            {
                let id = format!("impl-c-avx2/size-{size:07}/chunk_size-{chunk_size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| {
                        let mut hasher = c::avx2::XxHash3_64::with_seed(seed);
                        for chunk in &chunks {
                            hasher.write(chunk);
                        }
                        hasher.finish()
                    })
                });

                let id = format!("impl-c-sse2/size-{size:07}/chunk_size-{chunk_size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| {
                        let mut hasher = c::sse2::XxHash3_64::with_seed(seed);
                        for chunk in &chunks {
                            hasher.write(chunk);
                        }
                        hasher.finish()
                    })
                });
            }

            let id = format!("impl-rust/size-{size:07}/chunk_size-{chunk_size:07}");
            g.bench_function(id, |b| {
                b.iter(|| {
                    let mut hasher = rust::XxHash3_64::with_seed(seed);
                    for chunk in &chunks {
                        hasher.write(chunk);
                    }
                    hasher.finish()
                })
            });
        }

        g.finish();
    }

    criterion_group!(benches, tiny_data, oneshot, streaming);
}

mod xxhash3_128 {
    use super::*;

    struct Oneshot;

    impl xxhash3::OneshotFamily for Oneshot {
        type Output = u128;

        fn name(&self) -> &'static str {
            "oneshot"
        }

        #[inline(always)]
        fn c_oneshot(&self, _seed: u64, data: &[u8]) -> u128 {
            c::XxHash3_128::oneshot(data)
        }

        #[inline(always)]
        fn c_scalar_oneshot(&self, _seed: u64, data: &[u8]) -> u128 {
            c::scalar::XxHash3_128::oneshot(data)
        }

        #[cfg(target_arch = "aarch64")]
        #[inline(always)]
        fn c_neon_oneshot(&self, _seed: u64, data: &[u8]) -> u128 {
            c::neon::XxHash3_128::oneshot(data)
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        fn c_avx2_oneshot(&self, _seed: u64, data: &[u8]) -> u128 {
            c::avx2::XxHash3_128::oneshot(data)
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        fn c_sse2_oneshot(&self, _seed: u64, data: &[u8]) -> u128 {
            c::sse2::XxHash3_128::oneshot(data)
        }

        #[inline(always)]
        fn rust_oneshot(&self, _seed: u64, data: &[u8]) -> u128 {
            rust::XxHash3_128::oneshot(data)
        }
    }

    struct OneshotWithSeed;

    impl xxhash3::OneshotFamily for OneshotWithSeed {
        type Output = u128;

        fn name(&self) -> &'static str {
            "oneshot_with_seed"
        }

        #[inline(always)]
        fn c_oneshot(&self, seed: u64, data: &[u8]) -> u128 {
            c::XxHash3_128::oneshot_with_seed(seed, data)
        }

        #[inline(always)]
        fn c_scalar_oneshot(&self, seed: u64, data: &[u8]) -> u128 {
            c::scalar::XxHash3_128::oneshot_with_seed(seed, data)
        }

        #[cfg(target_arch = "aarch64")]
        #[inline(always)]
        fn c_neon_oneshot(&self, seed: u64, data: &[u8]) -> u128 {
            c::neon::XxHash3_128::oneshot_with_seed(seed, data)
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        fn c_avx2_oneshot(&self, seed: u64, data: &[u8]) -> u128 {
            c::avx2::XxHash3_128::oneshot_with_seed(seed, data)
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        fn c_sse2_oneshot(&self, seed: u64, data: &[u8]) -> u128 {
            c::sse2::XxHash3_128::oneshot_with_seed(seed, data)
        }

        #[inline(always)]
        fn rust_oneshot(&self, seed: u64, data: &[u8]) -> u128 {
            rust::XxHash3_128::oneshot_with_seed(seed, data)
        }
    }

    fn tiny_data(c: &mut Criterion) {
        xxhash3::tiny_data(c, "xxhash3_128", Oneshot);
        xxhash3::tiny_data(c, "xxhash3_128", OneshotWithSeed);
    }

    fn oneshot(c: &mut Criterion) {
        let (seed, data) = gen_data(BIG_DATA_SIZE);
        let mut g = c.my_benchmark_group("xxhash3_128", "oneshot");

        for size in half_sizes(data.len()).take_while(|&s| s >= MIN_BIG_DATA_SIZE) {
            let data = &data[..size];
            g.throughput(Throughput::Bytes(data.len() as _));

            let id = format!("impl-c/size-{size:07}");
            g.bench_function(id, |b| {
                b.iter(|| c::XxHash3_128::oneshot_with_seed(seed, data))
            });

            let id = format!("impl-c-scalar/size-{size:07}");
            g.bench_function(id, |b| {
                b.iter(|| c::scalar::XxHash3_128::oneshot_with_seed(seed, data))
            });

            #[cfg(target_arch = "aarch64")]
            {
                let id = format!("impl-c-neon/size-{size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| c::neon::XxHash3_128::oneshot_with_seed(seed, data))
                });
            }

            #[cfg(target_arch = "x86_64")]
            {
                let id = format!("impl-c-avx2/size-{size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| c::avx2::XxHash3_128::oneshot_with_seed(seed, data))
                });

                let id = format!("impl-c-sse2/size-{size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| c::sse2::XxHash3_128::oneshot_with_seed(seed, data))
                });
            }

            let id = format!("impl-rust/size-{size:07}");
            g.bench_function(id, |b| {
                b.iter(|| rust::XxHash3_128::oneshot_with_seed(seed, data))
            });
        }

        g.finish();
    }

    fn streaming(c: &mut Criterion) {
        let mut g = c.my_benchmark_group("xxhash3_128", "streaming");

        let size = 1024 * 1024;
        let (seed, data) = gen_data(size);

        for chunk_size in half_sizes(size) {
            let chunks = data.chunks(chunk_size).collect::<Vec<_>>();

            g.throughput(Throughput::Bytes(size as _));

            let id = format!("impl-c/size-{size:07}/chunk_size-{chunk_size:07}");
            g.bench_function(id, |b| {
                b.iter(|| {
                    let mut hasher = c::XxHash3_128::with_seed(seed);
                    for chunk in &chunks {
                        hasher.write(chunk);
                    }
                    hasher.finish()
                })
            });

            let id = format!("impl-c-scalar/size-{size:07}/chunk_size-{chunk_size:07}");
            g.bench_function(id, |b| {
                b.iter(|| {
                    let mut hasher = c::scalar::XxHash3_128::with_seed(seed);
                    for chunk in &chunks {
                        hasher.write(chunk);
                    }
                    hasher.finish()
                })
            });

            #[cfg(target_arch = "aarch64")]
            {
                let id = format!("impl-c-neon/size-{size:07}/chunk_size-{chunk_size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| {
                        let mut hasher = c::neon::XxHash3_128::with_seed(seed);
                        for chunk in &chunks {
                            hasher.write(chunk);
                        }
                        hasher.finish()
                    })
                });
            }

            #[cfg(target_arch = "x86_64")]
            {
                let id = format!("impl-c-avx2/size-{size:07}/chunk_size-{chunk_size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| {
                        let mut hasher = c::avx2::XxHash3_128::with_seed(seed);
                        for chunk in &chunks {
                            hasher.write(chunk);
                        }
                        hasher.finish()
                    })
                });

                let id = format!("impl-c-sse2/size-{size:07}/chunk_size-{chunk_size:07}");
                g.bench_function(id, |b| {
                    b.iter(|| {
                        let mut hasher = c::sse2::XxHash3_128::with_seed(seed);
                        for chunk in &chunks {
                            hasher.write(chunk);
                        }
                        hasher.finish()
                    })
                });
            }

            let id = format!("impl-rust/size-{size:07}/chunk_size-{chunk_size:07}");
            g.bench_function(id, |b| {
                b.iter(|| {
                    let mut hasher = rust::XxHash3_128::with_seed(seed);
                    for chunk in &chunks {
                        hasher.write(chunk);
                    }
                    hasher.finish_128()
                })
            });
        }

        g.finish();
    }

    criterion_group!(benches, tiny_data, oneshot, streaming);
}

criterion_main!(xxhash64::benches, xxhash3_64::benches, xxhash3_128::benches);
