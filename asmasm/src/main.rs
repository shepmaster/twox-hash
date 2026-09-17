use std::{array, hash::Hasher as _, hint, time::Instant};

fn main() {
    let filename = std::env::args().nth(1).expect("filename");
    let mode = std::env::args().nth(2);
    let mode = mode.as_deref().unwrap_or("rust-oneshot");
    let file = std::fs::read(filename).expect("read");
    let chunk_size = file.len() / 100;
    let chunk_size = usize::max(chunk_size, 1);
    let seed = hint::black_box(42);
    let secret: [u8; 256] = hint::black_box(array::from_fn(|i| i as u8 % 253));
    let iterations = (|| {
        let v = std::env::var("N_ITERATIONS").ok()?;
        v.parse().ok()
    })();

    let run_once = || match mode {
        "rust-oneshot" => rust_oneshot(&file),
        "c-oneshot" => c_oneshot(&file),
        "rust-oneshot-with-seed" => rust_oneshot_with_seed(&file, seed),
        "c-oneshot-with-seed" => c_oneshot_with_seed(&file, seed),
        "rust-oneshot-with-secret" => rust_oneshot_with_secret(&file, &secret),
        "c-oneshot-with-secret" => c_oneshot_with_secret(&file, &secret),
        "rust-chunked" => rust_chunked(&file, chunk_size),
        "c-chunked" => c_chunked(&file, chunk_size),
        other => panic!("Unknown mode {other}"),
    };

    if let Some(iterations) = iterations {
        let hash_sum = (0..iterations)
            .map(|_| run_once())
            .fold(Hash::default(), |acc, v| acc.wrapping_add(v));
        eprintln!("{hash_sum}");
    }

    let start = Instant::now();
    let hash = run_once();
    let elapsed = start.elapsed();

    eprintln!("{mode}\t{elapsed:?}\t{hash:016X}");
}

type Rust = twox_hash::XxHash3_64;
type C = xx_hash_sys::XxHash3_64;
type Hash = u64;
fn finish(r: Rust) -> Hash {
    std::hash::Hasher::finish(&r)
}

// type Rust = twox_hash::XxHash3_128;
// type C = xx_hash_sys::XxHash3_128;
// type Hash = u128;
// fn finish(r: Rust) -> Hash {
//     r.finish_128()
// }

#[inline(never)]
fn rust_oneshot(file: &[u8]) -> Hash {
    Rust::oneshot(file)
}

#[inline(never)]
fn c_oneshot(file: &[u8]) -> Hash {
    C::oneshot(file)
}

#[inline(never)]
fn rust_oneshot_with_seed(file: &[u8], seed: u64) -> Hash {
    Rust::oneshot_with_seed(seed, file)
}

#[inline(never)]
fn c_oneshot_with_seed(file: &[u8], seed: u64) -> Hash {
    C::oneshot_with_seed(seed, file)
}

#[inline(never)]
fn rust_oneshot_with_secret(file: &[u8], secret: &[u8]) -> Hash {
    Rust::oneshot_with_secret(secret, file).unwrap()
}

#[inline(never)]
fn c_oneshot_with_secret(file: &[u8], secret: &[u8]) -> Hash {
    C::oneshot_with_secret(secret, file)
}

#[inline(never)]
fn rust_chunked(file: &[u8], chunk_size: usize) -> Hash {
    let mut hasher = Rust::new();
    for chunk in file.chunks(chunk_size) {
        hasher.write(chunk);
    }
    finish(hasher)
}

#[inline(never)]
fn c_chunked(file: &[u8], chunk_size: usize) -> Hash {
    let mut hasher = C::new();
    for chunk in file.chunks(chunk_size) {
        hasher.write(chunk);
    }
    hasher.finish()
}
