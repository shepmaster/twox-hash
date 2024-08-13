use std::{hash::Hasher, hint::black_box, time::Instant};
use xx_hash_sys::XxHash3_64 as C;
use xx_renu::xxhash3_64::XxHash3_64;

fn main() {
    let filename = std::env::args().nth(1).expect("filename");
    let use_c = std::env::args()
        .nth(2)
        .map_or(false, |a| a.eq_ignore_ascii_case("C"));
    let file = std::fs::read(filename).expect("read");
    let seed = 0xdead_beef;

    if use_c {
        let start = Instant::now();
        let hash = do_c(seed, &file);
        let elapsed = start.elapsed();
        black_box(hash);
        eprintln!("C    {elapsed:?}");
    } else {
        let start = Instant::now();
        let hash = do_rust(seed, &file);
        let elapsed = start.elapsed();
        black_box(hash);
        eprintln!("Rust {elapsed:?}");
    }
}

#[inline(never)]
fn do_c(seed: u64, file: &[u8]) -> u64 {
    let mut hasher = C::with_seed(seed);
    hasher.write(file);
    hasher.finish()
}

#[inline(never)]
fn do_rust(seed: u64, file: &[u8]) -> u64 {
    let mut hasher = XxHash3_64::with_seed(seed);
    hasher.write(&file);
    hasher.finish()
}
