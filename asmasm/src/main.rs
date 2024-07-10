use std::{hint::black_box, time::Instant};
use xx_hash_sys::XxHash3_64 as C;
use xx_renu::xxhash3_64::XxHash3_64;

fn main() {
    let filename = std::env::args().nth(1).expect("filename");
    let use_c = std::env::args()
        .nth(2)
        .map_or(false, |a| a.eq_ignore_ascii_case("C"));
    let file = std::fs::read(filename).expect("read");

    if use_c {
        let start = Instant::now();
        let hash = C::oneshot(&file);
        let elapsed = start.elapsed();
        black_box(hash);
        eprintln!("C    {elapsed:?}");
    } else {
        let start = Instant::now();
        let hash = XxHash3_64::oneshot(&file);
        let elapsed = start.elapsed();
        black_box(hash);
        eprintln!("Rust {elapsed:?}");
    }
}
