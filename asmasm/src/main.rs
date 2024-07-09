use std::{hint::black_box, time::Instant};
use xx_renu::xxhash3_64::XxHash3_64;

fn main() {
    let filename = std::env::args().nth(1).expect("filename");
    let file = std::fs::read(filename).expect("read");
    let start = Instant::now();
    let hash = XxHash3_64::oneshot(&file);
    let elapsed = start.elapsed();
    black_box(hash);
    eprintln!("{elapsed:?}");
}
