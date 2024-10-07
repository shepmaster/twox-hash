use std::{hash::Hasher as _, time::Instant};
use xx_hash_sys::XxHash3_64 as C;
use xx_renu::XxHash3_64;

fn main() {
    let filename = std::env::args().nth(1).expect("filename");
    let mode = std::env::args().nth(2);
    let mode = mode.as_deref().unwrap_or("rust-oneshot");
    let file = std::fs::read(filename).expect("read");
    let chunk_size = file.len() / 100;
    let chunk_size = usize::max(chunk_size, 1);

    let start = Instant::now();
    let hash = match mode {
        "rust-oneshot" => rust_oneshot(&file),
        "c-oneshot" => c_oneshot(&file),
        "rust-chunked" => rust_chunked(&file, chunk_size),
        "c-chunked" => c_chunked(&file, chunk_size),
        other => panic!("Unknown mode {other}"),
    };
    let elapsed = start.elapsed();

    eprintln!("{mode}\t{elapsed:?}\t{hash:016X}");
}

#[inline(never)]
fn rust_oneshot(file: &[u8]) -> u64 {
    XxHash3_64::oneshot(file)
}

#[inline(never)]
fn c_oneshot(file: &[u8]) -> u64 {
    C::oneshot(file)
}

#[inline(never)]
fn rust_chunked(file: &[u8], chunk_size: usize) -> u64 {
    let mut hasher = XxHash3_64::new();
    for chunk in file.chunks(chunk_size) {
        hasher.write(chunk);
    }
    hasher.finish()
}

#[inline(never)]
fn c_chunked(file: &[u8], chunk_size: usize) -> u64 {
    let mut hasher = C::new();
    for chunk in file.chunks(chunk_size) {
        hasher.write(chunk);
    }
    hasher.finish()
}
