use std::env;
use std::hash::Hasher;
use twox_hash::XxHash64;

fn main() {
    for arg in env::args().skip(1) {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(arg.as_bytes());

        println!("{:16x}   {}", hasher.finish(), arg);
    }
}
