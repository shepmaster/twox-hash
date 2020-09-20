#![cfg(test)]

use digest::Digest;
use twox_hash::XxHash64;

#[test]
fn it_works() {
    fn implements_digest<T: Digest>() {}

    implements_digest::<XxHash64>();
}
