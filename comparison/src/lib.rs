#![cfg_attr(feature = "bench", feature(test))]

extern crate libc;
extern crate twox_hash;

pub mod c_xxhash;

#[cfg(all(feature = "quickcheck", test))]
extern crate quickcheck;

#[cfg(all(feature = "quickcheck", test))]
extern crate rand;

#[cfg(all(feature = "quickcheck", test))]
mod same;
