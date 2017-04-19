#![cfg_attr(feature = "bench", feature(test))]

extern crate twox_hash;



#[cfg(all(feature = "bench", test))]
extern crate fnv;

#[cfg(all(feature = "bench", test))]
extern crate test;

#[cfg(all(feature = "bench", test))]
mod bench;
