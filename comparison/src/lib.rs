#![cfg_attr(feature = "bench", feature(test))]

extern crate twox_hash;



#[cfg(all(feature = "bench", test))]
extern crate fnv;

#[cfg(all(feature = "bench", test))]
extern crate test;

#[cfg(all(feature = "bench", test))]
mod bench;



#[cfg(all(feature = "quickcheck", test))]
extern crate quickcheck;

#[cfg(all(feature = "quickcheck", test))]
extern crate libc;

#[cfg(all(feature = "quickcheck", test))]
extern crate rand;

#[cfg(all(feature = "quickcheck", test))]
mod c_xxhash;

#[cfg(all(feature = "quickcheck", test))]
mod same;
