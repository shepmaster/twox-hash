#![no_std]
#![deny(rust_2018_idioms)]

#[cfg(test)]
extern crate std;

#[cfg(feature = "xxhash64")]
mod xxhash64;

#[cfg(feature = "xxhash64")]
pub use xxhash64::*;
