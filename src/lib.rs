//! A Rust implementation of the [XXHash] algorithm.
//!
//! [XXHash]: https://github.com/Cyan4973/xxHash
//!
//! ### With a fixed seed
//!
//! ```rust
//! use std::hash::BuildHasherDefault;
//! use std::collections::HashMap;
//! use twox_hash::XxHash64;
//!
//! let mut hash: HashMap<_, _, BuildHasherDefault<XxHash64>> = Default::default();
//! hash.insert(42, "the answer");
//! assert_eq!(hash.get(&42), Some(&"the answer"));
//! ```
//!
//! ### With a random seed
//!
//! ```rust
//! use std::collections::HashMap;
//! use twox_hash::RandomXxHashBuilder64;
//!
//! let mut hash: HashMap<_, _, RandomXxHashBuilder64> = Default::default();
//! hash.insert(42, "the answer");
//! assert_eq!(hash.get(&42), Some(&"the answer"));
//! ```

#![no_std]

#[cfg(test)]
extern crate std;

mod sixty_four;
mod thirty_two;

#[cfg(feature = "std")]
mod std_support;
#[cfg(feature = "std")]
pub use std_support::sixty_four::RandomXxHashBuilder64;
#[cfg(feature = "std")]
pub use std_support::thirty_two::RandomXxHashBuilder32;

#[cfg(feature = "digest")]
mod digest_support;

pub use crate::sixty_four::XxHash64;
pub use crate::thirty_two::XxHash32;

/// A backwards compatibility type alias. Consider directly using
/// `XxHash64` instead.
pub type XxHash = XxHash64;

#[cfg(feature = "std")]
/// A backwards compatibility type alias. Consider directly using
/// `RandomXxHashBuilder64` instead.
pub type RandomXxHashBuilder = RandomXxHashBuilder64;

trait TransmutingByteSlices {
    fn as_u64_arrays(&self) -> (&[u8], &[[u64; 4]], &[u8]);
    fn as_u64s(&self) -> (&[u8], &[u64], &[u8]);
    fn as_u32_arrays(&self) -> (&[u8], &[[u32; 4]], &[u8]);
    fn as_u32s(&self) -> (&[u8], &[u32], &[u8]);
}

// # Safety
//
// - Interpreting a properly-aligned set of bytes as a `u64` should be
//   valid.
// - `align_to` guarantees to only transmute aligned data.
// - An array is a tightly-packed set of bytes (as shown by `impl
//   TryFrom<&[u8]> for &[u8; N]`)
impl TransmutingByteSlices for [u8] {
    fn as_u64_arrays(&self) -> (&[u8], &[[u64; 4]], &[u8]) {
        unsafe { self.align_to::<[u64; 4]>() }
    }

    fn as_u64s(&self) -> (&[u8], &[u64], &[u8]) {
        unsafe { self.align_to::<u64>() }
    }

    fn as_u32_arrays(&self) -> (&[u8], &[[u32; 4]], &[u8]) {
        unsafe { self.align_to::<[u32; 4]>() }
    }

    fn as_u32s(&self) -> (&[u8], &[u32], &[u8]) {
        unsafe { self.align_to::<u32>() }
    }
}
