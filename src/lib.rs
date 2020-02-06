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

use core::{marker::PhantomData, mem};

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

/// An unaligned buffer with iteration support for `UnalignedItem`.
struct UnalignedBuffer<'a, T> {
    buf: &'a [u8],
    phantom: PhantomData<T>,
}

/// Types implementing this trait must be transmutable from a `*const
/// u8` to `*const Self` at any possible alignment.
///
/// The intent is to use this with only primitive integer types (and
/// tightly-packed arrays of those integers).
unsafe trait UnalignedItem {
    // xxhash specifies the data it processes should be little endian
    // which means information ingested on big-endian platforms needs
    // to have its contents byte-swapped prior to being digested.
    fn correct_endian(self) -> Self;
}

unsafe impl UnalignedItem for [u64; 4] {
    #[inline]
    fn correct_endian(self) -> Self {
        #[allow(unused_mut)]
        let mut result = self;
        #[cfg(target_endian = "big")]
        {
            for ptr in result.iter_mut() {
                *ptr = (*ptr).byte_swap();
            }
        }
        result
    }
}
unsafe impl UnalignedItem for [u32; 4] {
    #[inline]
    fn correct_endian(self) -> Self {
        #[allow(unused_mut)]
        let mut result = self;
        #[cfg(target_endian = "big")]
        {
            for ptr in result.iter_mut() {
                *ptr = (*ptr).byte_swap();
            }
        }
        result
    }
}
unsafe impl UnalignedItem for u64 {
    #[inline]
    fn correct_endian(self) -> Self {
        #[allow(unused_mut)]
        let mut result = self;
        #[cfg(target_endian = "big")]
        {
            result = result.byte_swap();
        }
        result
    }
}
unsafe impl UnalignedItem for u32 {
    #[inline]
    fn correct_endian(self) -> Self {
        #[allow(unused_mut)]
        let mut result = self;
        #[cfg(target_endian = "big")]
        {
            result = result.byte_swap();
        }
        result
    }
}

impl<'a, T: UnalignedItem> UnalignedBuffer<'a, T> {
    #[inline]
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            phantom: PhantomData,
        }
    }

    #[inline]
    fn remaining(&self) -> &[u8] {
        self.buf
    }
}

impl<'a, T: UnalignedItem> Iterator for UnalignedBuffer<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let size = mem::size_of::<T>();
        self.buf.get(size..).map(|remaining| {
            // `self.buf` has at least `size` bytes that can be read as `T`.
            let result = unsafe { (self.buf.as_ptr() as *const T).read_unaligned() };
            self.buf = remaining;
            result.correct_endian()
        })
    }
}
