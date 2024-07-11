//! A Rust implementation of the [XXHash][] algorithm.
//!
//! [XXHash]: https://github.com/Cyan4973/xxHash
//!
//! ## Hashing arbitrary data
//!
//! ### When all the data is available at once
//!
//! ```rust
//! use xx_renu::XxHash64;
//!
//! let seed = 1234;
//! let hash = XxHash64::oneshot(seed, b"some bytes");
//! assert_eq!(0xeab5_5659_a496_d78b, hash);
//! ```
//!
//! ### When the data is streaming
//!
//! ```rust
//! use std::hash::Hasher as _;
//! use xx_renu::XxHash64;
//!
//! let seed = 1234;
//! let mut hasher = XxHash64::with_seed(seed);
//! hasher.write(b"some");
//! hasher.write(b" ");
//! hasher.write(b"bytes");
//! let hash = hasher.finish();
//! assert_eq!(0xeab5_5659_a496_d78b, hash);
//! ```
//!
//! ## In a [`HashMap`](std::collections::HashMap)
//!
//! ### With a default seed
//!
//! ```rust
//! use std::{collections::HashMap, hash::BuildHasherDefault};
//! use xx_renu::XxHash64;
//!
//! let mut hash = HashMap::<_, _, BuildHasherDefault<XxHash64>>::default();
//! hash.insert(42, "the answer");
//! assert_eq!(hash.get(&42), Some(&"the answer"));
//! ```
//!
//! ### With a random seed
//!
//! ```rust
//! use std::collections::HashMap;
//! use xx_renu::xxhash64;
//!
//! let mut hash = HashMap::<_, _, xxhash64::RandomState>::default();
//! hash.insert(42, "the answer");
//! assert_eq!(hash.get(&42), Some(&"the answer"));
//! ```
//!
//! ### With a fixed seed
//!
//! ```rust
//! use std::collections::HashMap;
//! use xx_renu::xxhash64;
//!
//! let mut hash = HashMap::with_hasher(xxhash64::State::with_seed(0xdead_cafe));
//! hash.insert(42, "the answer");
//! assert_eq!(hash.get(&42), Some(&"the answer"));
//! ```

#![no_std]
#![deny(rust_2018_idioms)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(doc, test))]
extern crate std;

#[cfg(feature = "xxhash32")]
#[cfg_attr(docsrs, doc(cfg(feature = "xxhash32")))]
pub mod xxhash32;

#[cfg(feature = "xxhash32")]
#[cfg_attr(docsrs, doc(cfg(feature = "xxhash32")))]
pub use xxhash32::Hasher as XxHash32;

#[cfg(feature = "xxhash64")]
#[cfg_attr(docsrs, doc(cfg(feature = "xxhash64")))]
pub mod xxhash64;

#[cfg(feature = "xxhash64")]
#[cfg_attr(docsrs, doc(cfg(feature = "xxhash64")))]
pub use xxhash64::Hasher as XxHash64;

#[cfg(feature = "xxhash3_64")]
#[cfg_attr(docsrs, doc(cfg(feature = "xxhash3_64")))]
pub mod xxhash3_64;

#[cfg(feature = "xxhash3_64")]
#[cfg_attr(docsrs, doc(cfg(feature = "xxhash3_64")))]
pub use xxhash3_64::XxHash3_64;

trait IntoU32 {
    fn into_u32(self) -> u32;
}

impl IntoU32 for u8 {
    fn into_u32(self) -> u32 {
        self.into()
    }
}

trait IntoU64 {
    fn into_u64(self) -> u64;
}

impl IntoU64 for u8 {
    fn into_u64(self) -> u64 {
        self.into()
    }
}

impl IntoU64 for u32 {
    fn into_u64(self) -> u64 {
        self.into()
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl IntoU64 for usize {
    fn into_u64(self) -> u64 {
        self as u64
    }
}

trait IntoU128 {
    fn into_u128(self) -> u128;
}

impl IntoU128 for u64 {
    fn into_u128(self) -> u128 {
        u128::from(self)
    }
}
