#![no_std]
#![deny(rust_2018_idioms)]

#[cfg(test)]
extern crate std;

#[cfg(feature = "xxhash32")]
mod xxhash32;

#[cfg(feature = "xxhash32")]
pub use xxhash32::*;

#[cfg(feature = "xxhash64")]
mod xxhash64;

#[cfg(feature = "xxhash64")]
pub use xxhash64::*;

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
