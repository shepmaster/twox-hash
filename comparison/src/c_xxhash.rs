mod ffi {
    use libc::{c_void, size_t};

    #[allow(non_camel_case_types)]
    type XXH32_hash_t = u32;

    #[allow(non_camel_case_types)]
    type XXH64_hash_t = u64;

    #[allow(non_camel_case_types)]
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct XXH128_hash_t {
        pub low64: XXH64_hash_t,
        pub high64: XXH64_hash_t,
    }

    extern "C" {
        pub fn XXH32(input: *const c_void, length: size_t, seed: XXH32_hash_t) -> XXH32_hash_t;
        pub fn XXH64(input: *const c_void, length: size_t, seed: XXH64_hash_t) -> XXH64_hash_t;
        pub fn XXH3_64bits_withSeed(
            data: *const c_void,
            len: size_t,
            seed: XXH64_hash_t,
        ) -> XXH64_hash_t;
        pub fn XXH3_128bits_withSeed(
            data: *const c_void,
            len: size_t,
            seed: XXH64_hash_t,
        ) -> XXH128_hash_t;
    }
}

pub fn hash32(data: &[u8], seed: u32) -> u32 {
    unsafe { ffi::XXH32(data.as_ptr() as *const libc::c_void, data.len(), seed) }
}

pub fn hash64(data: &[u8], seed: u64) -> u64 {
    unsafe { ffi::XXH64(data.as_ptr() as *const libc::c_void, data.len(), seed) }
}

pub fn xxh3_hash64(data: &[u8], seed: u64) -> u64 {
    unsafe { ffi::XXH3_64bits_withSeed(data.as_ptr() as *const libc::c_void, data.len(), seed) }
}

pub fn xxh3_hash128(data: &[u8], seed: u64) -> u128 {
    let hash = unsafe {
        ffi::XXH3_128bits_withSeed(data.as_ptr() as *const libc::c_void, data.len(), seed)
    };

    u128::from(hash.low64) + (u128::from(hash.high64) << 64)
}
