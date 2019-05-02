mod ffi {
    use libc::{c_void, size_t, uint32_t, uint64_t};

    #[allow(non_camel_case_types)]
    type XXH32_hash_t = uint32_t;

    #[allow(non_camel_case_types)]
    type XXH64_hash_t = uint64_t;

    extern "C" {
        pub fn XXH32(input: *const c_void, length: size_t, seed: uint32_t) -> XXH32_hash_t;
        pub fn XXH64(input: *const c_void, length: size_t, seed: uint64_t) -> XXH64_hash_t;
    }
}

pub fn hash32(data: &[u8], seed: u32) -> u32 {
    unsafe { ffi::XXH32(data.as_ptr() as *const libc::c_void, data.len(), seed) }
}

pub fn hash64(data: &[u8], seed: u64) -> u64 {
    unsafe { ffi::XXH64(data.as_ptr() as *const libc::c_void, data.len(), seed) }
}
