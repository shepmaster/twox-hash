#![allow(non_camel_case_types)]

type XXH_errorcode = libc::c_int;
const XXH_OK: XXH_errorcode = 0;

// ----------

type XXH32_hash_t = u32;

#[repr(C)]
pub struct XXH32_state_t {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

extern "C" {
    fn XXH32(input: *const libc::c_void, length: libc::size_t, seed: XXH32_hash_t) -> XXH32_hash_t;

    fn XXH32_createState() -> *mut XXH32_state_t;
    fn XXH32_reset(state: *mut XXH32_state_t, seed: XXH32_hash_t) -> XXH_errorcode;
    fn XXH32_update(
        state: *mut XXH32_state_t,
        buffer: *const libc::c_void,
        length: libc::size_t,
    ) -> XXH_errorcode;
    fn XXH32_digest(state: *mut XXH32_state_t) -> XXH32_hash_t;
    fn XXH32_freeState(state: *mut XXH32_state_t) -> XXH_errorcode;
}

pub struct XxHash32(*mut XXH32_state_t);

impl XxHash32 {
    pub fn oneshot(seed: u32, data: &[u8]) -> u32 {
        unsafe { XXH32(data.as_ptr().cast(), data.len(), seed) }
    }

    pub fn with_seed(seed: u32) -> Self {
        let state = unsafe {
            let state = XXH32_createState();
            XXH32_reset(state, seed);
            state
        };

        Self(state)
    }

    pub fn write(&mut self, data: &[u8]) {
        let retval = unsafe { XXH32_update(self.0, data.as_ptr().cast(), data.len()) };
        assert_eq!(retval, XXH_OK);
    }

    pub fn finish(&mut self) -> u32 {
        unsafe { XXH32_digest(self.0) }
    }
}

impl Drop for XxHash32 {
    fn drop(&mut self) {
        let retval = unsafe { XXH32_freeState(self.0) };
        assert_eq!(retval, XXH_OK);
    }
}

// ----------

type XXH64_hash_t = u64;

#[repr(C)]
pub struct XXH64_state_t {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

extern "C" {
    fn XXH64(input: *const libc::c_void, length: libc::size_t, seed: XXH64_hash_t) -> XXH64_hash_t;

    fn XXH64_createState() -> *mut XXH64_state_t;
    fn XXH64_reset(state: *mut XXH64_state_t, seed: XXH64_hash_t) -> XXH_errorcode;
    fn XXH64_update(
        state: *mut XXH64_state_t,
        buffer: *const libc::c_void,
        length: libc::size_t,
    ) -> XXH_errorcode;
    fn XXH64_digest(state: *mut XXH64_state_t) -> XXH64_hash_t;
    fn XXH64_freeState(state: *mut XXH64_state_t) -> XXH_errorcode;
}

pub struct XxHash64(*mut XXH64_state_t);

impl XxHash64 {
    pub fn oneshot(seed: u64, data: &[u8]) -> u64 {
        unsafe { XXH64(data.as_ptr().cast(), data.len(), seed) }
    }

    pub fn with_seed(seed: u64) -> Self {
        let state = unsafe {
            let state = XXH64_createState();
            XXH64_reset(state, seed);
            state
        };

        Self(state)
    }

    pub fn write(&mut self, data: &[u8]) {
        let retval = unsafe { XXH64_update(self.0, data.as_ptr().cast(), data.len()) };
        assert_eq!(retval, XXH_OK);
    }

    pub fn finish(&mut self) -> u64 {
        unsafe { XXH64_digest(self.0) }
    }
}

impl Drop for XxHash64 {
    fn drop(&mut self) {
        let retval = unsafe { XXH64_freeState(self.0) };
        assert_eq!(retval, XXH_OK);
    }
}

// ----------

#[repr(C)]
pub struct XXH3_state_t {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

extern "C" {
    fn XXH3_64bits(input: *const libc::c_void, length: libc::size_t) -> XXH64_hash_t;
    fn XXH3_64bits_withSeed(
        input: *const libc::c_void,
        length: libc::size_t,
        seed: XXH64_hash_t,
    ) -> XXH64_hash_t;
    fn XXH3_64bits_withSecret(
        input: *const libc::c_void,
        length: libc::size_t,
        secret: *const libc::c_void,
        secret_length: libc::size_t,
    ) -> XXH64_hash_t;

    fn XXH3_createState() -> *mut XXH3_state_t;
    fn XXH3_64bits_reset(state: *mut XXH3_state_t) -> XXH_errorcode;
    fn XXH3_64bits_update(
        state: *mut XXH3_state_t,
        buffer: *const libc::c_void,
        length: libc::size_t,
    ) -> XXH_errorcode;
    fn XXH3_64bits_digest(state: *mut XXH3_state_t) -> XXH64_hash_t;
    fn XXH3_freeState(state: *mut XXH3_state_t) -> XXH_errorcode;
}

pub struct XxHash3_64(*mut XXH3_state_t);

impl XxHash3_64 {
    pub fn oneshot(data: &[u8]) -> u64 {
        unsafe { XXH3_64bits(data.as_ptr().cast(), data.len()) }
    }

    pub fn oneshot_with_seed(seed: u64, data: &[u8]) -> u64 {
        unsafe { XXH3_64bits_withSeed(data.as_ptr().cast(), data.len(), seed) }
    }

    pub fn oneshot_with_secret(secret: &[u8], data: &[u8]) -> u64 {
        unsafe {
            XXH3_64bits_withSecret(
                data.as_ptr().cast(),
                data.len(),
                secret.as_ptr().cast(),
                secret.len(),
            )
        }
    }

    pub fn with_seed() -> Self {
        let state = unsafe {
            let state = XXH3_createState();
            XXH3_64bits_reset(state);
            state
        };

        Self(state)
    }

    pub fn write(&mut self, data: &[u8]) {
        let retval = unsafe { XXH3_64bits_update(self.0, data.as_ptr().cast(), data.len()) };
        assert_eq!(retval, XXH_OK);
    }

    pub fn finish(&mut self) -> u64 {
        unsafe { XXH3_64bits_digest(self.0) }
    }
}

impl Drop for XxHash3_64 {
    fn drop(&mut self) {
        let retval = unsafe { XXH3_freeState(self.0) };
        assert_eq!(retval, XXH_OK);
    }
}

// ----------

extern "C" {
    fn scalar_XXH3_64bits(input: *const libc::c_void, length: libc::size_t) -> XXH64_hash_t;
    fn scalar_XXH3_64bits_withSeed(
        input: *const libc::c_void,
        length: libc::size_t,
        seed: XXH64_hash_t,
    ) -> XXH64_hash_t;
    fn scalar_XXH3_64bits_withSecret(
        input: *const libc::c_void,
        length: libc::size_t,
        secret: *const libc::c_void,
        secret_length: libc::size_t,
    ) -> XXH64_hash_t;

    fn scalar_XXH3_createState() -> *mut XXH3_state_t;
    fn scalar_XXH3_64bits_reset(state: *mut XXH3_state_t) -> XXH_errorcode;
    fn scalar_XXH3_64bits_update(
        state: *mut XXH3_state_t,
        buffer: *const libc::c_void,
        length: libc::size_t,
    ) -> XXH_errorcode;
    fn scalar_XXH3_64bits_digest(state: *mut XXH3_state_t) -> XXH64_hash_t;
    fn scalar_XXH3_freeState(state: *mut XXH3_state_t) -> XXH_errorcode;
}

pub struct ScalarXxHash3_64(*mut XXH3_state_t);

impl ScalarXxHash3_64 {
    pub fn oneshot(data: &[u8]) -> u64 {
        unsafe { scalar_XXH3_64bits(data.as_ptr().cast(), data.len()) }
    }

    pub fn oneshot_with_seed(seed: u64, data: &[u8]) -> u64 {
        unsafe { scalar_XXH3_64bits_withSeed(data.as_ptr().cast(), data.len(), seed) }
    }

    pub fn oneshot_with_secret(secret: &[u8], data: &[u8]) -> u64 {
        unsafe {
            scalar_XXH3_64bits_withSecret(
                data.as_ptr().cast(),
                data.len(),
                secret.as_ptr().cast(),
                secret.len(),
            )
        }
    }

    pub fn with_seed() -> Self {
        let state = unsafe {
            let state = scalar_XXH3_createState();
            scalar_XXH3_64bits_reset(state);
            state
        };

        Self(state)
    }

    pub fn write(&mut self, data: &[u8]) {
        let retval = unsafe { scalar_XXH3_64bits_update(self.0, data.as_ptr().cast(), data.len()) };
        assert_eq!(retval, XXH_OK);
    }

    pub fn finish(&mut self) -> u64 {
        unsafe { scalar_XXH3_64bits_digest(self.0) }
    }
}

impl Drop for ScalarXxHash3_64 {
    fn drop(&mut self) {
        let retval = unsafe { scalar_XXH3_freeState(self.0) };
        assert_eq!(retval, XXH_OK);
    }
}
