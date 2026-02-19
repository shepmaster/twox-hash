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
    #[inline]
    pub fn oneshot(seed: u32, data: &[u8]) -> u32 {
        unsafe { XXH32(data.as_ptr().cast(), data.len(), seed) }
    }

    #[inline]
    pub fn with_seed(seed: u32) -> Self {
        let state = unsafe {
            let state = XXH32_createState();
            XXH32_reset(state, seed);
            state
        };

        Self(state)
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        let retval = unsafe { XXH32_update(self.0, data.as_ptr().cast(), data.len()) };
        assert_eq!(retval, XXH_OK);
    }

    #[inline]
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
    #[inline]
    pub fn oneshot(seed: u64, data: &[u8]) -> u64 {
        unsafe { XXH64(data.as_ptr().cast(), data.len(), seed) }
    }

    #[inline]
    pub fn with_seed(seed: u64) -> Self {
        let state = unsafe {
            let state = XXH64_createState();
            XXH64_reset(state, seed);
            state
        };

        Self(state)
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        let retval = unsafe { XXH64_update(self.0, data.as_ptr().cast(), data.len()) };
        assert_eq!(retval, XXH_OK);
    }

    #[inline]
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

#[repr(C)]
pub struct XXH128_hash_t {
    low64: XXH64_hash_t,
    high64: XXH64_hash_t,
}

impl From<XXH128_hash_t> for u128 {
    fn from(value: XXH128_hash_t) -> Self {
        u128::from(value.high64) << 64 | u128::from(value.low64)
    }
}

/// Constructs a wrapper around the XXH3_* familiy of functions as we
/// compile the library in multiple modes to performance test against.
macro_rules! xxh3_template {
    () => { crate::xxh3_template!(@ XXH3); };

    ($prefix: ident) => { ::paste::paste! { crate::xxh3_template!(@ [< $prefix _XXH3 >]); } };

    (@ $prefix: ident) => {
        ::paste::paste! {
            extern "C" {
                fn [<$prefix _createState>]() -> *mut crate::XXH3_state_t;
                fn [<$prefix _freeState>](state: *mut crate::XXH3_state_t) -> crate::XXH_errorcode;
            }
        }
    };
}
pub(crate) use xxh3_template;

/// Constructs a wrapper around the XXH3_64bit familiy of functions as
/// we compile the library in multiple modes to performance test
/// against.
macro_rules! xxh3_64b_template {
    () => { crate::xxh3_64b_template!(@ XXH3); };

    ($prefix: ident) => { ::paste::paste! { crate::xxh3_64b_template!(@ [< $prefix _XXH3 >]); } };

    (@ $prefix: ident) => {
        ::paste::paste! {
            extern "C" {
                fn [<$prefix _64bits>](input: *const libc::c_void, length: libc::size_t) -> crate::XXH64_hash_t;
                fn [<$prefix _64bits_withSeed>](
                    input: *const libc::c_void,
                    length: libc::size_t,
                    seed: crate::XXH64_hash_t,
                ) -> crate::XXH64_hash_t;
                fn [<$prefix _64bits_withSecret>](
                    input: *const libc::c_void,
                    length: libc::size_t,
                    secret: *const libc::c_void,
                    secret_length: libc::size_t,
                ) -> crate::XXH64_hash_t;
                fn [<$prefix _64bits_withSecretandSeed>](
                    input: *const libc::c_void,
                    length: libc::size_t,
                    secret: *const libc::c_void,
                    secret_length: libc::size_t,
                    seed: crate::XXH64_hash_t,
                ) -> crate::XXH64_hash_t;

                fn [<$prefix _64bits_reset>](state: *mut crate::XXH3_state_t) -> crate::XXH_errorcode;
                fn [<$prefix _64bits_reset_withSeed>](
                    state: *mut crate::XXH3_state_t,
                    seed: crate::XXH64_hash_t,
                ) -> crate::XXH_errorcode;
                fn [<$prefix _64bits_reset_withSecretandSeed>](
                    state: *mut crate::XXH3_state_t,
                    secret: *const libc::c_void,
                    secret_length: libc::size_t,
                    seed: crate::XXH64_hash_t,
                ) -> crate::XXH_errorcode;
                fn [<$prefix _64bits_update>](
                    state: *mut crate::XXH3_state_t,
                    buffer: *const libc::c_void,
                    length: libc::size_t,
                ) -> crate::XXH_errorcode;
                fn [<$prefix _64bits_digest>](state: *mut crate::XXH3_state_t) -> crate::XXH64_hash_t;
            }

            pub struct XxHash3_64(*mut crate::XXH3_state_t);

            impl XxHash3_64 {
                #[inline]
                pub fn oneshot(data: &[u8]) -> u64 {
                    unsafe { [<$prefix _64bits>](data.as_ptr().cast(), data.len()) }
                }

                #[inline]
                pub fn oneshot_with_seed(seed: u64, data: &[u8]) -> u64 {
                    unsafe { [<$prefix _64bits_withSeed>](data.as_ptr().cast(), data.len(), seed) }
                }

                #[inline]
                pub fn oneshot_with_secret(secret: &[u8], data: &[u8]) -> u64 {
                    unsafe {
                        [<$prefix _64bits_withSecret>](
                            data.as_ptr().cast(),
                            data.len(),
                            secret.as_ptr().cast(),
                            secret.len(),
                        )
                    }
                }

                #[inline]
                pub fn oneshot_with_seed_and_secret(seed: u64, secret: &[u8], data: &[u8]) -> u64 {
                    unsafe {
                        [<$prefix _64bits_withSecretandSeed>](
                            data.as_ptr().cast(),
                            data.len(),
                            secret.as_ptr().cast(),
                            secret.len(),
                            seed,
                        )
                    }
                }

                #[inline]
                #[expect(clippy::new_without_default, reason = "Just testing code")]
                pub fn new() -> Self {
                    let state = unsafe {
                        let state = [<$prefix _createState>]();
                        [<$prefix _64bits_reset>](state);
                        state
                    };

                    Self(state)
                }

                #[inline]
                pub fn with_seed(seed: u64) -> Self {
                    let state = unsafe {
                        let state = [<$prefix _createState>]();
                        [<$prefix _64bits_reset_withSeed>](state, seed);
                        state
                    };

                    Self(state)
                }

                #[inline]
                pub fn with_seed_and_secret(seed: u64, secret: &[u8]) -> Self {
                    let state = unsafe {
                        let state = [<$prefix _createState>]();
                        [<$prefix _64bits_reset_withSecretandSeed>](state, secret.as_ptr().cast(), secret.len(), seed);
                        state
                    };

                    Self(state)
                }

                #[inline]
                pub fn write(&mut self, data: &[u8]) {
                    let retval =
                    unsafe { [<$prefix _64bits_update>](self.0, data.as_ptr().cast(), data.len()) };
                    assert_eq!(retval, crate::XXH_OK);
                }

                #[inline]
                pub fn finish(&mut self) -> u64 {
                    unsafe { [<$prefix _64bits_digest>](self.0) }
                }
            }

            impl Drop for XxHash3_64 {
                fn drop(&mut self) {
                    let retval = unsafe { [<$prefix _freeState>](self.0) };
                    assert_eq!(retval, crate::XXH_OK);
                }
            }
        }
    };
}
pub(crate) use xxh3_64b_template;

/// Constructs a wrapper around the XXH3_128bit familiy of functions as
/// we compile the library in multiple modes to performance test
/// against.
macro_rules! xxh3_128b_template {
    () => { crate::xxh3_128b_template!(@ XXH3); };

    ($prefix: ident) => { ::paste::paste! { crate::xxh3_128b_template!(@ [< $prefix _XXH3 >]); } };

    (@ $prefix: ident) => {
        ::paste::paste! {
            extern "C" {
                fn [<$prefix _128bits>](input: *const libc::c_void, length: libc::size_t) -> crate::XXH128_hash_t;
                fn [<$prefix _128bits_withSeed>](
                    input: *const libc::c_void,
                    length: libc::size_t,
                    seed: crate::XXH64_hash_t,
                ) -> crate::XXH128_hash_t;
                fn [<$prefix _128bits_withSecret>](
                    input: *const libc::c_void,
                    length: libc::size_t,
                    secret: *const libc::c_void,
                    secret_length: libc::size_t,
                ) -> crate::XXH128_hash_t;
                fn [<$prefix _128bits_withSecretandSeed>](
                    input: *const libc::c_void,
                    length: libc::size_t,
                    secret: *const libc::c_void,
                    secret_length: libc::size_t,
                    seed: crate::XXH64_hash_t,
                ) -> crate::XXH128_hash_t;

                fn [<$prefix _128bits_reset>](state: *mut crate::XXH3_state_t) -> crate::XXH_errorcode;
                fn [<$prefix _128bits_reset_withSeed>](
                    state: *mut crate::XXH3_state_t,
                    seed: crate::XXH64_hash_t,
                ) -> crate::XXH_errorcode;
                fn [<$prefix _128bits_reset_withSecretandSeed>](
                    state: *mut crate::XXH3_state_t,
                    secret: *const libc::c_void,
                    secret_length: libc::size_t,
                    seed: crate::XXH64_hash_t,
                ) -> crate::XXH_errorcode;
                fn [<$prefix _128bits_update>](
                    state: *mut crate::XXH3_state_t,
                    buffer: *const libc::c_void,
                    length: libc::size_t,
                ) -> crate::XXH_errorcode;
                fn [<$prefix _128bits_digest>](state: *mut crate::XXH3_state_t) -> crate::XXH128_hash_t;
            }

            pub struct XxHash3_128(*mut crate::XXH3_state_t);

            impl XxHash3_128 {
                #[inline]
                pub fn oneshot(data: &[u8]) -> u128 {
                    unsafe { [<$prefix _128bits>](data.as_ptr().cast(), data.len()) }.into()
                }

                #[inline]
                pub fn oneshot_with_seed(seed: u64, data: &[u8]) -> u128 {
                    unsafe { [<$prefix _128bits_withSeed>](data.as_ptr().cast(), data.len(), seed) }.into()
                }

                #[inline]
                pub fn oneshot_with_secret(secret: &[u8], data: &[u8]) -> u128 {
                    unsafe {
                        [<$prefix _128bits_withSecret>](
                            data.as_ptr().cast(),
                            data.len(),
                            secret.as_ptr().cast(),
                            secret.len(),
                        )
                    }.into()
                }

                #[inline]
                pub fn oneshot_with_seed_and_secret(seed: u64, secret: &[u8], data: &[u8]) -> u128 {
                    unsafe {
                        [<$prefix _128bits_withSecretandSeed>](
                            data.as_ptr().cast(),
                            data.len(),
                            secret.as_ptr().cast(),
                            secret.len(),
                            seed,
                        )
                    }.into()
                }

                #[expect(clippy::new_without_default, reason = "Just testing code")]
                #[inline]
                pub fn new() -> Self {
                    let state = unsafe {
                        let state = [<$prefix _createState>]();
                        [<$prefix _128bits_reset>](state);
                        state
                    };

                    Self(state)
                }

                #[inline]
                pub fn with_seed(seed: u64) -> Self {
                    let state = unsafe {
                        let state = [<$prefix _createState>]();
                        [<$prefix _128bits_reset_withSeed>](state, seed);
                        state
                    };

                    Self(state)
                }

                #[inline]
                pub fn with_seed_and_secret(seed: u64, secret: &[u8]) -> Self {
                    let state = unsafe {
                        let state = [<$prefix _createState>]();
                        [<$prefix _128bits_reset_withSecretandSeed>](state, secret.as_ptr().cast(), secret.len(), seed);
                        state
                    };

                    Self(state)
                }

                #[inline]
                pub fn write(&mut self, data: &[u8]) {
                    let retval =
                    unsafe { [<$prefix _128bits_update>](self.0, data.as_ptr().cast(), data.len()) };
                    assert_eq!(retval, crate::XXH_OK);
                }

                #[inline]
                pub fn finish(&mut self) -> u128 {
                    unsafe { [<$prefix _128bits_digest>](self.0) }.into()
                }
            }

            impl Drop for XxHash3_128 {
                fn drop(&mut self) {
                    let retval = unsafe { [<$prefix _freeState>](self.0) };
                    assert_eq!(retval, crate::XXH_OK);
                }
            }
        }
    };
}
pub(crate) use xxh3_128b_template;

xxh3_template!();
xxh3_64b_template!();
xxh3_128b_template!();

pub mod scalar {
    crate::xxh3_template!(scalar);
    crate::xxh3_64b_template!(scalar);
    crate::xxh3_128b_template!(scalar);
}

#[cfg(target_arch = "aarch64")]
pub mod neon {
    crate::xxh3_template!(neon);
    crate::xxh3_64b_template!(neon);
    crate::xxh3_128b_template!(neon);
}

#[cfg(target_arch = "x86_64")]
pub mod avx2 {
    crate::xxh3_template!(avx2);
    crate::xxh3_64b_template!(avx2);
    crate::xxh3_128b_template!(avx2);
}

#[cfg(target_arch = "x86_64")]
pub mod sse2 {
    crate::xxh3_template!(sse2);
    crate::xxh3_64b_template!(sse2);
    crate::xxh3_128b_template!(sse2);
}
