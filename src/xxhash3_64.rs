//! The implementation of XXH3_64.

#![deny(
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks,
    unsafe_op_in_unsafe_fn
)]

use core::{hash, hint::assert_unchecked, slice};

use crate::{IntoU128, IntoU32, IntoU64};

mod secret;

use secret::Secret;

pub use secret::SECRET_MINIMUM_LENGTH;

// This module is not `cfg`-gated because it is used by some of the
// SIMD implementations.
mod scalar;

#[cfg(target_arch = "aarch64")]
mod neon;

#[cfg(target_arch = "x86_64")]
mod avx2;

#[cfg(target_arch = "x86_64")]
mod sse2;

const PRIME32_1: u64 = 0x9E3779B1;
const PRIME32_2: u64 = 0x85EBCA77;
const PRIME32_3: u64 = 0xC2B2AE3D;
const PRIME64_1: u64 = 0x9E3779B185EBCA87;
const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME64_3: u64 = 0x165667B19E3779F9;
const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
const PRIME64_5: u64 = 0x27D4EB2F165667C5;
const PRIME_MX1: u64 = 0x165667919E3779F9;
const PRIME_MX2: u64 = 0x9FB21C651E98DF25;

const CUTOFF: usize = 240;

const DEFAULT_SEED: u64 = 0;

/// The length of the default secret.
pub const DEFAULT_SECRET_LENGTH: usize = 192;

type DefaultSecret = [u8; DEFAULT_SECRET_LENGTH];

const DEFAULT_SECRET_RAW: DefaultSecret = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

// Safety: The default secret is long enough
const DEFAULT_SECRET: &Secret = unsafe { Secret::new_unchecked(&DEFAULT_SECRET_RAW) };

/// Calculates the 64-bit hash.
#[derive(Clone)]
pub struct Hasher {
    #[cfg(feature = "alloc")]
    inner: with_alloc::AllocRawHasher,
    _private: (),
}

impl Hasher {
    /// Hash all data at once. If you can use this function, you may
    /// see noticable speed gains for certain types of input.
    #[must_use]
    #[inline]
    pub fn oneshot(input: &[u8]) -> u64 {
        impl_oneshot(DEFAULT_SECRET, DEFAULT_SEED, input)
    }

    /// Hash all data at once using the provided seed and a secret
    /// derived from the seed. If you can use this function, you may
    /// see noticable speed gains for certain types of input.
    #[must_use]
    #[inline]
    pub fn oneshot_with_seed(seed: u64, input: &[u8]) -> u64 {
        let mut secret = DEFAULT_SECRET_RAW;

        // We know that the secret will only be used if we have more
        // than 240 bytes, so don't waste time computing it otherwise.
        if input.len() > CUTOFF {
            derive_secret(seed, &mut secret);
        }

        let secret = Secret::new(&secret).expect("The default secret length is invalid");

        impl_oneshot(secret, seed, input)
    }

    /// Hash all data at once using the provided secret and the
    /// default seed. If you can use this function, you may see
    /// noticable speed gains for certain types of input.
    #[inline]
    pub fn oneshot_with_secret(secret: &[u8], input: &[u8]) -> Result<u64, OneshotWithSecretError> {
        let secret = Secret::new(secret).map_err(OneshotWithSecretError)?;
        Ok(impl_oneshot(secret, DEFAULT_SEED, input))
    }

    /// Hash all data at once using the provided seed and secret. If
    /// you can use this function, you may see noticable speed gains
    /// for certain types of input.
    #[inline]
    pub fn oneshot_with_seed_and_secret(
        seed: u64,
        secret: &[u8],
        input: &[u8],
    ) -> Result<u64, OneshotWithSecretError> {
        let secret = if input.len() > CUTOFF {
            Secret::new(secret).map_err(OneshotWithSecretError)?
        } else {
            DEFAULT_SECRET
        };

        Ok(impl_oneshot(secret, seed, input))
    }
}

/// The provided secret was not at least [`SECRET_MINIMUM_LENGTH`][]
/// bytes.
#[derive(Debug)]
pub struct OneshotWithSecretError(secret::Error);

impl core::error::Error for OneshotWithSecretError {}

impl core::fmt::Display for OneshotWithSecretError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

const STRIPE_BYTES: usize = 64;
const BUFFERED_STRIPES: usize = 4;
const BUFFERED_BYTES: usize = STRIPE_BYTES * BUFFERED_STRIPES;
type Buffer = [u8; BUFFERED_BYTES];

// Ensure that a full buffer always implies we are in the 241+ byte case.
const _: () = assert!(BUFFERED_BYTES > CUTOFF);

/// A buffer containing the secret bytes.
///
/// # Safety
///
/// Must always return a slice with the same number of elements.
pub unsafe trait FixedBuffer: AsRef<[u8]> {}

/// A mutable buffer to contain the secret bytes.
///
/// # Safety
///
/// Must always return a slice with the same number of elements. The
/// slice must always be the same as that returned from
/// [`AsRef::as_ref`][].
pub unsafe trait FixedMutBuffer: FixedBuffer + AsMut<[u8]> {}

// Safety: An array will never change size.
unsafe impl<const N: usize> FixedBuffer for [u8; N] {}

// Safety: An array will never change size.
unsafe impl<const N: usize> FixedMutBuffer for [u8; N] {}

// Safety: An array will never change size.
unsafe impl<const N: usize> FixedBuffer for &[u8; N] {}

// Safety: An array will never change size.
unsafe impl<const N: usize> FixedBuffer for &mut [u8; N] {}

// Safety: An array will never change size.
unsafe impl<const N: usize> FixedMutBuffer for &mut [u8; N] {}

/// Holds secret and temporary buffers that are ensured to be
/// appropriately sized.
#[derive(Clone)]
pub struct SecretBuffer<S> {
    seed: u64,
    secret: S,
    buffer: Buffer,
}

impl<S> SecretBuffer<S>
where
    S: FixedBuffer,
{
    /// Takes the seed, secret, and buffer and performs no
    /// modifications to them, only validating that the sizes are
    /// appropriate.
    pub fn new(seed: u64, secret: S) -> Result<Self, SecretTooShortError<S>> {
        match Secret::new(secret.as_ref()) {
            Ok(_) => Ok(Self {
                seed,
                secret,
                buffer: [0; BUFFERED_BYTES],
            }),
            Err(e) => Err(SecretTooShortError(e, secret)),
        }
    }

    #[inline(always)]
    #[cfg(test)]
    fn is_valid(&self) -> bool {
        let secret = self.secret.as_ref();

        secret.len() >= SECRET_MINIMUM_LENGTH
    }

    #[inline]
    fn n_stripes(&self) -> usize {
        Self::secret(&self.secret).n_stripes()
    }

    #[inline]
    fn parts(&self) -> (u64, &Secret, &Buffer) {
        (self.seed, Self::secret(&self.secret), &self.buffer)
    }

    #[inline]
    fn parts_mut(&mut self) -> (u64, &Secret, &mut Buffer) {
        (self.seed, Self::secret(&self.secret), &mut self.buffer)
    }

    fn secret(secret: &S) -> &Secret {
        let secret = secret.as_ref();
        // Safety: We established the length at construction and the
        // length is not allowed to change.
        unsafe { Secret::new_unchecked(secret) }
    }
}

impl<S> SecretBuffer<S> {
    /// Returns the secret.
    pub fn into_secret(self) -> S {
        self.secret
    }
}

impl SecretBuffer<&'static [u8; DEFAULT_SECRET_LENGTH]> {
    /// Use the default seed and secret values while allocating nothing.
    ///
    /// Note that this type may take up a surprising amount of stack space.
    #[inline]
    pub const fn default() -> Self {
        SecretBuffer {
            seed: DEFAULT_SEED,
            secret: &DEFAULT_SECRET_RAW,
            buffer: [0; BUFFERED_BYTES],
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
mod with_alloc {
    use ::alloc::boxed::Box;

    use super::*;

    // Safety: A plain slice will never change size.
    unsafe impl FixedBuffer for Box<[u8]> {}

    // Safety: A plain slice will never change size.
    unsafe impl FixedMutBuffer for Box<[u8]> {}

    impl Hasher {
        /// Constructs the hasher using the default seed and secret values.
        pub fn new() -> Self {
            Self {
                inner: RawHasher::allocate_default(),
                _private: (),
            }
        }

        /// Constructs the hasher using the provided seed and a secret
        /// derived from the seed.
        pub fn with_seed(seed: u64) -> Self {
            Self {
                inner: RawHasher::allocate_with_seed(seed),
                _private: (),
            }
        }

        /// Constructs the hasher using the provided seed and secret.
        pub fn with_seed_and_secret(
            seed: u64,
            secret: impl Into<Box<[u8]>>,
        ) -> Result<Self, SecretTooShortError<Box<[u8]>>> {
            Ok(Self {
                inner: RawHasher::allocate_with_seed_and_secret(seed, secret)?,
                _private: (),
            })
        }

        /// Returns the secret.
        pub fn into_secret(self) -> Box<[u8]> {
            self.inner.into_secret()
        }
    }

    impl Default for Hasher {
        fn default() -> Self {
            Self::new()
        }
    }

    impl hash::Hasher for Hasher {
        #[inline]
        fn write(&mut self, input: &[u8]) {
            self.inner.write(input)
        }

        #[inline]
        fn finish(&self) -> u64 {
            self.inner.finish()
        }
    }

    type AllocSecretBuffer = SecretBuffer<Box<[u8]>>;

    impl AllocSecretBuffer {
        /// Allocates the secret and temporary buffers and fills them
        /// with the default seed and secret values.
        pub fn allocate_default() -> Self {
            Self {
                seed: DEFAULT_SEED,
                secret: DEFAULT_SECRET_RAW.to_vec().into(),
                buffer: [0; BUFFERED_BYTES],
            }
        }

        /// Allocates the secret and temporary buffers and uses the
        /// provided seed to construct the secret value.
        pub fn allocate_with_seed(seed: u64) -> Self {
            let mut secret = DEFAULT_SECRET_RAW;
            derive_secret(seed, &mut secret);

            Self {
                seed,
                secret: secret.to_vec().into(),
                buffer: [0; BUFFERED_BYTES],
            }
        }

        /// Allocates the temporary buffer and uses the provided seed
        /// and secret buffer.
        pub fn allocate_with_seed_and_secret(
            seed: u64,
            secret: impl Into<Box<[u8]>>,
        ) -> Result<Self, SecretTooShortError<Box<[u8]>>> {
            Self::new(seed, secret.into())
        }
    }

    pub type AllocRawHasher = RawHasher<Box<[u8]>>;

    impl AllocRawHasher {
        fn allocate_default() -> Self {
            Self::new(SecretBuffer::allocate_default())
        }

        fn allocate_with_seed(seed: u64) -> Self {
            Self::new(SecretBuffer::allocate_with_seed(seed))
        }

        fn allocate_with_seed_and_secret(
            seed: u64,
            secret: impl Into<Box<[u8]>>,
        ) -> Result<Self, SecretTooShortError<Box<[u8]>>> {
            SecretBuffer::allocate_with_seed_and_secret(seed, secret).map(Self::new)
        }
    }
}

impl<S> SecretBuffer<S>
where
    S: FixedMutBuffer,
{
    /// Fills the secret buffer with a secret derived from the seed
    /// and the default secret. The secret must be exactly
    /// [`DEFAULT_SECRET_LENGTH`][] bytes long.
    pub fn with_seed(seed: u64, mut secret: S) -> Result<Self, SecretWithSeedError<S>> {
        match <&mut DefaultSecret>::try_from(secret.as_mut()) {
            Ok(secret_slice) => {
                *secret_slice = DEFAULT_SECRET_RAW;
                derive_secret(seed, secret_slice);

                Ok(Self {
                    seed,
                    secret,
                    buffer: [0; BUFFERED_BYTES],
                })
            }
            Err(_) => Err(SecretWithSeedError(secret)),
        }
    }
}

/// The provided secret was not at least [`SECRET_MINIMUM_LENGTH`][]
/// bytes.
pub struct SecretTooShortError<S>(secret::Error, S);

impl<S> SecretTooShortError<S> {
    /// Returns the secret.
    pub fn into_secret(self) -> S {
        self.1
    }
}

impl<S> core::error::Error for SecretTooShortError<S> {}

impl<S> core::fmt::Debug for SecretTooShortError<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretTooShortError").finish()
    }
}

impl<S> core::fmt::Display for SecretTooShortError<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// The provided secret was not exactly [`DEFAULT_SECRET_LENGTH`][]
/// bytes.
pub struct SecretWithSeedError<S>(S);

impl<S> SecretWithSeedError<S> {
    /// Returns the secret.
    pub fn into_secret(self) -> S {
        self.0
    }
}

impl<S> core::error::Error for SecretWithSeedError<S> {}

impl<S> core::fmt::Debug for SecretWithSeedError<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretWithSeedError").finish()
    }
}

impl<S> core::fmt::Display for SecretWithSeedError<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "The secret must be exactly {DEFAULT_SECRET_LENGTH} bytes"
        )
    }
}

/// Tracks which stripe we are currently on to know which part of the
/// secret we should be using.
#[derive(Copy, Clone)]
struct StripeAccumulator {
    accumulator: [u64; 8],
    current_stripe: usize,
}

impl StripeAccumulator {
    fn new() -> Self {
        Self {
            accumulator: INITIAL_ACCUMULATORS,
            current_stripe: 0,
        }
    }

    #[inline]
    fn process_stripe(
        &mut self,
        vector: impl Vector,
        stripe: &[u8; 64],
        n_stripes: usize,
        secret: &Secret,
    ) {
        let Self {
            accumulator,
            current_stripe,
            ..
        } = self;

        // For each stripe

        // Safety: The number of stripes is determined by the
        // block size, which is determined by the secret size.
        let secret_stripe = unsafe { secret.stripe(*current_stripe) };
        vector.accumulate(accumulator, stripe, secret_stripe);

        *current_stripe += 1;

        // After a full block's worth
        if *current_stripe == n_stripes {
            let secret_end = secret.last_stripe();
            vector.round_scramble(accumulator, secret_end);

            *current_stripe = 0;
        }
    }
}

/// A lower-level interface for computing a hash from streaming data.
///
/// The algorithm requires a secret which can be a reasonably large
/// piece of data. [`Hasher`][] makes one concrete implementation
/// decision that uses dynamic memory allocation, but specialized
/// usages may desire more flexibility. This type, combined with
/// [`SecretBuffer`][], offer that flexibility at the cost of a
/// generic type.
#[derive(Clone)]
pub struct RawHasher<S> {
    secret_buffer: SecretBuffer<S>,
    buffer_usage: usize,
    stripe_accumulator: StripeAccumulator,
    total_bytes: usize,
}

impl<S> RawHasher<S> {
    /// Construct the hasher with the provided seed, secret, and
    /// temporary buffer.
    pub fn new(secret_buffer: SecretBuffer<S>) -> Self {
        Self {
            secret_buffer,
            buffer_usage: 0,
            stripe_accumulator: StripeAccumulator::new(),
            total_bytes: 0,
        }
    }

    /// Returns the secret.
    pub fn into_secret(self) -> S {
        self.secret_buffer.into_secret()
    }
}

macro_rules! dispatch {
    (
        fn $fn_name:ident<$($gen:ident),*>($($arg_name:ident : $arg_ty:ty),*) $(-> $ret_ty:ty)?
        [$($wheres:tt)*]
    ) => {
        #[inline]
        fn do_scalar<$($gen),*>($($arg_name : $arg_ty),*) $(-> $ret_ty)?
        where
            $($wheres)*
        {
            $fn_name(scalar::Impl, $($arg_name),*)
        }

        /// # Safety
        ///
        /// You must ensure that the CPU has the NEON feature
        #[inline]
        #[target_feature(enable = "neon")]
        #[cfg(all(target_arch = "aarch64", feature = "std"))]
        unsafe fn do_neon<$($gen),*>($($arg_name : $arg_ty),*) $(-> $ret_ty)?
        where
            $($wheres)*
        {
            // Safety: The caller has ensured we have the NEON feature
            unsafe {
                $fn_name(neon::Impl::new_unchecked(), $($arg_name),*)
            }
        }

        /// # Safety
        ///
        /// You must ensure that the CPU has the AVX2 feature
        #[inline]
        #[target_feature(enable = "avx2")]
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        unsafe fn do_avx2<$($gen),*>($($arg_name : $arg_ty),*) $(-> $ret_ty)?
        where
            $($wheres)*
        {
            // Safety: The caller has ensured we have the AVX2 feature
            unsafe {
                $fn_name(avx2::Impl::new_unchecked(), $($arg_name),*)
            }
        }

        /// # Safety
        ///
        /// You must ensure that the CPU has the SSE2 feature
        #[inline]
        #[target_feature(enable = "sse2")]
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        unsafe fn do_sse2<$($gen),*>($($arg_name : $arg_ty),*) $(-> $ret_ty)?
        where
            $($wheres)*
        {
            // Safety: The caller has ensured we have the SSE2 feature
            unsafe {
                $fn_name(sse2::Impl::new_unchecked(), $($arg_name),*)
            }
        }

        // Now we invoke the right function

        #[cfg(_internal_xxhash3_force_neon)]
        return unsafe { do_neon($($arg_name),*) };

        #[cfg(_internal_xxhash3_force_avx2)]
        return unsafe { do_avx2($($arg_name),*) };

        #[cfg(_internal_xxhash3_force_sse2)]
        return unsafe { do_sse2($($arg_name),*) };

        #[cfg(_internal_xxhash3_force_scalar)]
        return do_scalar($($arg_name),*);

        // This code can be unreachable if one of the `*_force_*` cfgs
        // are set above, but that's the point.
        #[allow(unreachable_code)]
        {
            #[cfg(all(target_arch = "aarch64", feature = "std"))]
            {
                if std::arch::is_aarch64_feature_detected!("neon") {
                    // Safety: We just ensured we have the NEON feature
                    return unsafe { do_neon($($arg_name),*) };
                }
            }

            #[cfg(all(target_arch = "x86_64", feature = "std"))]
            {
                if is_x86_feature_detected!("avx2") {
                    // Safety: We just ensured we have the AVX2 feature
                    return unsafe { do_avx2($($arg_name),*) };
                } else if is_x86_feature_detected!("sse2") {
                    // Safety: We just ensured we have the SSE2 feature
                    return unsafe { do_sse2($($arg_name),*) };
                }
            }
            do_scalar($($arg_name),*)
        }
    };
}

impl<S> hash::Hasher for RawHasher<S>
where
    S: FixedBuffer,
{
    #[inline]
    fn write(&mut self, input: &[u8]) {
        let this = self;
        dispatch! {
            fn write_impl<S>(this: &mut RawHasher<S>, input: &[u8])
            [S: FixedBuffer]
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        let this = self;
        dispatch! {
            fn finish_impl<S>(this: &RawHasher<S>) -> u64
            [S: FixedBuffer]
        }
    }
}

#[inline(always)]
fn write_impl<S>(vector: impl Vector, this: &mut RawHasher<S>, mut input: &[u8])
where
    S: FixedBuffer,
{
    if input.is_empty() {
        return;
    }

    let RawHasher {
        secret_buffer,
        buffer_usage,
        stripe_accumulator,
        total_bytes,
        ..
    } = this;

    let n_stripes = secret_buffer.n_stripes();
    let (_, secret, buffer) = secret_buffer.parts_mut();

    *total_bytes += input.len();

    // Safety: This is an invariant of the buffer.
    unsafe {
        debug_assert!(*buffer_usage <= buffer.len());
        assert_unchecked(*buffer_usage <= buffer.len())
    };

    // We have some previous data saved; try to fill it up and process it first
    if !buffer.is_empty() {
        let remaining = &mut buffer[*buffer_usage..];
        let n_to_copy = usize::min(remaining.len(), input.len());

        let (remaining_head, remaining_tail) = remaining.split_at_mut(n_to_copy);
        let (input_head, input_tail) = input.split_at(n_to_copy);

        remaining_head.copy_from_slice(input_head);
        *buffer_usage += n_to_copy;

        input = input_tail;

        // We did not fill up the buffer
        if !remaining_tail.is_empty() {
            return;
        }

        // We don't know this isn't the last of the data
        if input.is_empty() {
            return;
        }

        let (stripes, _) = buffer.bp_as_chunks();
        for stripe in stripes {
            stripe_accumulator.process_stripe(vector, stripe, n_stripes, secret);
        }
        *buffer_usage = 0;
    }

    debug_assert!(*buffer_usage == 0);

    // Process as much of the input data in-place as possible,
    // while leaving at least one full stripe for the
    // finalization.
    if let Some(len) = input.len().checked_sub(STRIPE_BYTES) {
        let full_block_point = (len / STRIPE_BYTES) * STRIPE_BYTES;
        // Safety: We know that `full_block_point` must be less than
        // `input.len()` as we subtracted and then integer-divided
        // (which rounds down) and then multiplied back. That's not
        // evident to the compiler and `split_at` results in a
        // potential panic.
        //
        // https://github.com/llvm/llvm-project/issues/104827
        let (stripes, remainder) = unsafe { input.split_at_unchecked(full_block_point) };
        let (stripes, _) = stripes.bp_as_chunks();

        for stripe in stripes {
            stripe_accumulator.process_stripe(vector, stripe, n_stripes, secret)
        }
        input = remainder;
    }

    // Any remaining data has to be less than the buffer, and the
    // buffer is empty so just fill up the buffer.
    debug_assert!(*buffer_usage == 0);
    debug_assert!(!input.is_empty());

    // Safety: We have parsed all the full blocks of input except one
    // and potentially a full block minus one byte. That amount of
    // data must be less than the buffer.
    let buffer_head = unsafe {
        debug_assert!(input.len() < 2 * STRIPE_BYTES);
        debug_assert!(2 * STRIPE_BYTES < buffer.len());
        buffer.get_unchecked_mut(..input.len())
    };

    buffer_head.copy_from_slice(input);
    *buffer_usage = input.len();
}

#[inline(always)]
fn finish_impl<S>(vector: impl Vector, this: &RawHasher<S>) -> u64
where
    S: FixedBuffer,
{
    let RawHasher {
        ref secret_buffer,
        buffer_usage,
        mut stripe_accumulator,
        total_bytes,
    } = *this;

    let n_stripes = secret_buffer.n_stripes();
    let (seed, secret, buffer) = secret_buffer.parts();

    // Safety: This is an invariant of the buffer.
    unsafe {
        debug_assert!(buffer_usage <= buffer.len());
        assert_unchecked(buffer_usage <= buffer.len())
    };

    if total_bytes > CUTOFF {
        let input = &buffer[..buffer_usage];

        // Ingest final stripes
        let (stripes, remainder) = stripes_with_tail(input);
        for stripe in stripes {
            stripe_accumulator.process_stripe(vector, stripe, n_stripes, secret);
        }

        let mut temp = [0; 64];

        let last_stripe = match input.last_chunk() {
            Some(chunk) => chunk,
            None => {
                let n_to_reuse = 64 - input.len();
                let to_reuse = buffer.len() - n_to_reuse;

                let (temp_head, temp_tail) = temp.split_at_mut(n_to_reuse);
                temp_head.copy_from_slice(&buffer[to_reuse..]);
                temp_tail.copy_from_slice(input);

                &temp
            }
        };

        Algorithm(vector).finalize(
            stripe_accumulator.accumulator,
            remainder,
            last_stripe,
            secret,
            total_bytes,
        )
    } else {
        impl_oneshot(DEFAULT_SECRET, seed, &buffer[..total_bytes])
    }
}

/// # Correctness
///
/// This function assumes that the incoming buffer has been populated
/// with the default secret.
#[inline]
fn derive_secret(seed: u64, secret: &mut DefaultSecret) {
    if seed == DEFAULT_SEED {
        return;
    }

    let (words, _) = secret.bp_as_chunks_mut();
    let (pairs, _) = words.bp_as_chunks_mut();

    for [a_p, b_p] in pairs {
        let a = u64::from_le_bytes(*a_p);
        let b = u64::from_le_bytes(*b_p);

        let a = a.wrapping_add(seed);
        let b = b.wrapping_sub(seed);

        *a_p = a.to_le_bytes();
        *b_p = b.to_le_bytes();
    }
}

#[inline(always)]
fn impl_oneshot(secret: &Secret, seed: u64, input: &[u8]) -> u64 {
    match input.len() {
        241.. => impl_241_plus_bytes(secret, input),

        129..=240 => impl_129_to_240_bytes(secret, seed, input),

        17..=128 => impl_17_to_128_bytes(secret, seed, input),

        9..=16 => impl_9_to_16_bytes(secret, seed, input),

        4..=8 => impl_4_to_8_bytes(secret, seed, input),

        1..=3 => impl_1_to_3_bytes(secret, seed, input),

        0 => impl_0_bytes(secret, seed),
    }
}

macro_rules! assert_input_range {
    ($min:literal.., $len:expr) => {
        assert!($min <= $len);
    };
    ($min:literal..=$max:literal, $len:expr) => {
        assert!($min <= $len);
        assert!($len <= $max);
    };
}

#[inline(always)]
fn impl_0_bytes(secret: &Secret, seed: u64) -> u64 {
    let secret_words = secret.words_for_0();
    avalanche_xxh64(seed ^ secret_words[0] ^ secret_words[1])
}

#[inline(always)]
fn impl_1_to_3_bytes(secret: &Secret, seed: u64, input: &[u8]) -> u64 {
    assert_input_range!(1..=3, input.len());
    let input_length = input.len() as u8; // OK as we checked that the length fits

    let combined = input[input.len() - 1].into_u32()
        | input_length.into_u32() << 8
        | input[0].into_u32() << 16
        | input[input.len() >> 1].into_u32() << 24;

    let secret_words = secret.words_for_1_to_3();

    let value = ((secret_words[0] ^ secret_words[1]).into_u64() + seed) ^ combined.into_u64();

    // FUTURE: TEST: "Note that the XXH3-64 result is the lower half of XXH3-128 result."
    avalanche_xxh64(value)
}

#[inline(always)]
fn impl_4_to_8_bytes(secret: &Secret, seed: u64, input: &[u8]) -> u64 {
    assert_input_range!(4..=8, input.len());
    let input_first = input.first_u32().unwrap();
    let input_last = input.last_u32().unwrap();

    let modified_seed = seed ^ (seed.lower_half().swap_bytes().into_u64() << 32);
    let secret_words = secret.words_for_4_to_8();

    let combined = input_last.into_u64() | (input_first.into_u64() << 32);

    let mut value = {
        let a = secret_words[0] ^ secret_words[1];
        let b = a.wrapping_sub(modified_seed);
        b ^ combined
    };
    value ^= value.rotate_left(49) ^ value.rotate_left(24);
    value = value.wrapping_mul(PRIME_MX2);
    value ^= (value >> 35).wrapping_add(input.len().into_u64());
    value = value.wrapping_mul(PRIME_MX2);
    value ^= value >> 28;
    value
}

#[inline(always)]
fn impl_9_to_16_bytes(secret: &Secret, seed: u64, input: &[u8]) -> u64 {
    assert_input_range!(9..=16, input.len());
    let input_first = input.first_u64().unwrap();
    let input_last = input.last_u64().unwrap();

    let secret_words = secret.words_for_9_to_16();
    let low = ((secret_words[0] ^ secret_words[1]).wrapping_add(seed)) ^ input_first;
    let high = ((secret_words[2] ^ secret_words[3]).wrapping_sub(seed)) ^ input_last;
    let mul_result = low.into_u128().wrapping_mul(high.into_u128());
    let value = input
        .len()
        .into_u64()
        .wrapping_add(low.swap_bytes())
        .wrapping_add(high)
        .wrapping_add(mul_result.lower_half() ^ mul_result.upper_half());

    avalanche(value)
}

#[inline]
fn impl_17_to_128_bytes(secret: &Secret, seed: u64, input: &[u8]) -> u64 {
    assert_input_range!(17..=128, input.len());
    let mut acc = input.len().into_u64().wrapping_mul(PRIME64_1);

    let secret = secret.words_for_17_to_128();
    let (secret, _) = secret.bp_as_chunks::<2>();
    let (fwd, _) = input.bp_as_chunks();
    let (_, bwd) = input.bp_as_rchunks();

    let q = bwd.len();

    if input.len() > 32 {
        if input.len() > 64 {
            if input.len() > 96 {
                acc = acc.wrapping_add(mix_step(&fwd[3], &secret[3][0], seed));
                acc = acc.wrapping_add(mix_step(&bwd[q - 4], &secret[3][1], seed));
            }

            acc = acc.wrapping_add(mix_step(&fwd[2], &secret[2][0], seed));
            acc = acc.wrapping_add(mix_step(&bwd[q - 3], &secret[2][1], seed));
        }

        acc = acc.wrapping_add(mix_step(&fwd[1], &secret[1][0], seed));
        acc = acc.wrapping_add(mix_step(&bwd[q - 2], &secret[1][1], seed));
    }

    acc = acc.wrapping_add(mix_step(&fwd[0], &secret[0][0], seed));
    acc = acc.wrapping_add(mix_step(&bwd[q - 1], &secret[0][1], seed));

    avalanche(acc)
}

#[inline]
fn impl_129_to_240_bytes(secret: &Secret, seed: u64, input: &[u8]) -> u64 {
    assert_input_range!(129..=240, input.len());
    let mut acc = input.len().into_u64().wrapping_mul(PRIME64_1);

    let (head, _) = input.bp_as_chunks();
    let mut head = head.iter();

    let ss = secret.words_for_127_to_240_part1();
    for (chunk, secret) in head.by_ref().zip(ss).take(8) {
        acc = acc.wrapping_add(mix_step(chunk, secret, seed));
    }

    acc = avalanche(acc);

    let ss = secret.words_for_127_to_240_part2();
    for (chunk, secret) in head.zip(ss) {
        acc = acc.wrapping_add(mix_step(chunk, secret, seed));
    }

    let last_chunk = input.last_chunk().unwrap();
    let ss = secret.words_for_127_to_240_part3();
    acc = acc.wrapping_add(mix_step(last_chunk, ss, seed));

    avalanche(acc)
}

#[inline]
fn mix_step(data: &[u8; 16], secret: &[u8; 16], seed: u64) -> u64 {
    #[inline]
    fn to_u64s(bytes: &[u8; 16]) -> [u64; 2] {
        let (pair, _) = bytes.bp_as_chunks::<8>();
        [pair[0], pair[1]].map(u64::from_le_bytes)
    }

    let data_words = to_u64s(data);
    let secret_words = to_u64s(secret);

    let mul_result = {
        let a = (data_words[0] ^ secret_words[0].wrapping_add(seed)).into_u128();
        let b = (data_words[1] ^ secret_words[1].wrapping_sub(seed)).into_u128();

        a.wrapping_mul(b)
    };

    mul_result.lower_half() ^ mul_result.upper_half()
}

#[rustfmt::skip]
const INITIAL_ACCUMULATORS: [u64; 8] = [
    PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3,
    PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1,
];

#[inline]
fn impl_241_plus_bytes(secret: &Secret, input: &[u8]) -> u64 {
    assert_input_range!(241.., input.len());
    dispatch! {
        fn oneshot_impl<>(secret: &Secret, input: &[u8]) -> u64
        []
    }
}

#[inline]
fn oneshot_impl(vector: impl Vector, secret: &Secret, input: &[u8]) -> u64 {
    Algorithm(vector).oneshot(secret, input)
}

struct Algorithm<V>(V);

impl<V> Algorithm<V>
where
    V: Vector,
{
    #[inline]
    fn oneshot(&self, secret: &Secret, input: &[u8]) -> u64 {
        assert_input_range!(241.., input.len());
        let mut acc = INITIAL_ACCUMULATORS;

        let stripes_per_block = (secret.len() - 64) / 8;
        let block_size = 64 * stripes_per_block;

        let mut blocks = input.chunks_exact(block_size);

        let last_block = if blocks.remainder().is_empty() {
            // Safety: We know that `input` is non-empty, which means
            // that either there will be a remainder or one or more
            // full blocks. That info isn't flowing to the optimizer,
            // so we use `unwrap_unchecked`.
            unsafe { blocks.next_back().unwrap_unchecked() }
        } else {
            blocks.remainder()
        };

        self.rounds(&mut acc, blocks, secret);

        let len = input.len();

        let last_stripe = input.last_chunk().unwrap();
        self.finalize(acc, last_block, last_stripe, secret, len)
    }

    #[inline]
    fn rounds<'a>(
        &self,
        acc: &mut [u64; 8],
        blocks: impl IntoIterator<Item = &'a [u8]>,
        secret: &Secret,
    ) {
        for block in blocks {
            let (stripes, _) = block.bp_as_chunks();

            self.round(acc, stripes, secret);
        }
    }

    #[inline]
    fn round(&self, acc: &mut [u64; 8], stripes: &[[u8; 64]], secret: &Secret) {
        let secret_end = secret.last_stripe();

        self.round_accumulate(acc, stripes, secret);
        self.0.round_scramble(acc, secret_end);
    }

    #[inline]
    fn round_accumulate(&self, acc: &mut [u64; 8], stripes: &[[u8; 64]], secret: &Secret) {
        let secrets = (0..stripes.len()).map(|i| {
            // Safety: The number of stripes is determined by the
            // block size, which is determined by the secret size.
            unsafe { secret.stripe(i) }
        });

        for (stripe, secret) in stripes.iter().zip(secrets) {
            self.0.accumulate(acc, stripe, secret);
        }
    }

    #[inline]
    fn finalize(
        &self,
        mut acc: [u64; 8],
        last_block: &[u8],
        last_stripe: &[u8; 64],
        secret: &Secret,
        len: usize,
    ) -> u64 {
        debug_assert!(!last_block.is_empty());
        self.last_round(&mut acc, last_block, last_stripe, secret);

        self.final_merge(&mut acc, len.into_u64().wrapping_mul(PRIME64_1), secret)
    }

    #[inline]
    fn last_round(
        &self,
        acc: &mut [u64; 8],
        block: &[u8],
        last_stripe: &[u8; 64],
        secret: &Secret,
    ) {
        // Accumulation steps are run for the stripes in the last block,
        // except for the last stripe (whether it is full or not)
        let (stripes, _) = stripes_with_tail(block);

        let secrets = (0..stripes.len()).map(|i| {
            // Safety: The number of stripes is determined by the
            // block size, which is determined by the secret size.
            unsafe { secret.stripe(i) }
        });

        for (stripe, secret) in stripes.iter().zip(secrets) {
            self.0.accumulate(acc, stripe, secret);
        }

        let last_stripe_secret = secret.last_stripe_secret_better_name();
        self.0.accumulate(acc, last_stripe, last_stripe_secret);
    }

    #[inline]
    fn final_merge(&self, acc: &mut [u64; 8], init_value: u64, secret: &Secret) -> u64 {
        let secret = secret.final_secret();
        let (secrets, _) = secret.bp_as_chunks();
        let mut result = init_value;
        for i in 0..4 {
            // 64-bit by 64-bit multiplication to 128-bit full result
            let mul_result = {
                let sa = u64::from_le_bytes(secrets[i * 2]);
                let sb = u64::from_le_bytes(secrets[i * 2 + 1]);

                let a = (acc[i * 2] ^ sa).into_u128();
                let b = (acc[i * 2 + 1] ^ sb).into_u128();
                a.wrapping_mul(b)
            };
            result = result.wrapping_add(mul_result.lower_half() ^ mul_result.upper_half());
        }
        avalanche(result)
    }
}

#[inline]
fn stripes_with_tail(block: &[u8]) -> (&[[u8; 64]], &[u8]) {
    match block.bp_as_chunks() {
        ([stripes @ .., last], []) => (stripes, last),
        (stripes, last) => (stripes, last),
    }
}

trait Vector: Copy {
    fn round_scramble(&self, acc: &mut [u64; 8], secret_end: &[u8; 64]);

    fn accumulate(&self, acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]);
}

#[inline]
fn avalanche(mut x: u64) -> u64 {
    x ^= x >> 37;
    x = x.wrapping_mul(PRIME_MX1);
    x ^= x >> 32;
    x
}

#[inline]
fn avalanche_xxh64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(PRIME64_2);
    x ^= x >> 29;
    x = x.wrapping_mul(PRIME64_3);
    x ^= x >> 32;
    x
}

trait Halves {
    type Output;

    fn upper_half(self) -> Self::Output;
    fn lower_half(self) -> Self::Output;
}

impl Halves for u64 {
    type Output = u32;

    #[inline]
    fn upper_half(self) -> Self::Output {
        (self >> 32) as _
    }

    #[inline]
    fn lower_half(self) -> Self::Output {
        self as _
    }
}

impl Halves for u128 {
    type Output = u64;

    #[inline]
    fn upper_half(self) -> Self::Output {
        (self >> 64) as _
    }

    #[inline]
    fn lower_half(self) -> Self::Output {
        self as _
    }
}

trait U8SliceExt {
    fn first_u32(&self) -> Option<u32>;

    fn last_u32(&self) -> Option<u32>;

    fn first_u64(&self) -> Option<u64>;

    fn last_u64(&self) -> Option<u64>;
}

impl U8SliceExt for [u8] {
    #[inline]
    fn first_u32(&self) -> Option<u32> {
        self.first_chunk().copied().map(u32::from_le_bytes)
    }

    #[inline]
    fn last_u32(&self) -> Option<u32> {
        self.last_chunk().copied().map(u32::from_le_bytes)
    }

    #[inline]
    fn first_u64(&self) -> Option<u64> {
        self.first_chunk().copied().map(u64::from_le_bytes)
    }

    #[inline]
    fn last_u64(&self) -> Option<u64> {
        self.last_chunk().copied().map(u64::from_le_bytes)
    }
}

trait SliceBackport<T> {
    fn bp_as_chunks<const N: usize>(&self) -> (&[[T; N]], &[T]);

    fn bp_as_chunks_mut<const N: usize>(&mut self) -> (&mut [[T; N]], &mut [T]);

    fn bp_as_rchunks<const N: usize>(&self) -> (&[T], &[[T; N]]);
}

impl<T> SliceBackport<T> for [T] {
    fn bp_as_chunks<const N: usize>(&self) -> (&[[T; N]], &[T]) {
        assert_ne!(N, 0);
        let len = self.len() / N;
        // Safety: `(len / N) * N` has to be less-than-or-equal to `len`
        let (head, tail) = unsafe { self.split_at_unchecked(len * N) };
        // Safety: (1) `head` points to valid data, (2) the alignment
        // of an array and the individual type are the same, (3) the
        // valid elements are less-than-or-equal to the original
        // slice.
        let head = unsafe { slice::from_raw_parts(head.as_ptr().cast(), len) };
        (head, tail)
    }

    fn bp_as_chunks_mut<const N: usize>(&mut self) -> (&mut [[T; N]], &mut [T]) {
        assert_ne!(N, 0);
        let len = self.len() / N;
        // Safety: `(len / N) * N` has to be less than or equal to `len`
        let (head, tail) = unsafe { self.split_at_mut_unchecked(len * N) };
        // Safety: (1) `head` points to valid data, (2) the alignment
        // of an array and the individual type are the same, (3) the
        // valid elements are less-than-or-equal to the original
        // slice.
        let head = unsafe { slice::from_raw_parts_mut(head.as_mut_ptr().cast(), len) };
        (head, tail)
    }

    fn bp_as_rchunks<const N: usize>(&self) -> (&[T], &[[T; N]]) {
        assert_ne!(N, 0);
        let len = self.len() / N;
        // Safety: `(len / N) * N` has to be less than or equal to `len`
        let (head, tail) = unsafe { self.split_at_unchecked(self.len() - len * N) };
        // Safety: (1) `tail` points to valid data, (2) the alignment
        // of an array and the individual type are the same, (3) the
        // valid elements are less-than-or-equal to the original
        // slice.
        let tail = unsafe { slice::from_raw_parts(tail.as_ptr().cast(), len) };
        (head, tail)
    }
}

#[cfg(test)]
mod test {
    use std::{array, hash::Hasher as _};

    use super::*;

    const _: () = {
        const fn is_clone<T: Clone>() {}
        is_clone::<Hasher>();
    };

    const EMPTY_BYTES: [u8; 0] = [];

    #[test]
    fn default_secret_is_valid() {
        assert!(DEFAULT_SECRET.is_valid())
    }

    #[test]
    fn secret_buffer_default_is_valid() {
        assert!(SecretBuffer::default().is_valid());
    }

    #[test]
    fn secret_buffer_allocate_default_is_valid() {
        assert!(SecretBuffer::allocate_default().is_valid())
    }

    #[test]
    fn secret_buffer_allocate_with_seed_is_valid() {
        assert!(SecretBuffer::allocate_with_seed(0xdead_beef).is_valid())
    }

    macro_rules! bytes {
        ($($n: literal),* $(,)?) => {
            &[$(&gen_bytes::<$n>() as &[u8],)*] as &[&[u8]]
        };
    }

    fn gen_bytes<const N: usize>() -> [u8; N] {
        // Picking 251 as it's a prime number, which will hopefully
        // help avoid incidental power-of-two alignment.
        array::from_fn(|i| (i % 251) as u8)
    }

    fn hash_byte_by_byte(input: &[u8]) -> u64 {
        let mut hasher = Hasher::new();
        for byte in input.chunks(1) {
            hasher.write(byte)
        }
        hasher.finish()
    }

    fn hash_byte_by_byte_with_seed(seed: u64, input: &[u8]) -> u64 {
        let mut hasher = Hasher::with_seed(seed);
        for byte in input.chunks(1) {
            hasher.write(byte)
        }
        hasher.finish()
    }

    #[test]
    fn oneshot_empty() {
        let hash = Hasher::oneshot(&EMPTY_BYTES);
        assert_eq!(hash, 0x2d06_8005_38d3_94c2);
    }

    #[test]
    fn streaming_empty() {
        let hash = hash_byte_by_byte(&EMPTY_BYTES);
        assert_eq!(hash, 0x2d06_8005_38d3_94c2);
    }

    #[test]
    fn oneshot_1_to_3_bytes() {
        test_1_to_3_bytes(Hasher::oneshot)
    }

    #[test]
    fn streaming_1_to_3_bytes() {
        test_1_to_3_bytes(hash_byte_by_byte)
    }

    #[track_caller]
    fn test_1_to_3_bytes(mut f: impl FnMut(&[u8]) -> u64) {
        let inputs = bytes![1, 2, 3];

        let expected = [
            0xc44b_dff4_074e_ecdb,
            0xd664_5fc3_051a_9457,
            0x5f42_99fc_161c_9cbb,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = f(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn oneshot_4_to_8_bytes() {
        test_4_to_8_bytes(Hasher::oneshot)
    }

    #[test]
    fn streaming_4_to_8_bytes() {
        test_4_to_8_bytes(hash_byte_by_byte)
    }

    #[track_caller]
    fn test_4_to_8_bytes(mut f: impl FnMut(&[u8]) -> u64) {
        let inputs = bytes![4, 5, 6, 7, 8];

        let expected = [
            0x60da_b036_a582_11f2,
            0xb075_753a_84ca_0fbe,
            0xa658_4d1d_9a6a_e704,
            0x0cd2_084a_6240_6b69,
            0x3a1c_2d7c_85af_88f8,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = f(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn oneshot_9_to_16_bytes() {
        test_9_to_16_bytes(Hasher::oneshot)
    }

    #[test]
    fn streaming_9_to_16_bytes() {
        test_9_to_16_bytes(hash_byte_by_byte)
    }

    #[track_caller]
    fn test_9_to_16_bytes(mut f: impl FnMut(&[u8]) -> u64) {
        let inputs = bytes![9, 10, 11, 12, 13, 14, 15, 16];

        let expected = [
            0xe961_2598_145b_b9dc,
            0xab69_a08e_f83d_8f77,
            0x1cf3_96aa_4de6_198d,
            0x5ace_6a51_1c10_894b,
            0xb7a5_d8a8_309a_2cb9,
            0x4cf4_5c94_4a9a_2237,
            0x55ec_edc2_b87b_b042,
            0x8355_e3a6_f617_70db,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = f(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn oneshot_17_to_128_bytes() {
        test_17_to_128_bytes(Hasher::oneshot)
    }

    #[test]
    fn streaming_17_to_128_bytes() {
        test_17_to_128_bytes(hash_byte_by_byte)
    }

    #[track_caller]
    fn test_17_to_128_bytes(mut f: impl FnMut(&[u8]) -> u64) {
        let lower_boundary = bytes![17, 18, 19];
        let chunk_boundary = bytes![31, 32, 33];
        let upper_boundary = bytes![126, 127, 128];

        let inputs = lower_boundary
            .iter()
            .chain(chunk_boundary)
            .chain(upper_boundary);

        let expected = [
            // lower_boundary
            0x9ef3_41a9_9de3_7328,
            0xf691_2490_d4c0_eed5,
            0x60e7_2614_3cf5_0312,
            // chunk_boundary
            0x4f36_db8e_4df3_78fd,
            0x3523_581f_e96e_4c05,
            0xe68c_56ba_8899_1e58,
            // upper_boundary
            0x6c2a_9eb7_459c_dc61,
            0x120b_9787_f842_5f2f,
            0x85c6_174c_7ff4_c46b,
        ];

        for (input, expected) in inputs.zip(expected) {
            let hash = f(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn oneshot_129_to_240_bytes() {
        test_129_to_240_bytes(Hasher::oneshot)
    }

    #[test]
    fn streaming_129_to_240_bytes() {
        test_129_to_240_bytes(hash_byte_by_byte)
    }

    #[track_caller]
    fn test_129_to_240_bytes(mut f: impl FnMut(&[u8]) -> u64) {
        let lower_boundary = bytes![129, 130, 131];
        let upper_boundary = bytes![238, 239, 240];

        let inputs = lower_boundary.iter().chain(upper_boundary);

        let expected = [
            // lower_boundary
            0xec76_42b4_31ba_3e5a,
            0x4d32_24b1_0090_8a87,
            0xe57f_7ea6_741f_e3a0,
            // upper_boundary
            0x3044_9a0b_4899_dee9,
            0x972b_14e3_c46f_214b,
            0x375a_384d_957f_e865,
        ];

        for (input, expected) in inputs.zip(expected) {
            let hash = f(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn oneshot_241_plus_bytes() {
        test_241_plus_bytes(Hasher::oneshot)
    }

    #[test]
    fn streaming_241_plus_bytes() {
        test_241_plus_bytes(hash_byte_by_byte)
    }

    #[track_caller]
    fn test_241_plus_bytes(mut f: impl FnMut(&[u8]) -> u64) {
        let inputs = bytes![241, 242, 243, 244, 1024, 10240];

        let expected = [
            0x02e8_cd95_421c_6d02,
            0xddcb_33c4_9405_1832,
            0x8835_f952_9193_e3dc,
            0xbc17_c91e_c3cf_8d7f,
            0xe5d7_8baf_a45b_2aa5,
            0xbcd6_3266_df6e_2244,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = f(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn oneshot_with_seed() {
        test_with_seed(Hasher::oneshot_with_seed)
    }

    #[test]
    fn streaming_with_seed() {
        test_with_seed(hash_byte_by_byte_with_seed)
    }

    #[track_caller]
    fn test_with_seed(mut f: impl FnMut(u64, &[u8]) -> u64) {
        let inputs = bytes![0, 1, 4, 9, 17, 129, 241, 1024];

        let expected = [
            0x4aed_e683_89c0_e311,
            0x78fc_079a_75aa_f3c0,
            0x1b73_06b8_9f25_4507,
            0x7df7_627f_d1f9_39b6,
            0x49ca_0fff_0950_1622,
            0x2bfd_caec_30ff_3000,
            0xf984_56bc_25be_0901,
            0x2483_9f0f_cdf4_d078,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = f(0xdead_cafe, input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn backported_as_chunks() {
        let x = [1, 2, 3, 4, 5];

        let (a, b) = x.bp_as_chunks::<1>();
        assert_eq!(a, &[[1], [2], [3], [4], [5]]);
        assert_eq!(b, &[] as &[i32]);

        let (a, b) = x.bp_as_chunks::<2>();
        assert_eq!(a, &[[1, 2], [3, 4]]);
        assert_eq!(b, &[5]);

        let (a, b) = x.bp_as_chunks::<3>();
        assert_eq!(a, &[[1, 2, 3]]);
        assert_eq!(b, &[4, 5]);

        let (a, b) = x.bp_as_chunks::<4>();
        assert_eq!(a, &[[1, 2, 3, 4]]);
        assert_eq!(b, &[5]);

        let (a, b) = x.bp_as_chunks::<5>();
        assert_eq!(a, &[[1, 2, 3, 4, 5]]);
        assert_eq!(b, &[] as &[i32]);

        let (a, b) = x.bp_as_chunks::<6>();
        assert_eq!(a, &[] as &[[i32; 6]]);
        assert_eq!(b, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn backported_as_rchunks() {
        let x = [1, 2, 3, 4, 5];

        let (a, b) = x.bp_as_rchunks::<1>();
        assert_eq!(a, &[] as &[i32]);
        assert_eq!(b, &[[1], [2], [3], [4], [5]]);

        let (a, b) = x.bp_as_rchunks::<2>();
        assert_eq!(a, &[1]);
        assert_eq!(b, &[[2, 3], [4, 5]]);

        let (a, b) = x.bp_as_rchunks::<3>();
        assert_eq!(a, &[1, 2]);
        assert_eq!(b, &[[3, 4, 5]]);

        let (a, b) = x.bp_as_rchunks::<4>();
        assert_eq!(a, &[1]);
        assert_eq!(b, &[[2, 3, 4, 5]]);

        let (a, b) = x.bp_as_rchunks::<5>();
        assert_eq!(a, &[] as &[i32]);
        assert_eq!(b, &[[1, 2, 3, 4, 5]]);

        let (a, b) = x.bp_as_rchunks::<6>();
        assert_eq!(a, &[1, 2, 3, 4, 5]);
        assert_eq!(b, &[] as &[[i32; 6]]);
    }
}
