#![allow(missing_docs)]

use core::{hash, mem, slice};

use crate::{IntoU128, IntoU32, IntoU64};

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

const DEFAULT_SEED: u64 = 0;

const DEFAULT_SECRET: [u8; 192] = [
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

pub const SECRET_MINIMUM_LENGTH: usize = 136;

pub struct XxHash3_64 {
    #[cfg(feature = "alloc")]
    inner: with_alloc::AllocRawHasher,
    _private: (),
}

impl XxHash3_64 {
    #[inline(never)]
    pub fn oneshot(input: &[u8]) -> u64 {
        impl_oneshot(&DEFAULT_SECRET, DEFAULT_SEED, input)
    }

    #[inline(never)]
    pub fn oneshot_with_seed(seed: u64, input: &[u8]) -> u64 {
        let mut secret = DEFAULT_SECRET;

        // We know that the secret will only be used if we have more
        // than 240 bytes, so don't waste time computing it otherwise.
        if input.len() > 240 {
            derive_secret(seed, &mut secret);
        }

        impl_oneshot(&secret, seed, input)
    }

    #[inline(never)]
    pub fn oneshot_with_secret(secret: &[u8], input: &[u8]) -> u64 {
        assert!(secret.len() >= SECRET_MINIMUM_LENGTH); // TODO: ERROR
        impl_oneshot(secret, DEFAULT_SEED, input)
    }
}

const STRIPE_BYTES: usize = 64;
const BUFFERED_STRIPES: usize = 4;
const BUFFERED_BYTES: usize = STRIPE_BYTES * BUFFERED_STRIPES;

// Ensure that a full buffer always implies we are in the 241+ byte case.
const _: () = assert!(BUFFERED_BYTES > 240);

/// Holds secret and temporary buffers that are ensured to be
/// appropriately sized.
pub struct SecretBuffer<S> {
    seed: u64,
    secret: S,
    buffer: [u8; BUFFERED_BYTES],
}

impl<S> SecretBuffer<S>
where
    S: AsRef<[u8]>,
{
    /// Takes the seed, secret, and buffer and performs no
    /// modifications to them, only validating that the sizes are
    /// appropriate.
    pub fn new(seed: u64, secret: S) -> Result<Self, S> {
        let this = Self {
            seed,
            secret,
            buffer: [0; BUFFERED_BYTES],
        };

        if this.is_valid() {
            Ok(this)
        } else {
            Err(this.decompose())
        }
    }

    fn is_valid(&self) -> bool {
        let secret = self.secret.as_ref();

        secret.len() >= SECRET_MINIMUM_LENGTH
    }

    #[inline]
    fn n_stripes(&self) -> usize {
        let secret = self.secret.as_ref();

        // stripes_per_block
        (secret.len() - 64) / 8
    }

    /// Returns the secret and buffer values.
    pub fn decompose(self) -> S {
        self.secret
    }
}

impl SecretBuffer<&'static [u8; 192]> {
    /// Use the default seed and secret values while allocating nothing.
    ///
    /// Note that this type may take up a surprising amount of stack space.
    #[inline]
    pub const fn default() -> Self {
        SecretBuffer {
            seed: DEFAULT_SEED,
            secret: &DEFAULT_SECRET,
            buffer: [0; BUFFERED_BYTES],
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
mod with_alloc {
    use ::alloc::boxed::Box;

    use super::*;

    impl XxHash3_64 {
        pub fn new() -> Self {
            Self {
                inner: RawHasher::allocate_default(),
                _private: (),
            }
        }

        pub fn with_seed(seed: u64) -> Self {
            Self {
                inner: RawHasher::allocate_with_seed(seed),
                _private: (),
            }
        }

        pub fn with_seed_and_secret(seed: u64, secret: impl Into<Box<[u8]>>) -> Self {
            Self {
                inner: RawHasher::allocate_with_seed_and_secret(seed, secret),
                _private: (),
            }
        }
    }

    impl Default for XxHash3_64 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl hash::Hasher for XxHash3_64 {
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
                secret: DEFAULT_SECRET.to_vec().into(),
                buffer: [0; BUFFERED_BYTES],
            }
        }

        /// Allocates the secret and temporary buffers and uses the
        /// provided seed to construct the secret value.
        pub fn allocate_with_seed(seed: u64) -> Self {
            let mut secret = DEFAULT_SECRET;
            derive_secret(seed, &mut secret);

            Self {
                seed,
                secret: secret.to_vec().into(),
                buffer: [0; BUFFERED_BYTES],
            }
        }

        /// Allocates the temporary buffer and uses the provided seed
        /// and secret buffer.
        pub fn allocate_with_seed_and_secret(seed: u64, secret: impl Into<Box<[u8]>>) -> Self {
            let secret = secret.into();
            assert!(secret.len() > SECRET_MINIMUM_LENGTH); // todo result

            Self {
                seed,
                secret,
                buffer: [0; BUFFERED_BYTES],
            }
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

        fn allocate_with_seed_and_secret(seed: u64, secret: impl Into<Box<[u8]>>) -> Self {
            Self::new(SecretBuffer::allocate_with_seed_and_secret(seed, secret))
        }
    }
}

impl<S> SecretBuffer<S>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Fills the secret buffer with a secret derived from the seed
    /// and the default secret.
    pub fn with_seed(seed: u64, mut secret: S) -> Result<Self, S> {
        let secret_slice: &mut [u8; 192] = match secret.as_mut().try_into() {
            Ok(s) => s,
            Err(_) => return Err(secret),
        };

        *secret_slice = DEFAULT_SECRET;
        derive_secret(seed, secret_slice);

        Self::new(seed, secret)
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
    fn process_stripe<V: Vector>(
        &mut self,
        vector: V,
        stripe: &[u8; 64],
        n_stripes: usize,
        secret: &[u8],
    ) {
        let Self {
            accumulator,
            current_stripe,
            ..
        } = self;

        let secret_end = unsafe { secret.last_chunk().unwrap_unchecked() };

        // each stripe
        let secret = unsafe { &*secret.get_unchecked(*current_stripe * 8..).as_ptr().cast() };
        vector.accumulate(accumulator, stripe, secret);

        *current_stripe += 1;

        if *current_stripe == n_stripes {
            // after block's worth
            vector.round_scramble(accumulator, secret_end);
            *current_stripe = 0;
        }
    }
}

/// A lower-level interface for computing a hash from streaming data.
///
/// The algorithm requires a secret which can be a reasonably large
/// piece of data. [`XxHash3_64`][] makes one concrete implementation
/// decision that uses dynamic memory allocation, but specialized
/// usages may desire more flexibility. This type, combined with
/// [`SecretBuffer`][], offer that flexibility at the cost of a
/// generic type.
pub struct RawHasher<S> {
    secret_buffer: SecretBuffer<S>,
    buffer_len: usize,
    stripe_accumulator: StripeAccumulator,
    total_bytes: usize,
}

impl<S> RawHasher<S> {
    pub fn new(secret_buffer: SecretBuffer<S>) -> Self {
        Self {
            secret_buffer,
            buffer_len: 0,
            stripe_accumulator: StripeAccumulator::new(),
            total_bytes: 0,
        }
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

        #[inline]
        #[target_feature(enable = "neon")]
        #[cfg(target_arch = "aarch64")]
        unsafe fn do_neon<$($gen),*>($($arg_name : $arg_ty),*) $(-> $ret_ty)?
        where
            $($wheres)*
        {
            $fn_name(neon::Impl::new_unchecked(), $($arg_name),*)
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        #[cfg(target_arch = "x86_64")]
        unsafe fn do_avx2<$($gen),*>($($arg_name : $arg_ty),*) $(-> $ret_ty)?
        where
            $($wheres)*
        {
            $fn_name(avx2::Impl::new_unchecked(), $($arg_name),*)
        }

        #[inline]
        #[target_feature(enable = "sse2")]
        #[cfg(target_arch = "x86_64")]
        unsafe fn do_sse2<$($gen),*>($($arg_name : $arg_ty),*) $(-> $ret_ty)?
        where
            $($wheres)*
        {
            $fn_name(sse2::Impl::new_unchecked(), $($arg_name),*)
        }

        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return unsafe { do_neon($($arg_name),*) };
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                return unsafe { do_avx2($($arg_name),*) };
            } else if is_x86_feature_detected!("sse2") {
                return unsafe { do_sse2($($arg_name),*) };
            }
        }

        do_scalar($($arg_name),*)
    };
}

impl<S> hash::Hasher for RawHasher<S>
where
    S: AsRef<[u8]>,
{
    #[inline(never)]
    fn write(&mut self, input: &[u8]) {
        let this = self;
        dispatch! {
            fn write_impl<S>(this: &mut RawHasher<S>, input: &[u8])
            [S: AsRef<[u8]>]
        }
    }

    #[inline(never)]
    fn finish(&self) -> u64 {
        let this = self;
        dispatch! {
            fn finish_impl<S>(this: &RawHasher<S>) -> u64
            [S: AsRef<[u8]>]
        }
    }
}

#[inline(always)]
fn write_impl<S>(vector: impl Vector, this: &mut RawHasher<S>, mut input: &[u8])
where
    S: AsRef<[u8]>,
{
    if input.is_empty() {
        return;
    }

    let RawHasher {
        secret_buffer,
        buffer_len,
        stripe_accumulator,
        total_bytes,
        ..
    } = this;

    let n_stripes = secret_buffer.n_stripes();

    let SecretBuffer { secret, buffer, .. } = secret_buffer;
    let secret = secret.as_ref();

    *total_bytes += input.len();

    // We have some previous data saved; try to fill it up and process it first
    if !buffer.is_empty() {
        let remaining = &mut buffer[*buffer_len..];
        let n_to_copy = usize::min(remaining.len(), input.len());

        let (remaining_head, remaining_tail) = remaining.split_at_mut(n_to_copy);
        let (input_head, input_tail) = input.split_at(n_to_copy);

        remaining_head.copy_from_slice(input_head);
        *buffer_len += n_to_copy;

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
        *buffer_len = 0;
    }

    debug_assert!(*buffer_len == 0);

    // Process as much of the input data in-place as possible,
    // while leaving at least one full stripe for the
    // finalization.
    if let Some(dd) = input.len().checked_sub(STRIPE_BYTES) {
        let nn = dd / STRIPE_BYTES;
        let nn = nn * STRIPE_BYTES;
        let (aa, remainder) = input.split_at(nn);
        let (stripes, _) = aa.bp_as_chunks();

        for stripe in stripes {
            stripe_accumulator.process_stripe(vector, stripe, n_stripes, secret)
        }
        input = remainder;
    }

    // Any remaining data has to be less than the buffer, and the
    // buffer is empty so just fill up the buffer.
    debug_assert!(*buffer_len == 0);
    debug_assert!(!input.is_empty());
    debug_assert!(input.len() < buffer.len());

    buffer[..input.len()].copy_from_slice(input);
    *buffer_len = input.len();
}

#[inline(always)]
fn finish_impl<S>(vector: impl Vector, this: &RawHasher<S>) -> u64
where
    S: AsRef<[u8]>,
{
    let RawHasher {
        ref secret_buffer,
        buffer_len,
        mut stripe_accumulator,
        total_bytes,
    } = *this;
    let n_stripes = secret_buffer.n_stripes();
    let SecretBuffer {
        seed,
        ref secret,
        ref buffer,
    } = *secret_buffer;
    let secret = secret.as_ref();
    let buffer = buffer.as_ref();

    let input = &buffer[..buffer_len];

    match total_bytes {
        241.. => {
            // Ingest final stripes
            let (stripes, remainder) = fun_name(input);
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
        }

        129..=240 => impl_129_to_240_bytes(&DEFAULT_SECRET, seed, input),

        17..=128 => impl_17_to_128_bytes(&DEFAULT_SECRET, seed, input),

        9..=16 => impl_9_to_16_bytes(&DEFAULT_SECRET, seed, input),

        4..=8 => impl_4_to_8_bytes(&DEFAULT_SECRET, seed, input),

        1..=3 => impl_1_to_3_bytes(&DEFAULT_SECRET, seed, input),

        0 => impl_0_bytes(&DEFAULT_SECRET, seed),
    }
}

/// # Correctness
///
/// This function assumes that the incoming buffer has been populated
/// with the default secret.
#[inline]
fn derive_secret(seed: u64, secret: &mut [u8; 192]) {
    if seed == DEFAULT_SEED {
        return;
    }

    let base = secret.as_mut_ptr().cast::<u64>();

    for i in 0..12 {
        let a_p = unsafe { base.add(i * 2) };
        let b_p = unsafe { base.add(i * 2 + 1) };

        let mut a = unsafe { a_p.read_unaligned() };
        let mut b = unsafe { b_p.read_unaligned() };

        a = a.wrapping_add(seed);
        b = b.wrapping_sub(seed);

        unsafe { a_p.write_unaligned(a) };
        unsafe { b_p.write_unaligned(b) };
    }
}

#[inline(always)]
fn impl_oneshot(secret: &[u8], seed: u64, input: &[u8]) -> u64 {
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

#[inline]
fn impl_0_bytes(secret: &[u8], seed: u64) -> u64 {
    let secret_words = unsafe { secret.as_ptr().add(56).cast::<[u64; 2]>().read_unaligned() };
    avalanche_xxh64(seed ^ secret_words[0] ^ secret_words[1])
}

#[inline]
fn impl_1_to_3_bytes(secret: &[u8], seed: u64, input: &[u8]) -> u64 {
    let input_length = input.len() as u8; // OK as we checked that the length fits

    let combined = input[input.len() - 1].into_u32()
        | input_length.into_u32() << 8
        | input[0].into_u32() << 16
        | input[input.len() >> 1].into_u32() << 24;

    let secret_words = unsafe { secret.as_ptr().cast::<[u32; 2]>().read_unaligned() };

    let value = ((secret_words[0] ^ secret_words[1]).into_u64() + seed) ^ combined.into_u64();

    // FUTURE: TEST: "Note that the XXH3-64 result is the lower half of XXH3-128 result."
    avalanche_xxh64(value)
}

#[inline]
fn impl_4_to_8_bytes(secret: &[u8], seed: u64, input: &[u8]) -> u64 {
    let input_first = unsafe { input.as_ptr().cast::<u32>().read_unaligned() };
    let input_last = unsafe {
        input
            .as_ptr()
            .add(input.len())
            .sub(mem::size_of::<u32>())
            .cast::<u32>()
            .read_unaligned()
    };

    let modified_seed = seed ^ (seed.lower_half().swap_bytes().into_u64() << 32);
    let secret_words = unsafe { secret.as_ptr().add(8).cast::<[u64; 2]>().read_unaligned() };

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

#[inline]
fn impl_9_to_16_bytes(secret: &[u8], seed: u64, input: &[u8]) -> u64 {
    let input_first = unsafe { input.as_ptr().cast::<u64>().read_unaligned() };
    let input_last = unsafe {
        input
            .as_ptr()
            .add(input.len())
            .sub(mem::size_of::<u64>())
            .cast::<u64>()
            .read_unaligned()
    };

    let secret_words = unsafe { secret.as_ptr().add(24).cast::<[u64; 4]>().read_unaligned() };
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
fn impl_17_to_128_bytes(secret: &[u8], seed: u64, input: &[u8]) -> u64 {
    let mut acc = input.len().into_u64().wrapping_mul(PRIME64_1);

    let (secret, _) = secret.bp_as_chunks();
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
fn impl_129_to_240_bytes(secret: &[u8], seed: u64, input: &[u8]) -> u64 {
    let mut acc = input.len().into_u64().wrapping_mul(PRIME64_1);

    let (head, _) = input.bp_as_chunks();
    let last_chunk = input.last_chunk().unwrap();
    let mut head = head.iter();

    let (ss, _) = secret.bp_as_chunks();
    let (ss2, _) = secret[3..].bp_as_chunks();

    let qq = head.by_ref().zip(ss);

    for (chunk, s) in qq.take(8) {
        acc = acc.wrapping_add(mix_step(chunk, s, seed));
    }

    acc = avalanche(acc);

    for (chunk, s) in head.zip(ss2) {
        acc = acc.wrapping_add(mix_step(chunk, s, seed));
    }

    let ss3 = &secret[119..].first_chunk().unwrap();
    acc = acc.wrapping_add(mix_step(last_chunk, ss3, seed));

    avalanche(acc)
}

#[inline]
fn mix_step(data: &[u8; 16], secret: &[u8; 16], seed: u64) -> u64 {
    let data_words = unsafe { data.as_ptr().cast::<[u64; 2]>().read_unaligned() };
    let secret_words = unsafe { secret.as_ptr().cast::<[u64; 2]>().read_unaligned() };

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
fn impl_241_plus_bytes(secret: &[u8], input: &[u8]) -> u64 {
    detect::oneshot(secret, input)
}

fn block_size(secret: &[u8]) -> usize {
    let stripes_per_block = (secret.len() - 64) / 8;
    64 * stripes_per_block
}

struct Algorithm<V>(V);

impl<V: Vector> Algorithm<V> {
    #[inline]
    fn oneshot(&self, secret: &[u8], input: &[u8]) -> u64 {
        let mut acc = INITIAL_ACCUMULATORS;

        assert!(secret.len() >= SECRET_MINIMUM_LENGTH);
        assert!(input.len() >= 241);

        let block_size = block_size(secret);

        let (blocks, last_block) = unsafe { chunks_and_last(input, block_size) };

        self.rounds(&mut acc, blocks, secret);

        let len = input.len();

        let last_stripe: &[u8; 64] = unsafe {
            &*input
                .as_ptr()
                .add(len)
                .sub(mem::size_of::<[u8; 64]>())
                .cast()
        };

        self.finalize(acc, last_block, last_stripe, secret, len)
    }

    #[inline]
    fn rounds<'a>(
        &self,
        acc: &mut [u64; 8],
        blocks: impl IntoIterator<Item = &'a [u8]>,
        secret: &[u8],
    ) {
        for block in blocks {
            let (stripes, _) = block.bp_as_chunks();

            self.round(acc, stripes, secret);
        }
    }

    #[inline]
    fn round(&self, acc: &mut [u64; 8], stripes: &[[u8; 64]], secret: &[u8]) {
        let secret_end = secret.last_chunk().unwrap();

        self.round_accumulate(acc, stripes, secret);
        self.0.round_scramble(acc, secret_end);
    }

    #[inline]
    fn round_accumulate(&self, acc: &mut [u64; 8], stripes: &[[u8; 64]], secret: &[u8]) {
        // TODO: [unify]
        let secrets =
            (0..stripes.len()).map(|i| unsafe { &*secret.get_unchecked(i * 8..).as_ptr().cast() });

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
        secret: &[u8],
        len: usize,
    ) -> u64 {
        debug_assert!(!last_block.is_empty());
        self.last_round(&mut acc, last_block, last_stripe, secret);

        self.final_merge(&mut acc, len.into_u64().wrapping_mul(PRIME64_1), secret, 11)
    }

    #[inline]
    fn last_round(&self, acc: &mut [u64; 8], block: &[u8], last_stripe: &[u8; 64], secret: &[u8]) {
        // Accumulation steps are run for the stripes in the last block,
        // except for the last stripe (whether it is full or not)
        let (stripes, _) = fun_name(block);

        // TODO: [unify]
        let secrets =
            (0..stripes.len()).map(|i| unsafe { &*secret.get_unchecked(i * 8..).as_ptr().cast() });

        for (stripe, secret) in stripes.iter().zip(secrets) {
            self.0.accumulate(acc, stripe, secret);
        }

        let q = &secret[secret.len() - 71..];
        let q: &[u8; 64] = unsafe { &*q.as_ptr().cast() };
        self.0.accumulate(acc, last_stripe, q);
    }

    #[inline]
    fn final_merge(
        &self,
        acc: &mut [u64; 8],
        init_value: u64,
        secret: &[u8],
        secret_offset: usize,
    ) -> u64 {
        let secret_words = unsafe {
            secret
                .as_ptr()
                .add(secret_offset)
                .cast::<[u64; 8]>()
                .read_unaligned()
        };
        let mut result = init_value;
        for i in 0..4 {
            // 64-bit by 64-bit multiplication to 128-bit full result
            let mul_result = {
                let a = (acc[i * 2] ^ secret_words[i * 2]).into_u128();
                let b = (acc[i * 2 + 1] ^ secret_words[i * 2 + 1]).into_u128();
                a.wrapping_mul(b)
            };
            result = result.wrapping_add(mul_result.lower_half() ^ mul_result.upper_half());
        }
        avalanche(result)
    }
}

#[inline]
fn fun_name(block: &[u8]) -> (&[[u8; 64]], &[u8]) {
    match block.bp_as_chunks() {
        ([stripes @ .., last], []) => (stripes, last),
        (stripes, last) => (stripes, last),
    }
}

/// # Safety
/// `input` must be non-empty.
#[inline]
unsafe fn chunks_and_last(input: &[u8], block_size: usize) -> (slice::ChunksExact<'_, u8>, &[u8]) {
    debug_assert!(!input.is_empty());

    let mut blocks = input.chunks_exact(block_size);

    let last_block = if blocks.remainder().is_empty() {
        // SAFETY: We know that `input` is non-empty, which means
        // that either there will be a remainder or one or more
        // full blocks. That info isn't flowing to the optimizer,
        // so we use `unwrap_unchecked`.
        unsafe { blocks.next_back().unwrap_unchecked() }
    } else {
        blocks.remainder()
    };

    (blocks, last_block)
}

trait Vector: Copy {
    fn round_scramble(&self, acc: &mut [u64; 8], secret_end: &[u8; 64]);

    fn accumulate(&self, acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]);
}

// This module is not `cfg`-gated because it is used by some of the
// SIMD implementations.
mod scalar {
    #[inline]
    pub fn oneshot(secret: &[u8], input: &[u8]) -> u64 {
        super::Algorithm(Impl).oneshot(secret, input)
    }

    use super::{SliceBackport as _, Vector, PRIME32_1};

    #[derive(Copy, Clone)]
    pub struct Impl;

    impl Vector for Impl {
        #[inline]
        fn round_scramble(&self, acc: &mut [u64; 8], secret_end: &[u8; 64]) {
            let (last, _) = secret_end.bp_as_chunks();
            let last = last.iter().copied().map(u64::from_ne_bytes);

            for (acc, secret) in acc.iter_mut().zip(last) {
                *acc ^= *acc >> 47;
                *acc ^= secret;
                *acc = acc.wrapping_mul(PRIME32_1);
            }
        }

        #[inline]
        fn accumulate(&self, acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]) {
            for i in 0..8 {
                let stripe = unsafe { stripe.as_ptr().cast::<u64>().add(i).read_unaligned() };
                let secret = unsafe { secret.as_ptr().cast::<u64>().add(i).read_unaligned() };

                let value = stripe ^ secret;
                acc[i ^ 1] = acc[i ^ 1].wrapping_add(stripe);
                acc[i] = multiply_64_as_32_and_add(value, value >> 32, acc[i]);
            }
        }
    }

    #[inline]
    #[cfg(not(target_arch = "aarch64"))]
    fn multiply_64_as_32_and_add(lhs: u64, rhs: u64, acc: u64) -> u64 {
        use super::IntoU64;

        let lhs = (lhs as u32).into_u64();
        let rhs = (rhs as u32).into_u64();

        let product = lhs.wrapping_mul(rhs);
        acc.wrapping_add(product)
    }

    #[inline]
    // https://github.com/Cyan4973/xxHash/blob/d5fe4f54c47bc8b8e76c6da9146c32d5c720cd79/xxhash.h#L5595-L5610
    // https://github.com/llvm/llvm-project/issues/98481
    #[cfg(target_arch = "aarch64")]
    fn multiply_64_as_32_and_add(lhs: u64, rhs: u64, acc: u64) -> u64 {
        use core::arch::asm;

        let res;

        unsafe {
            asm!(
                "umaddl {res}, {lhs:w}, {rhs:w}, {acc}",
                lhs = in(reg) lhs,
                rhs = in(reg) rhs,
                acc = in(reg) acc,
                res = out(reg) res,
            )
        }

        res
    }
}

#[cfg(target_arch = "aarch64")]
mod neon {
    use core::arch::aarch64::*;

    use super::{SliceBackport as _, Vector, PRIME32_1};

    /// # Safety
    /// You must ensure that the CPU has the NEON feature
    #[inline]
    #[target_feature(enable = "neon")]
    pub unsafe fn oneshot_unchecked(secret: &[u8], input: &[u8]) -> u64 {
        super::Algorithm(Impl::new_unchecked()).oneshot(secret, input)
    }

    #[derive(Copy, Clone)]
    pub struct Impl(());

    impl Impl {
        /// # Safety
        /// You must ensure that the CPU has the NEON feature
        #[inline]
        pub unsafe fn new_unchecked() -> Self {
            Self(())
        }
    }

    impl Vector for Impl {
        #[inline]
        fn round_scramble(&self, acc: &mut [u64; 8], secret_end: &[u8; 64]) {
            unsafe { round_scramble_neon(acc, secret_end) }
        }

        #[inline]
        fn accumulate(&self, acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]) {
            unsafe { accumulate_neon(acc, stripe, secret) }
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn round_scramble_neon(acc: &mut [u64; 8], secret_end: &[u8; 64]) {
        unsafe {
            let secret_base = secret_end.as_ptr().cast::<u64>();
            let (acc, _) = acc.bp_as_chunks_mut::<2>();
            for (i, acc) in acc.iter_mut().enumerate() {
                let mut accv = vld1q_u64(acc.as_ptr());
                let secret = vld1q_u64(secret_base.add(i * 2));

                // tmp[i] = acc[i] >> 47
                let shifted = vshrq_n_u64::<47>(accv);

                // acc[i] ^= tmp[i]
                accv = veorq_u64(accv, shifted);

                // acc[i] ^= secret[i]
                accv = veorq_u64(accv, secret);

                // acc[i] *= PRIME32_1
                accv = xx_vmulq_u32_u64(accv, PRIME32_1 as u32);

                vst1q_u64(acc.as_mut_ptr(), accv);
            }
        }
    }

    // We process 4x u64 at a time as that allows us to completely
    // fill a `uint64x2_t` with useful values when performing the
    // multiplication.
    #[target_feature(enable = "neon")]
    #[inline]
    unsafe fn accumulate_neon(acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]) {
        let (acc2, _) = acc.bp_as_chunks_mut::<4>();
        for (i, acc) in acc2.into_iter().enumerate() {
            unsafe {
                let mut accv_0 = vld1q_u64(acc.as_ptr().cast::<u64>());
                let mut accv_1 = vld1q_u64(acc.as_ptr().cast::<u64>().add(2));
                let stripe_0 = vld1q_u64(stripe.as_ptr().cast::<u64>().add(i * 4));
                let stripe_1 = vld1q_u64(stripe.as_ptr().cast::<u64>().add(i * 4 + 2));
                let secret_0 = vld1q_u64(secret.as_ptr().cast::<u64>().add(i * 4));
                let secret_1 = vld1q_u64(secret.as_ptr().cast::<u64>().add(i * 4 + 2));

                // stripe_rot[i ^ 1] = stripe[i];
                let stripe_rot_0 = vextq_u64::<1>(stripe_0, stripe_0);
                let stripe_rot_1 = vextq_u64::<1>(stripe_1, stripe_1);

                // value[i] = stripe[i] ^ secret[i];
                let value_0 = veorq_u64(stripe_0, secret_0);
                let value_1 = veorq_u64(stripe_1, secret_1);

                // sum[i] = value[i] * (value[i] >> 32) + stripe_rot[i]
                //
                // Each vector has 64-bit values, but we treat them as
                // 32-bit and then unzip them. This naturally splits
                // the upper and lower 32 bits.
                let parts_0 = vreinterpretq_u32_u64(value_0);
                let parts_1 = vreinterpretq_u32_u64(value_1);

                let hi = vuzp1q_u32(parts_0, parts_1);
                let lo = vuzp2q_u32(parts_0, parts_1);

                let sum_0 = vmlal_u32(stripe_rot_0, vget_low_u32(hi), vget_low_u32(lo));
                let sum_1 = vmlal_high_u32(stripe_rot_1, hi, lo);

                reordering_barrier(sum_0);
                reordering_barrier(sum_1);

                // acc[i] += sum[i]
                accv_0 = vaddq_u64(accv_0, sum_0);
                accv_1 = vaddq_u64(accv_1, sum_1);

                vst1q_u64(acc.as_mut_ptr().cast::<u64>(), accv_0);
                vst1q_u64(acc.as_mut_ptr().cast::<u64>().add(2), accv_1);
            };
        }
    }

    // There is no `vmulq_u64` (multiply 64-bit by 64-bit, keeping the
    // lower 64 bits of the result) operation, so we have to make our
    // own out of 32-bit operations . We can simplify by realizing
    // that we are always multiplying by a 32-bit number.
    //
    // The basic algorithm is traditional long multiplication. `[]`
    // denotes groups of 32 bits.
    //
    //         [AAAA][BBBB]
    // x             [CCCC]
    // --------------------
    //         [BCBC][BCBC]
    // + [ACAC][ACAC]
    // --------------------
    //         [ACBC][BCBC] // 64-bit truncation occurs
    //
    // This can be written in NEON as a vectorwise wrapping
    // multiplication of the high-order chunk of the input (`A`)
    // against the constant and then a multiply-widen-and-accumulate
    // of the low-order chunk of the input and the constant:
    //
    // 1. High-order, vectorwise
    //
    //         [AAAA][BBBB]
    // x       [CCCC][0000]
    // --------------------
    //         [ACAC][0000]
    //
    // 2. Low-order, widening
    //
    //               [BBBB]
    // x             [CCCC] // widening
    // --------------------
    //         [BCBC][BCBC]
    //
    // 3. Accumulation
    //
    //         [ACAC][0000]
    // +       [BCBC][BCBC] // vectorwise
    // --------------------
    //         [ACBC][BCBC]
    //
    // Thankfully, NEON has a single multiply-widen-and-accumulate
    // operation.
    #[inline]
    pub fn xx_vmulq_u32_u64(input: uint64x2_t, og_factor: u32) -> uint64x2_t {
        unsafe {
            let input_as_u32 = vreinterpretq_u32_u64(input);
            let factor = vmov_n_u32(og_factor);
            let factor_striped = vmovq_n_u64(u64::from(og_factor) << 32);
            let factor_striped = vreinterpretq_u32_u64(factor_striped);

            let high_shifted_as_32 = vmulq_u32(input_as_u32, factor_striped);
            let high_shifted = vreinterpretq_u64_u32(high_shifted_as_32);

            let input_lo = vmovn_u64(input);
            vmlal_u32(high_shifted, input_lo, factor)
        }
    }

    // https://github.com/Cyan4973/xxHash/blob/d5fe4f54c47bc8b8e76c6da9146c32d5c720cd79/xxhash.h#L5312-L5323
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn reordering_barrier(r: uint64x2_t) {
        unsafe { core::arch::asm!("/* {r:v} */", r = in(vreg) r) }
    }
}

#[cfg(all(target_arch = "aarch64", feature = "std"))]
mod aarch64_detect {
    macro_rules! pick {
        ($f:ident, $s:ident, $($t:tt)+) => {
            #[cfg(_internal_xxhash3_force_neon)]
            return unsafe { super::neon::$f $($t)+ };

            if std::arch::is_aarch64_feature_detected!("neon") {
                return unsafe { super::neon::$f $($t)+ };
            }

            super::scalar::$s $($t)+
        };
    }

    #[inline]
    pub fn oneshot(secret: &[u8], input: &[u8]) -> u64 {
        pick! { oneshot_unchecked, oneshot, (secret, input) }
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use core::arch::x86_64::*;

    use super::{scalar, Vector};

    /// # Safety
    /// You must ensure that the CPU has the AVX2 feature
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn oneshot_unchecked(secret: &[u8], input: &[u8]) -> u64 {
        super::Algorithm(Impl::new_unchecked()).oneshot(secret, input)
    }

    #[derive(Copy, Clone)]
    pub struct Impl(());

    impl Impl {
        /// # Safety
        /// You must ensure that the CPU has the AVX2 feature
        #[inline]
        pub unsafe fn new_unchecked() -> Impl {
            Impl(())
        }
    }

    impl Vector for Impl {
        #[inline]
        fn round_scramble(&self, acc: &mut [u64; 8], secret_end: &[u8; 64]) {
            // SAFETY: Type can only be constructed when AVX2 feature is present
            unsafe { round_scramble_avx2(acc, secret_end) }
        }

        #[inline]
        fn accumulate(&self, acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]) {
            // SAFETY: Type can only be constructed when AVX2 feature is present
            unsafe { accumulate_avx2(acc, stripe, secret) }
        }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn round_scramble_avx2(acc: &mut [u64; 8], secret_end: &[u8; 64]) {
        // The scalar implementation is autovectorized nicely enough
        scalar::Impl.round_scramble(acc, secret_end)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn accumulate_avx2(acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]) {
        let acc = acc.as_mut_ptr().cast::<__m256i>();
        let stripe = stripe.as_ptr().cast::<__m256i>();
        let secret = secret.as_ptr().cast::<__m256i>();

        for i in 0..2 {
            // [align-acc]: The C code aligns the accumulator to avoid
            // the unaligned load and store here, but that doesn't
            // seem to be a big performance loss.
            let mut acc_0 = _mm256_loadu_si256(acc.add(i));
            let stripe_0 = _mm256_loadu_si256(stripe.add(i));
            let secret_0 = _mm256_loadu_si256(secret.add(i));

            // let value[i] = stripe[i] ^ secret[i];
            let value_0 = _mm256_xor_si256(stripe_0, secret_0);

            // stripe_swap[i] = stripe[i ^ 1]
            let stripe_swap_0 = _mm256_shuffle_epi32::<0b01_00_11_10>(stripe_0);

            // acc[i] += stripe_swap[i]
            acc_0 = _mm256_add_epi64(acc_0, stripe_swap_0);

            // value_shift[i] = value[i] >> 32
            let value_shift_0 = _mm256_srli_epi64::<32>(value_0);

            // product[i] = lower_32_bit(value[i]) * lower_32_bit(value_shift[i])
            let product_0 = _mm256_mul_epu32(value_0, value_shift_0);

            // acc[i] += product[i]
            acc_0 = _mm256_add_epi64(acc_0, product_0);

            _mm256_storeu_si256(acc.add(i), acc_0);
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod sse2 {
    use core::arch::x86_64::*;

    use super::{scalar, Vector};

    /// # Safety
    /// You must ensure that the CPU has the SSE2 feature
    #[inline]
    #[target_feature(enable = "sse2")]
    pub unsafe fn oneshot_unchecked(secret: &[u8], input: &[u8]) -> u64 {
        super::Algorithm(Impl::new_unchecked()).oneshot(secret, input)
    }

    #[derive(Copy, Clone)]
    pub struct Impl(());

    impl Impl {
        /// # Safety
        /// You must ensure that the CPU has the SSE2 feature
        #[inline]
        pub unsafe fn new_unchecked() -> Impl {
            Impl(())
        }
    }

    impl Vector for Impl {
        #[inline]
        fn round_scramble(&self, acc: &mut [u64; 8], secret_end: &[u8; 64]) {
            // SAFETY: Type can only be constructed when SSE2 feature is present
            unsafe { round_scramble_sse2(acc, secret_end) }
        }

        #[inline]
        fn accumulate(&self, acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]) {
            // SAFETY: Type can only be constructed when SSE2 feature is present
            unsafe { accumulate_sse2(acc, stripe, secret) }
        }
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn round_scramble_sse2(acc: &mut [u64; 8], secret_end: &[u8; 64]) {
        // The scalar implementation is autovectorized nicely enough
        scalar::Impl.round_scramble(acc, secret_end)
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn accumulate_sse2(acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]) {
        let acc = acc.as_mut_ptr().cast::<__m128i>();
        let stripe = stripe.as_ptr().cast::<__m128i>();
        let secret = secret.as_ptr().cast::<__m128i>();

        for i in 0..4 {
            // See [align-acc].
            let mut acc_0 = _mm_loadu_si128(acc.add(i));
            let stripe_0 = _mm_loadu_si128(stripe.add(i));
            let secret_0 = _mm_loadu_si128(secret.add(i));

            // let value[i] = stripe[i] ^ secret[i];
            let value_0 = _mm_xor_si128(stripe_0, secret_0);

            // stripe_swap[i] = stripe[i ^ 1]
            let stripe_swap_0 = _mm_shuffle_epi32::<0b01_00_11_10>(stripe_0);

            // acc[i] += stripe_swap[i]
            acc_0 = _mm_add_epi64(acc_0, stripe_swap_0);

            // value_shift[i] = value[i] >> 32
            let value_shift_0 = _mm_srli_epi64::<32>(value_0);

            // product[i] = lower_32_bit(value[i]) * lower_32_bit(value_shift[i])
            let product_0 = _mm_mul_epu32(value_0, value_shift_0);

            // acc[i] += product[i]
            acc_0 = _mm_add_epi64(acc_0, product_0);

            _mm_storeu_si128(acc.add(i), acc_0);
        }
    }
}

#[cfg(all(target_arch = "x86_64", feature = "std"))]
mod x86_64_detect {
    macro_rules! pick {
        ($f:ident, $s:ident, $($t:tt)+) => {
            #[cfg(_internal_xxhash3_force_avx2)]
            return unsafe { super::avx2::$f $($t)+ };

            #[cfg(_internal_xxhash3_force_sse2)]
            return unsafe { super::sse2::$f $($t)+ };

            if std::arch::is_x86_feature_detected!("avx2") {
                return unsafe { super::avx2::$f $($t)+ };
            }

            if std::arch::is_x86_feature_detected!("sse2") {
                return unsafe { super::sse2::$f $($t)+ };
            }

            super::scalar::$s $($t)+
        };
    }

    #[inline]
    pub fn oneshot(secret: &[u8], input: &[u8]) -> u64 {
        pick! { oneshot_unchecked, oneshot, (secret, input) }
    }
}

mod detect {
    macro_rules! pick {
        ($e:expr) => {
            #[cfg(_internal_xxhash3_force_scalar)]
            {
                use super::scalar::*;
                return $e;
            }

            #[cfg(all(target_arch = "aarch64", feature = "std"))]
            {
                use super::aarch64_detect::*;
                return $e;
            }

            #[cfg(all(target_arch = "x86_64", feature = "std"))]
            {
                use super::x86_64_detect::*;
                return $e;
            }

            #[allow(unreachable_code)]
            {
                use super::scalar::*;
                $e
            }
        };
    }

    #[inline]
    pub fn oneshot(secret: &[u8], input: &[u8]) -> u64 {
        pick! { oneshot(secret, input) }
    }
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

trait SliceBackport<T> {
    fn bp_as_chunks<const N: usize>(&self) -> (&[[T; N]], &[T]);

    #[cfg(target_arch = "aarch64")]
    fn bp_as_chunks_mut<const N: usize>(&mut self) -> (&mut [[T; N]], &mut [T]);

    fn bp_as_rchunks<const N: usize>(&self) -> (&[T], &[[T; N]]);
}

impl<T> SliceBackport<T> for [T] {
    fn bp_as_chunks<const N: usize>(&self) -> (&[[T; N]], &[T]) {
        assert_ne!(N, 0);
        let len = self.len() / N;
        let (head, tail) = unsafe { self.split_at_unchecked(len * N) };
        let head = unsafe { slice::from_raw_parts(head.as_ptr().cast(), len) };
        (head, tail)
    }

    #[cfg(target_arch = "aarch64")]
    fn bp_as_chunks_mut<const N: usize>(&mut self) -> (&mut [[T; N]], &mut [T]) {
        assert_ne!(N, 0);
        let len = self.len() / N;
        let (head, tail) = unsafe { self.split_at_mut_unchecked(len * N) };
        let head = unsafe { slice::from_raw_parts_mut(head.as_mut_ptr().cast(), len) };
        (head, tail)
    }

    fn bp_as_rchunks<const N: usize>(&self) -> (&[T], &[[T; N]]) {
        assert_ne!(N, 0);
        let len = self.len() / N;
        let (head, tail) = unsafe { self.split_at_unchecked(self.len() - len * N) };
        let tail = unsafe { slice::from_raw_parts(tail.as_ptr().cast(), len) };
        (head, tail)
    }
}

#[cfg(test)]
mod test {
    use std::{array, hash::Hasher};

    use super::*;

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

    #[test]
    fn secret_buffer_allocate_with_seed_and_secret_is_valid() {
        let secret = [42; 1024];
        assert!(SecretBuffer::allocate_with_seed_and_secret(0xdead_beef, secret).is_valid())
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
        let mut hasher = XxHash3_64::new();
        for byte in input.chunks(1) {
            hasher.write(byte)
        }
        hasher.finish()
    }

    fn hash_byte_by_byte_with_seed(seed: u64, input: &[u8]) -> u64 {
        let mut hasher = XxHash3_64::with_seed(seed);
        for byte in input.chunks(1) {
            hasher.write(byte)
        }
        hasher.finish()
    }

    #[test]
    fn oneshot_empty() {
        let hash = XxHash3_64::oneshot(&[]);
        assert_eq!(hash, 0x2d06_8005_38d3_94c2);
    }

    #[test]
    fn streaming_empty() {
        let hash = hash_byte_by_byte(&[]);
        assert_eq!(hash, 0x2d06_8005_38d3_94c2);
    }

    #[test]
    fn oneshot_1_to_3_bytes() {
        test_1_to_3_bytes(XxHash3_64::oneshot)
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
        test_4_to_8_bytes(XxHash3_64::oneshot)
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
        test_9_to_16_bytes(XxHash3_64::oneshot)
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
        test_17_to_128_bytes(XxHash3_64::oneshot)
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
        test_129_to_240_bytes(XxHash3_64::oneshot)
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
        test_241_plus_bytes(XxHash3_64::oneshot)
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
        test_with_seed(XxHash3_64::oneshot_with_seed)
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
        assert_eq!(b, &[]);

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
        assert_eq!(b, &[]);

        let (a, b) = x.bp_as_chunks::<6>();
        assert_eq!(a, &[] as &[[i32; 6]]);
        assert_eq!(b, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn backported_as_rchunks() {
        let x = [1, 2, 3, 4, 5];

        let (a, b) = x.bp_as_rchunks::<1>();
        assert_eq!(a, &[]);
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
        assert_eq!(a, &[]);
        assert_eq!(b, &[[1, 2, 3, 4, 5]]);

        let (a, b) = x.bp_as_rchunks::<6>();
        assert_eq!(a, &[1, 2, 3, 4, 5]);
        assert_eq!(b, &[] as &[[i32; 6]]);
    }
}
