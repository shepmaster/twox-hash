//! The XXH3 algorithm.
//!
//! XXH3 is a new hash algorithm featuring:
//!  - Improved speed for both small and large inputs
//!  - True 64-bit and 128-bit outputs
//!  - SIMD acceleration
//!  - Improved 32-bit viability
//!
//! Speed analysis methodology is explained here:
//!
//!    <https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html>
//!
//! In general, expect XXH3 to run about ~2x faster on large inputs and >3x
//! faster on small ones compared to XXH64, though exact differences depend on
//! the platform.
//!
//! The algorithm is portable: Like XXH32 and XXH64, it generates the same hash
//! on all platforms.
//!
//! It benefits greatly from SIMD and 64-bit arithmetic, but does not require it.
//!
//! Almost all 32-bit and 64-bit targets that can run XXH32 smoothly can run
//! XXH3 at competitive speeds, even if XXH64 runs slowly. Further details are
//! explained in the implementation.
//!
//! Optimized implementations are provided for AVX512, AVX2, SSE2, NEON, POWER8,
//! ZVector and scalar targets. This can be controlled with the XXH_VECTOR macro.
//!
//! XXH3 offers 2 variants, _64bits and _128bits.
//! When only 64 bits are needed, prefer calling the _64bits variant, as it
//! reduces the amount of mixing, resulting in faster speed on small inputs.
//!
//! It's also generally simpler to manipulate a scalar return type than a struct.
//!
//! The 128-bit version adds additional strength, but it is slightly slower.
//!
//! The XXH3 algorithm is still in development.
//! The results it produces may still change in future versions.
//!
//! Results produced by v0.7.x are not comparable with results from v0.7.y.
//! However, the API is completely stable, and it can safely be used for
//! ephemeral data (local sessions).
//!
//! Avoid storing values in long-term storage until the algorithm is finalized.
//! XXH3's return values will be officially finalized upon reaching v0.8.0.
//!
//! After which, return values of XXH3 and XXH128 will no longer change in
//! future versions.
//!
//! The API supports one-shot hashing, streaming mode, and custom secrets.

use alloc::vec::Vec;

use core::hash::Hasher;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::ptr;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use cfg_if::cfg_if;
use static_assertions::{const_assert, const_assert_eq};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

use crate::sixty_four::{
    PRIME_1 as PRIME64_1, PRIME_2 as PRIME64_2, PRIME_3 as PRIME64_3, PRIME_4 as PRIME64_4,
    PRIME_5 as PRIME64_5,
};
use crate::thirty_two::{PRIME_1 as PRIME32_1, PRIME_2 as PRIME32_2, PRIME_3 as PRIME32_3};

#[cfg(feature = "std")]
pub use crate::std_support::xxh3::{RandomHashBuilder128, RandomHashBuilder64};

/// Default 64-bit variant, using default secret and default seed of 0.
///
/// It's the fastest variant.
#[inline(always)]
pub fn hash64(data: &[u8]) -> u64 {
    hash64_internal(data, 0, &SECRET, || {
        hash_long_64bits_internal(data, &SECRET)
    })
}

/// This variant generates a custom secret on the fly based on default secret altered using the `seed` value.
///
/// While this operation is decently fast, note that it's not completely free.
/// Note: seed==0 produces the same results as XXH3_64bits().
#[inline(always)]
pub fn hash64_with_seed(data: &[u8], seed: u64) -> u64 {
    hash64_internal(data, seed, &SECRET, || {
        if seed == 0 {
            hash_long_64bits_internal(data, &SECRET)
        } else {
            let secret = Secret::with_seed(seed);

            hash_long_64bits_internal(data, &secret)
        }
    })
}

/// Default 64-bit variant, using a secret and default seed of 0.
///
/// It's possible to provide any blob of bytes as a "secret" to generate the hash.
/// This makes it more difficult for an external actor to prepare an intentional collision.
/// The main condition is that secretSize *must* be large enough (>= Secret::SIZE_MIN).
/// However, the quality of produced hash values depends on secret's entropy.
/// Technically, the secret must look like a bunch of random bytes.
/// Avoid "trivial" or structured data such as repeated sequences or a text document.
/// Whenever unsure about the "randomness" of the blob of bytes,
/// consider relabelling it as a "custom seed" instead,
/// and employ "XXH3_generateSecret()" (see below)
/// to generate a high entropy secret derived from the custom seed.
#[inline(always)]
pub fn hash64_with_secret(data: &[u8], secret: &[u8]) -> u64 {
    hash64_internal(data, 0, secret, || hash_long_64bits_internal(data, secret))
}

#[inline(always)]
fn hash64_internal<F>(data: &[u8], seed: u64, secret: &[u8], hash_long_64bits: F) -> u64
where
    F: FnOnce() -> u64,
{
    debug_assert!(secret.len() >= Secret::SIZE_MIN);

    let len = data.len();

    if len <= 16 {
        hash_len_0to16_64bits(data, len, secret, seed)
    } else if len <= 128 {
        hash_len_17to128_64bits(data, len, secret, seed)
    } else if len <= MIDSIZE_MAX {
        hash_len_129to240_64bits(data, len, secret, seed)
    } else {
        hash_long_64bits()
    }
}

#[inline(always)]
pub fn hash128(data: &[u8]) -> u128 {
    hash128_internal(data, 0, &SECRET, || {
        hash_long_128bits_internal(data, &SECRET)
    })
}

#[inline(always)]
pub fn hash128_with_seed(data: &[u8], seed: u64) -> u128 {
    hash128_internal(data, seed, &SECRET, || {
        if seed == 0 {
            hash_long_128bits_internal(data, &SECRET)
        } else {
            let secret = Secret::with_seed(seed);

            hash_long_128bits_internal(data, &secret)
        }
    })
}

#[inline(always)]
pub fn hash128_with_secret(data: &[u8], secret: &[u8]) -> u128 {
    hash128_internal(data, 0, secret, || hash_long_128bits_internal(data, secret))
}

#[inline(always)]
fn hash128_internal<F>(data: &[u8], seed: u64, secret: &[u8], hash_long_128bits: F) -> u128
where
    F: FnOnce() -> u128,
{
    debug_assert!(secret.len() >= Secret::SIZE_MIN);

    let len = data.len();

    if len <= 16 {
        hash_len_0to16_128bits(data, len, secret, seed)
    } else if len <= 128 {
        hash_len_17to128_128bits(data, len, secret, seed)
    } else if len <= MIDSIZE_MAX {
        hash_len_129to240_128bits(data, len, secret, seed)
    } else {
        hash_long_128bits()
    }
}

/// Calculates the 64-bit hash.
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
#[derive(Clone, Default)]
pub struct Hash64(State);

impl Hash64 {
    pub fn with_seed(seed: u64) -> Self {
        Self(State::with_seed(seed))
    }

    pub fn with_secret<S: Into<Vec<u8>>>(secret: S) -> Self {
        Self(State::with_secret(secret))
    }
}

impl Hasher for Hash64 {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.0.digest64()
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }
}

/// Calculates the 128-bit hash.
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
#[derive(Clone, Default)]
pub struct Hash128(State);

impl Hash128 {
    pub fn with_seed(seed: u64) -> Self {
        Self(State::with_seed(seed))
    }

    pub fn with_secret<S: Into<Vec<u8>>>(secret: S) -> Self {
        Self(State::with_secret(secret))
    }
}

impl Hasher for Hash128 {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.0.digest128() as u64
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }
}

pub trait HasherExt: Hasher {
    fn finish_ext(&self) -> u128;
}

impl HasherExt for Hash128 {
    #[inline(always)]
    fn finish_ext(&self) -> u128 {
        self.0.digest128()
    }
}

/* ==========================================
 * XXH3 default settings
 * ========================================== */

const SECRET: Secret = Secret([
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
]);

#[repr(align(64))]
#[derive(Clone)]
struct Secret([u8; Secret::DEFAULT_SIZE]);

impl Deref for Secret {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

const_assert!(Secret::DEFAULT_SIZE >= Secret::SIZE_MIN);
const_assert_eq!(mem::size_of::<Secret>() % mem::size_of::<u128>(), 0);

impl Secret {
    pub const SIZE_MIN: usize = 136;
    pub const DEFAULT_SIZE: usize = 192;

    #[inline(always)]
    pub fn with_seed(seed: u64) -> Self {
        Secret(unsafe { init_custom_secret(seed) })
    }
}

cfg_if! {
    if #[cfg(feature = "serialize")] {
        impl Serialize for Secret {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_bytes(self)
            }
        }

        impl<'de> Deserialize<'de> for Secret {
            fn deserialize<D>(deserializer: D) -> Result<Secret, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_bytes(SecretVisitor)
            }
        }

        struct SecretVisitor;

        impl<'de> serde::de::Visitor<'de> for SecretVisitor {
            type Value = Secret;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("secret with a bytes array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() == Secret::DEFAULT_SIZE {
                    let mut secret = [0; Secret::DEFAULT_SIZE];

                    secret.copy_from_slice(v);

                    Ok(Secret(secret))
                } else {
                    Err(E::custom("incomplete secret data"))
                }
            }
        }
    }
}

#[cfg_attr(target_feature = "avx2", repr(align(32)))]
#[cfg_attr(
    all(not(target_feature = "avx2"), target_feature = "sse2"),
    repr(align(16))
)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
#[derive(Clone)]
struct Acc([u64; ACC_NB]);

const_assert_eq!(Acc::SIZE, 64);

impl Acc {
    pub const SIZE: usize = mem::size_of::<Self>();
}

impl Default for Acc {
    #[inline(always)]
    fn default() -> Self {
        Acc([
            u64::from(PRIME32_3),
            PRIME64_1,
            PRIME64_2,
            PRIME64_3,
            PRIME64_4,
            u64::from(PRIME32_2),
            PRIME64_5,
            u64::from(PRIME32_1),
        ])
    }
}

impl Deref for Acc {
    type Target = [u64];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Acc {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

trait ReadU32 {
    fn read_le32(&self) -> u32;
}

trait ReadU64 {
    fn read_le64(&self) -> u64;
}

trait WriteU32 {
    fn write_le32(&mut self, n: u32);
}

trait WriteU64 {
    fn write_le64(&mut self, n: u64);
}

impl ReadU32 for *const u32 {
    #[inline(always)]
    fn read_le32(&self) -> u32 {
        u32::from_le(unsafe { self.read() })
    }
}

impl ReadU64 for *const u64 {
    #[inline(always)]
    fn read_le64(&self) -> u64 {
        u64::from_le(unsafe { self.read() })
    }
}

impl ReadU32 for [u8] {
    #[inline(always)]
    fn read_le32(&self) -> u32 {
        u32::from_le(unsafe { self.as_ptr().cast::<u32>().read() })
    }
}

impl ReadU64 for [u8] {
    #[inline(always)]
    fn read_le64(&self) -> u64 {
        u64::from_le(unsafe { self.as_ptr().cast::<u64>().read() })
    }
}

impl WriteU32 for [u8] {
    #[inline(always)]
    fn write_le32(&mut self, n: u32) {
        unsafe { self.as_mut_ptr().cast::<u32>().write(u32::to_le(n)) }
    }
}

impl WriteU64 for [u8] {
    #[inline(always)]
    fn write_le64(&mut self, n: u64) {
        unsafe { self.as_mut_ptr().cast::<u64>().write(u64::to_le(n)) }
    }
}

/* ==========================================
 * Short keys
 * ========================================== */

#[inline(always)]
fn hash_len_0to16_64bits(data: &[u8], len: usize, secret: &[u8], seed: u64) -> u64 {
    debug_assert!(len <= 16);

    if len > 8 {
        hash_len_9to16_64bits(data, len, secret, seed)
    } else if len >= 4 {
        hash_len_4to8_64bits(data, len, secret, seed)
    } else if len > 0 {
        hash_len_1to3_64bits(data, len, secret, seed)
    } else {
        xxh64_avalanche(seed ^ (secret[56..].read_le64() ^ secret[64..].read_le64()))
    }
}

#[inline(always)]
fn hash_len_9to16_64bits(input: &[u8], len: usize, secret: &[u8], seed: u64) -> u64 {
    debug_assert!((9..=16).contains(&len));

    let bitflip1 = (secret[24..].read_le64() ^ secret[32..].read_le64()).wrapping_add(seed);
    let bitflip2 = (secret[40..].read_le64() ^ secret[48..].read_le64()).wrapping_sub(seed);
    let input_lo = input.read_le64() ^ bitflip1;
    let input_hi = input[len - 8..].read_le64() ^ bitflip2;
    let acc = (len as u64)
        .wrapping_add(input_lo.swap_bytes())
        .wrapping_add(input_hi)
        .wrapping_add(mul128_fold64(input_lo, input_hi));

    avalanche(acc)
}

#[inline(always)]
fn hash_len_4to8_64bits(input: &[u8], len: usize, secret: &[u8], mut seed: u64) -> u64 {
    debug_assert!((4..=8).contains(&len));

    seed ^= u64::from((seed as u32).swap_bytes()) << 32;

    let input1 = u64::from(input.read_le32());
    let input2 = u64::from(input[len - 4..].read_le32());
    let bitflip = (secret[8..].read_le64() ^ secret[16..].read_le64()).wrapping_sub(seed);
    let input64 = input2.wrapping_add(input1 << 32);
    let keyed = input64 ^ bitflip;

    rrmxmx(keyed, len)
}

#[inline(always)]
fn hash_len_1to3_64bits(input: &[u8], len: usize, secret: &[u8], seed: u64) -> u64 {
    debug_assert!((1..=3).contains(&len));

    /*
     * len = 1: combined = { input[0], 0x01, input[0], input[0] }
     * len = 2: combined = { input[1], 0x02, input[0], input[1] }
     * len = 3: combined = { input[2], 0x03, input[0], input[1] }
     */
    let c1 = u32::from(input[0]);
    let c2 = u32::from(input[len >> 1]);
    let c3 = u32::from(input[len - 1]);
    let combined = (c1 << 16) | (c2 << 24) | c3 | ((len as u32) << 8);
    let bitflip = u64::from(secret.read_le32() ^ secret[4..].read_le32()).wrapping_add(seed);
    let keyed = u64::from(combined) ^ bitflip;

    xxh64_avalanche(keyed)
}

/// For mid range keys, XXH3 uses a Mum-hash variant.
#[inline(always)]
fn hash_len_17to128_64bits(data: &[u8], len: usize, secret: &[u8], seed: u64) -> u64 {
    debug_assert!((17..=128).contains(&len));
    debug_assert!(secret.len() >= Secret::SIZE_MIN);

    let mut acc = (len as u64).wrapping_mul(PRIME64_1);

    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc = acc
                    .wrapping_add(mix16bytes(&data[48..], &secret[96..], seed))
                    .wrapping_add(mix16bytes(&data[len - 64..], &secret[112..], seed));
            }
            acc = acc
                .wrapping_add(mix16bytes(&data[32..], &secret[64..], seed))
                .wrapping_add(mix16bytes(&data[len - 48..], &secret[80..], seed));
        }

        acc = acc
            .wrapping_add(mix16bytes(&data[16..], &secret[32..], seed))
            .wrapping_add(mix16bytes(&data[len - 32..], &secret[48..], seed));
    }

    acc = acc
        .wrapping_add(mix16bytes(data, &secret, seed))
        .wrapping_add(mix16bytes(&data[len - 16..], &secret[16..], seed));

    avalanche(acc)
}

const MIDSIZE_MAX: usize = 240;
const MIDSIZE_START_OFFSET: usize = 3;
const MIDSIZE_LAST_OFFSET: usize = 17;

#[inline(always)]
fn hash_len_129to240_64bits(data: &[u8], len: usize, secret: &[u8], seed: u64) -> u64 {
    debug_assert!((129..=MIDSIZE_MAX).contains(&len));
    debug_assert!(secret.len() >= Secret::SIZE_MIN);

    let acc = (len as u64).wrapping_mul(PRIME64_1);
    let acc = (0..8).fold(acc, |acc, i| {
        acc.wrapping_add(mix16bytes(&data[16 * i..], &secret[16 * i..], seed))
    });
    let acc = avalanche(acc);

    let rounds = len / 16;
    debug_assert!(rounds >= 8);

    let acc = (8..rounds).fold(acc, |acc, i| {
        acc.wrapping_add(mix16bytes(
            &data[16 * i..],
            &secret[16 * (i - 8) + MIDSIZE_START_OFFSET..],
            seed,
        ))
    });

    let acc = acc.wrapping_add(mix16bytes(
        &data[len - 16..],
        &secret[Secret::SIZE_MIN - MIDSIZE_LAST_OFFSET..],
        seed,
    ));

    avalanche(acc)
}

/* ==========================================
 * Long keys
 * ========================================== */

const STRIPE_LEN: usize = 64;
const SECRET_CONSUME_RATE: usize = 8; // nb of secret bytes consumed at each accumulation
const SECRET_MERGEACCS_START: usize = 11; // do not align on 8, so that secret is different from accumulator
const SECRET_LASTACC_START: usize = 7; // do not align on 8, so that secret is different from scrambler

const ACC_NB: usize = STRIPE_LEN / mem::size_of::<u64>();

#[inline(always)]
fn hash_long_64bits_internal(input: &[u8], secret: &[u8]) -> u64 {
    let len = input.len();
    let mut acc = Acc::default();

    hash_long_internal_loop(&mut acc, input, len, secret);

    debug_assert!(secret.len() >= mem::size_of::<Acc>() + SECRET_MERGEACCS_START);

    merge_accs(
        &acc,
        &secret[SECRET_MERGEACCS_START..],
        PRIME64_1.wrapping_mul(len as u64),
    )
}

#[inline(always)]
fn hash_long_internal_loop(acc: &mut [u64], input: &[u8], len: usize, secret: &[u8]) {
    let secret_size = secret.len();
    let nb_stripes_per_block = (secret_size - STRIPE_LEN) / SECRET_CONSUME_RATE;
    let block_len = STRIPE_LEN * nb_stripes_per_block;
    let nb_blocks = (len - 1) / block_len;

    debug_assert!(secret_size >= Secret::SIZE_MIN);

    for i in 0..nb_blocks {
        accumulate(acc, &input[i * block_len..], secret, nb_stripes_per_block);
        unsafe {
            scramble_acc(acc, &secret[secret_size - STRIPE_LEN..]);
        }
    }

    /* last partial block */
    debug_assert!(len > STRIPE_LEN);

    let block_size = block_len * nb_blocks;
    let nb_stripes = (len - 1 - block_size) / STRIPE_LEN;

    debug_assert!(nb_stripes < (secret_size / SECRET_CONSUME_RATE));

    accumulate(acc, &input[block_size..], secret, nb_stripes);

    // last stripe
    unsafe {
        accumulate512(
            acc,
            &input[len - STRIPE_LEN..],
            &secret[secret_size - STRIPE_LEN - SECRET_LASTACC_START..],
        );
    }
}

const PREFETCH_DIST: isize = 384;

#[inline(always)]
fn accumulate(acc: &mut [u64], input: &[u8], secret: &[u8], nb_stripes: usize) {
    for (chunk, secret) in input
        .chunks(STRIPE_LEN)
        .zip(secret.chunks(SECRET_CONSUME_RATE))
        .take(nb_stripes)
    {
        unsafe {
            prefetch(chunk.as_ptr().offset(PREFETCH_DIST).cast());
            accumulate512(acc, chunk, secret);
        }
    }
}

#[inline(always)]
unsafe fn prefetch(p: *const i8) {
    _mm_prefetch(p, _MM_HINT_T0);
}

#[inline(always)]
const fn _mm_shuffle(z: i32, y: i32, x: i32, w: i32) -> i32 {
    (z << 6) | (y << 4) | (x << 2) | w
}

#[cfg(target_feature = "avx2")]
mod avx2 {
    use super::*;

    const_assert!((mem::align_of::<Acc>() % mem::size_of::<__m256i>()) == 0);

    pub unsafe fn accumulate512(acc: &mut [u64], input: &[u8], secret: &[u8]) {
        let xacc = acc.as_mut_ptr().cast::<__m256i>();
        let xinput = input.as_ptr().cast::<__m256i>();
        let xsecret = secret.as_ptr().cast::<__m256i>();

        for i in 0..STRIPE_LEN / mem::size_of::<__m256i>() {
            // data_vec = xinput[i];
            let data_vec = _mm256_loadu_si256(xinput.add(i));

            // key_vec = xsecret[i];
            let key_vec = _mm256_loadu_si256(xsecret.add(i));

            // data_key = data_vec ^ key_vec;
            let data_key = _mm256_xor_si256(data_vec, key_vec);

            // data_key_lo = data_key >> 32;
            let data_key_lo = _mm256_shuffle_epi32(data_key, _mm_shuffle(0, 3, 0, 1));

            // product = (data_key & 0xffffffff) * (data_key_lo & 0xffffffff);
            let product = _mm256_mul_epu32(data_key, data_key_lo);

            // xacc[i] += swap(data_vec);
            let data_swap = _mm256_shuffle_epi32(data_vec, _mm_shuffle(1, 0, 3, 2));
            let sum = _mm256_add_epi64(xacc.add(i).read(), data_swap);

            // xacc[i] += product;
            xacc.add(i).write(_mm256_add_epi64(product, sum));
        }
    }

    pub unsafe fn scramble_acc(acc: &mut [u64], secret: &[u8]) {
        let xacc = acc.as_mut_ptr().cast::<__m256i>();
        let xsecret = secret.as_ptr().cast::<__m256i>();
        let prime32 = _mm256_set1_epi32(PRIME32_1 as i32);

        for i in 0..STRIPE_LEN / mem::size_of::<__m256i>() {
            // xacc[i] ^= (xacc[i] >> 47)
            let acc_vec = xacc.add(i).read();
            let shifted = _mm256_srli_epi64(acc_vec, 47);
            let data_vec = _mm256_xor_si256(acc_vec, shifted);

            // xacc[i] ^= xsecret;
            let key_vec = _mm256_loadu_si256(xsecret.add(i));
            let data_key = _mm256_xor_si256(data_vec, key_vec);

            // xacc[i] *= XXH_PRIME32_1;
            let data_key_hi = _mm256_shuffle_epi32(data_key, _mm_shuffle(0, 3, 0, 1));
            let prod_lo = _mm256_mul_epu32(data_key, prime32);
            let prod_hi = _mm256_mul_epu32(data_key_hi, prime32);
            xacc.add(i)
                .write(_mm256_add_epi64(prod_lo, _mm256_slli_epi64(prod_hi, 32)));
        }
    }

    const_assert_eq!(Secret::DEFAULT_SIZE % mem::size_of::<__m256i>(), 0);
    const_assert_eq!(Secret::DEFAULT_SIZE / mem::size_of::<__m256i>(), 6);

    #[target_feature(enable = "avx2")]
    pub unsafe fn init_custom_secret(seed: u64) -> [u8; Secret::DEFAULT_SIZE] {
        let mut secret = mem::MaybeUninit::<[u8; Secret::DEFAULT_SIZE]>::zeroed();

        let seed64 = seed as i64;
        let seed = _mm256_set_epi64x(-seed64, seed64, -seed64, seed64);
        let src = SECRET.as_ptr().cast::<__m256i>();
        let dest = secret.as_mut_ptr().cast::<__m256i>();

        dest.offset(0)
            .write(_mm256_add_epi64(_mm256_load_si256(src.offset(0)), seed));
        dest.offset(1)
            .write(_mm256_add_epi64(_mm256_load_si256(src.offset(1)), seed));
        dest.offset(2)
            .write(_mm256_add_epi64(_mm256_load_si256(src.offset(2)), seed));
        dest.offset(3)
            .write(_mm256_add_epi64(_mm256_load_si256(src.offset(3)), seed));
        dest.offset(4)
            .write(_mm256_add_epi64(_mm256_load_si256(src.offset(4)), seed));
        dest.offset(5)
            .write(_mm256_add_epi64(_mm256_load_si256(src.offset(5)), seed));

        secret.assume_init()
    }
}

#[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
mod sse2 {
    use super::*;

    const_assert_eq!(mem::align_of::<Acc>() % mem::size_of::<__m128i>(), 0);

    pub unsafe fn accumulate512(acc: &mut [u64], input: &[u8], secret: &[u8]) {
        let xacc = acc.as_mut_ptr().cast::<__m128i>();
        let xinput = input.as_ptr().cast::<__m128i>();
        let xsecret = secret.as_ptr().cast::<__m128i>();

        for i in 0..STRIPE_LEN / mem::size_of::<__m128i>() {
            // data_vec = xinput[i];
            let data_vec = _mm_loadu_si128(xinput.add(i));

            // key_vec = xsecret[i];
            let key_vec = _mm_loadu_si128(xsecret.add(i));

            // data_key = data_vec ^ key_vec;
            let data_key = _mm_xor_si128(data_vec, key_vec);

            // data_key_lo = data_key >> 32;
            let data_key_lo = _mm_shuffle_epi32(data_key, _mm_shuffle(0, 3, 0, 1));

            // product = (data_key & 0xffffffff) * (data_key_lo & 0xffffffff);
            let product = _mm_mul_epu32(data_key, data_key_lo);

            // xacc[i] += swap(data_vec);
            let data_swap = _mm_shuffle_epi32(data_vec, _mm_shuffle(1, 0, 3, 2));
            let sum = _mm_add_epi64(xacc.add(i).read(), data_swap);

            // xacc[i] += product;
            xacc.add(i).write(_mm_add_epi64(product, sum));
        }
    }

    pub unsafe fn scramble_acc(acc: &mut [u64], secret: &[u8]) {
        let xacc = acc.as_mut_ptr().cast::<__m128i>();
        let xsecret = secret.as_ptr().cast::<__m128i>();
        let prime32 = _mm_set1_epi32(PRIME32_1 as i32);

        for i in 0..STRIPE_LEN / mem::size_of::<__m128i>() {
            // xacc[i] ^= (xacc[i] >> 47)
            let acc_vec = xacc.add(i).read();
            let shifted = _mm_srli_epi64(acc_vec, 47);
            let data_vec = _mm_xor_si128(acc_vec, shifted);

            // xacc[i] ^= xsecret[i];
            let key_vec = _mm_loadu_si128(xsecret.add(i));
            let data_key = _mm_xor_si128(data_vec, key_vec);

            // xacc[i] *= XXH_PRIME32_1;
            let data_key_hi = _mm_shuffle_epi32(data_key, _mm_shuffle(0, 3, 0, 1));
            let prod_lo = _mm_mul_epu32(data_key, prime32);
            let prod_hi = _mm_mul_epu32(data_key_hi, prime32);
            xacc.add(i)
                .write(_mm_add_epi64(prod_lo, _mm_slli_epi32(prod_hi, 32)));
        }
    }

    const_assert_eq!(Secret::DEFAULT_SIZE % mem::size_of::<__m128i>(), 0);

    pub unsafe fn init_custom_secret(seed: u64) -> [u8; Secret::DEFAULT_SIZE] {
        let mut secret = mem::MaybeUninit::<[u8; Secret::DEFAULT_SIZE]>::zeroed();

        let seed64 = seed as i64;
        let seed = _mm_set_epi64x(-seed64, seed64);

        let rounds = Secret::DEFAULT_SIZE / mem::size_of::<__m128i>();
        let src = SECRET.as_ptr().cast::<f32>();
        let dest = secret.as_mut_ptr().cast::<__m128i>();

        for i in 0..rounds {
            dest.add(i).write(_mm_add_epi64(
                _mm_castps_si128(_mm_load_ps(src.add(i * 4))),
                seed,
            ))
        }

        secret.assume_init()
    }
}

/// scalar variants - universal
#[cfg(not(any(target_feature = "sse2", target_feature = "avx2")))]
mod generic {
    use super::*;

    const_assert_eq!(mem::align_of::<Acc>() % mem::size_of::<u64>(), 0);

    #[inline(always)]
    pub unsafe fn accumulate512(acc: &mut [u64], data: &[u8], secret: &[u8]) {
        let xinput = data.as_ptr().cast::<u64>();
        let xsecret = secret.as_ptr().cast::<u64>();

        for i in 0..ACC_NB {
            let data_val = xinput.add(i).read_le64();
            let data_key = data_val ^ xsecret.add(i).read_le64();
            acc[i ^ 1] = acc[i ^ 1].wrapping_add(data_val); // swap adjacent lanes
            acc[i] = acc[i].wrapping_add(mul32_to64(data_key as u32, (data_key >> 32) as u32));
        }
    }

    #[inline(always)]
    fn mul32_to64(a: u32, b: u32) -> u64 {
        u64::from(a).wrapping_mul(u64::from(b))
    }

    #[inline(always)]
    pub unsafe fn scramble_acc(acc: &mut [u64], secret: &[u8]) {
        let xsecret = secret.as_ptr().cast::<u64>();

        for i in 0..ACC_NB {
            let key64 = xsecret.add(i).read_le64();
            let mut acc64 = acc[i];
            acc64 = xorshift64(acc64, 47);
            acc64 ^= key64;
            acc64 = acc64.wrapping_mul(u64::from(PRIME32_1));
            acc[i] = acc64;
        }
    }

    const_assert_eq!(Secret::DEFAULT_SIZE % mem::size_of::<u128>(), 0);

    pub unsafe fn init_custom_secret(seed: u64) -> [u8; Secret::DEFAULT_SIZE] {
        let mut secret = mem::MaybeUninit::<[u8; Secret::DEFAULT_SIZE]>::zeroed();

        let rounds = Secret::DEFAULT_SIZE / mem::size_of::<u128>();
        let src = SECRET.as_ptr().cast::<u64>();
        let dest = secret.as_mut_ptr().cast::<u64>();

        for i in 0..rounds {
            let lo = src.add(i * 2).read_le64().wrapping_add(seed);
            let hi = src.add(i * 2 + 1).read_le64().wrapping_sub(seed);
            dest.add(i * 2).write(lo);
            dest.add(i * 2 + 1).write(hi);
        }

        secret.assume_init()
    }
}

cfg_if! {
    if #[cfg(target_feature = "avx2")] {
        use avx2::{accumulate512, scramble_acc, init_custom_secret};
    } else if #[cfg(target_feature = "sse2")] {
        use sse2::{accumulate512, scramble_acc, init_custom_secret};
    } else {
        use generic::{accumulate512, scramble_acc, init_custom_secret};
    }
}

#[inline(always)]
fn merge_accs(acc: &[u64], secret: &[u8], start: u64) -> u64 {
    avalanche(
        start
            .wrapping_add(mix2accs(acc, secret))
            .wrapping_add(mix2accs(&acc[2..], &secret[16..]))
            .wrapping_add(mix2accs(&acc[4..], &secret[32..]))
            .wrapping_add(mix2accs(&acc[6..], &secret[48..])),
    )
}

#[inline(always)]
fn mix2accs(acc: &[u64], secret: &[u8]) -> u64 {
    mul128_fold64(
        acc[0] ^ secret.read_le64(),
        acc[1] ^ secret[8..].read_le64(),
    )
}

#[inline(always)]
fn mix16bytes(input: &[u8], secret: &[u8], seed: u64) -> u64 {
    let input_lo = input.read_le64();
    let input_hi = input[8..].read_le64();

    mul128_fold64(
        input_lo ^ secret.read_le64().wrapping_add(seed),
        input_hi ^ secret[8..].read_le64().wrapping_sub(seed),
    )
}

#[inline(always)]
fn mix32bytes(
    acc: (u64, u64),
    input_1: &[u8],
    input_2: &[u8],
    secret: &[u8],
    seed: u64,
) -> (u64, u64) {
    let (mut low64, mut high64) = acc;

    low64 = low64.wrapping_add(mix16bytes(input_1, secret, seed));
    low64 ^= input_2.read_le64().wrapping_add(input_2[8..].read_le64());
    high64 = high64.wrapping_add(mix16bytes(input_2, &secret[16..], seed));
    high64 ^= input_1.read_le64().wrapping_add(input_1[8..].read_le64());

    (low64, high64)
}

#[inline(always)]
fn mul128_fold64(ll1: u64, ll2: u64) -> u64 {
    let product = u128::from(ll1).wrapping_mul(u128::from(ll2));

    (product as u64) ^ ((product >> 64) as u64)
}

/// Calculates a 32-bit to 64-bit long multiply.
#[inline(always)]
fn mult32to64(lhs: u32, rhs: u32) -> u64 {
    u64::from(lhs).wrapping_mul(u64::from(rhs))
}

/// Calculates a 64->128-bit long multiply.
#[inline(always)]
fn mult64to128(lhs: u64, rhs: u64) -> (u64, u64) {
    let product = u128::from(lhs).wrapping_mul(u128::from(rhs));

    (product as u64, (product >> 64) as u64)
}

#[inline(always)]
fn xorshift64(v64: u64, shift: usize) -> u64 {
    v64 ^ (v64 >> shift)
}

#[inline(always)]
fn xxh64_avalanche(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(PRIME64_2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(PRIME64_3);
    hash ^= hash >> 32;
    hash
}

/// This is a fast avalanche stage,
/// suitable when input bits are already partially mixed
#[inline(always)]
fn avalanche(mut h64: u64) -> u64 {
    h64 ^= h64 >> 37;
    h64 = h64.wrapping_mul(0x165667919E3779F9);
    h64 ^ (h64 >> 32)
}

/// This is a stronger avalanche,
/// inspired by Pelle Evensen's rrmxmx
/// preferable when input has not been previously mixed
#[inline(always)]
fn rrmxmx(mut h64: u64, len: usize) -> u64 {
    h64 ^= h64.rotate_left(49) ^ h64.rotate_left(24);
    h64 = h64.wrapping_mul(0x9FB21C651E98DF25);
    h64 ^= (h64 >> 35) + len as u64;
    h64 = h64.wrapping_mul(0x9FB21C651E98DF25);
    h64 ^ (h64 >> 28)
}

/* ===   XXH3 streaming   === */

const INTERNAL_BUFFER_SIZE: usize = 256;
const INTERNAL_BUFFER_STRIPES: usize = INTERNAL_BUFFER_SIZE / STRIPE_LEN;

const_assert!(INTERNAL_BUFFER_SIZE >= MIDSIZE_MAX);
const_assert_eq!(INTERNAL_BUFFER_SIZE % STRIPE_LEN, 0);

#[repr(align(64))]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
#[derive(Clone)]
struct State {
    acc: Acc,
    buffer: [u8; INTERNAL_BUFFER_SIZE],
    buffered_size: usize,
    secret_limit: usize,
    nb_stripes_per_block: usize,
    secret: With,
    seed: u64,
    total_len: usize,
    nb_stripes_so_far: usize,
}

#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
#[derive(Clone)]
enum With {
    DefaultSecret,
    Custom(Secret),
    Ref(Vec<u8>),
}

impl Deref for With {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            With::DefaultSecret => &SECRET,
            With::Custom(secret) => &secret.0,
            With::Ref(secret) => secret,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new(0, With::DefaultSecret)
    }
}

impl State {
    fn new(seed: u64, secret: With) -> Self {
        let secret_limit = secret.len() - STRIPE_LEN;
        let nb_stripes_per_block = secret_limit / SECRET_CONSUME_RATE;

        State {
            acc: Acc::default(),
            buffer: [0; INTERNAL_BUFFER_SIZE],
            buffered_size: 0,
            secret,
            secret_limit,
            nb_stripes_per_block,
            seed,
            total_len: 0,
            nb_stripes_so_far: 0,
        }
    }

    fn with_seed(seed: u64) -> Self {
        Self::new(seed, With::Custom(Secret::with_seed(seed)))
    }

    fn with_secret<S: Into<Vec<u8>>>(secret: S) -> State {
        let secret = secret.into();

        debug_assert!(secret.len() >= Secret::SIZE_MIN);

        Self::new(0, With::Ref(secret))
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.buffered_size == 0
    }

    #[inline(always)]
    fn clear(&mut self) {
        self.buffered_size = 0
    }

    #[inline(always)]
    fn extend_from_slice(&mut self, data: &[u8]) {
        debug_assert!(self.buffered_size + data.len() <= self.buffer.len());

        let buf = &mut self.buffer[self.buffered_size..];
        let len = data.len();
        buf[..len].copy_from_slice(data);
        self.buffered_size += len;
    }

    #[inline(always)]
    fn update(&mut self, mut input: &[u8]) {
        if input.is_empty() {
            return;
        }

        self.total_len += input.len();

        let free_size = INTERNAL_BUFFER_SIZE - self.buffered_size;

        if input.len() <= free_size {
            // fill in tmp buffer
            self.extend_from_slice(input);
            return;
        }

        // total input is now > XXH3_INTERNALBUFFER_SIZE

        // Internal buffer is partially filled (always, except at beginning) Complete it, then consume it.
        if !self.is_empty() {
            let (load, rest) = input.split_at(free_size);
            self.extend_from_slice(load);
            input = rest;
            self.nb_stripes_so_far = consume_stripes(
                &mut self.acc,
                self.nb_stripes_so_far,
                self.nb_stripes_per_block,
                &self.buffer,
                INTERNAL_BUFFER_STRIPES,
                &self.secret,
                self.secret_limit,
            );
            self.clear();
        }

        // Consume input by a multiple of internal buffer size
        if input.len() > INTERNAL_BUFFER_SIZE {
            let mut chunks = input.chunks_exact(INTERNAL_BUFFER_SIZE);

            for chunk in &mut chunks {
                self.nb_stripes_so_far = consume_stripes(
                    &mut self.acc,
                    self.nb_stripes_so_far,
                    self.nb_stripes_per_block,
                    chunk,
                    INTERNAL_BUFFER_STRIPES,
                    &self.secret,
                    self.secret_limit,
                );
            }

            input = chunks.remainder();

            // for last partial stripe
            unsafe {
                ptr::copy_nonoverlapping(
                    input.as_ptr().add(INTERNAL_BUFFER_SIZE).sub(STRIPE_LEN),
                    self.buffer.as_mut_ptr().add(self.buffer.len() - STRIPE_LEN),
                    STRIPE_LEN,
                );
            }
        }

        // Some remaining input (always) : buffer it
        self.extend_from_slice(input)
    }

    #[inline(always)]
    fn digest_long(&self) -> Acc {
        // Digest on a local copy.
        // This way, the state remains unaltered, and it can continue ingesting more input afterwards.
        let mut acc = self.acc.clone();

        if self.buffered_size >= STRIPE_LEN {
            let nb_stripes = (self.buffered_size - 1) / STRIPE_LEN;
            let _nb_stripes_so_far = consume_stripes(
                &mut acc,
                self.nb_stripes_so_far,
                self.nb_stripes_per_block,
                &self.buffer,
                nb_stripes,
                &self.secret,
                self.secret_limit,
            );

            // last stripe
            unsafe {
                accumulate512(
                    &mut acc,
                    &self.buffer[self.buffer.len() - STRIPE_LEN..],
                    &self.secret[self.secret_limit - SECRET_LASTACC_START..],
                );
            }
        } else {
            // one last stripe
            let mut last_stripe = [0u8; STRIPE_LEN];
            let catchup_size = STRIPE_LEN - self.buffered_size;

            unsafe {
                ptr::copy_nonoverlapping(
                    self.buffer
                        .as_ptr()
                        .add(self.buffer.len())
                        .sub(catchup_size),
                    last_stripe.as_mut_ptr(),
                    catchup_size,
                );
                ptr::copy_nonoverlapping(
                    self.buffer.as_ptr(),
                    last_stripe.as_mut_ptr().add(catchup_size),
                    self.buffered_size,
                );

                accumulate512(
                    &mut acc,
                    &last_stripe,
                    &self.secret[self.secret_limit - SECRET_LASTACC_START..],
                );
            }
        }

        acc
    }

    #[inline(always)]
    fn digest64(&self) -> u64 {
        if self.total_len > MIDSIZE_MAX {
            let acc = self.digest_long();

            merge_accs(
                &acc,
                &self.secret[SECRET_MERGEACCS_START..],
                (self.total_len as u64).wrapping_mul(PRIME64_1),
            )
        } else if self.seed != 0 {
            hash64_with_seed(&self.buffer[..self.total_len], self.seed)
        } else {
            hash64_with_secret(
                &self.buffer[..self.total_len],
                &self.secret[..self.secret_limit + STRIPE_LEN],
            )
        }
    }

    #[inline(always)]
    fn digest128(&self) -> u128 {
        if self.total_len > MIDSIZE_MAX {
            let acc = self.digest_long();

            debug_assert!(self.secret_limit + STRIPE_LEN >= Acc::SIZE + SECRET_MERGEACCS_START);

            let low64 = merge_accs(
                &acc,
                &self.secret[SECRET_MERGEACCS_START..],
                (self.total_len as u64).wrapping_mul(PRIME64_1),
            );
            let high64 = merge_accs(
                &acc,
                &self.secret[self.secret_limit + STRIPE_LEN - Acc::SIZE - SECRET_MERGEACCS_START..],
                !(self.total_len as u64).wrapping_mul(PRIME64_2),
            );

            u128::from(low64) + (u128::from(high64) << 64)
        } else if self.seed != 0 {
            hash128_with_seed(&self.buffer[..self.total_len], self.seed)
        } else {
            hash128_with_secret(
                &self.buffer[..self.total_len],
                &self.secret[..self.secret_limit + STRIPE_LEN],
            )
        }
    }
}

#[inline(always)]
fn consume_stripes(
    acc: &mut [u64],
    nb_stripes_so_far: usize,
    nb_stripes_per_block: usize,
    input: &[u8],
    nb_stripes: usize,
    secret: &[u8],
    secret_limit: usize,
) -> usize {
    debug_assert!(nb_stripes <= nb_stripes_per_block);
    debug_assert!(nb_stripes_so_far < nb_stripes_per_block);

    if nb_stripes_per_block - nb_stripes_so_far <= nb_stripes {
        // need a scrambling operation
        let nb_stripes_to_end_of_block = nb_stripes_per_block - nb_stripes_so_far;
        let nb_stripes_after_block = nb_stripes - nb_stripes_to_end_of_block;

        accumulate(
            acc,
            input,
            &secret[nb_stripes_so_far * SECRET_CONSUME_RATE..],
            nb_stripes_to_end_of_block,
        );
        unsafe {
            scramble_acc(acc, &secret[secret_limit..]);
        }
        accumulate(
            acc,
            &input[nb_stripes_to_end_of_block * STRIPE_LEN..],
            secret,
            nb_stripes_after_block,
        );

        nb_stripes_after_block
    } else {
        accumulate(
            acc,
            input,
            &secret[nb_stripes_so_far * SECRET_CONSUME_RATE..],
            nb_stripes,
        );

        nb_stripes_so_far + nb_stripes
    }
}

/* ==========================================
 * XXH3 128 bits (=> XXH128)
 * ========================================== */

#[inline(always)]
fn hash_len_0to16_128bits(data: &[u8], len: usize, secret: &[u8], seed: u64) -> u128 {
    debug_assert!(len <= 16);

    if len > 8 {
        hash_len_9to16_128bits(data, len, secret, seed)
    } else if len >= 4 {
        hash_len_4to8_128bits(data, len, secret, seed)
    } else if len > 0 {
        hash_len_1to3_128bits(data, len, secret, seed)
    } else {
        let bitflipl = secret[64..].read_le64() ^ secret[72..].read_le64();
        let bitfliph = secret[80..].read_le64() ^ secret[88..].read_le64();

        let low64 = xxh64_avalanche(seed ^ bitflipl);
        let high64 = xxh64_avalanche(seed ^ bitfliph);

        u128::from(low64) + (u128::from(high64) << 64)
    }
}

#[inline(always)]
fn hash_len_1to3_128bits(input: &[u8], len: usize, secret: &[u8], seed: u64) -> u128 {
    debug_assert!((1..=3).contains(&len));

    // len = 1: combinedl = { input[0], 0x01, input[0], input[0] }
    // len = 2: combinedl = { input[1], 0x02, input[0], input[1] }
    // len = 3: combinedl = { input[2], 0x03, input[0], input[1] }

    let c1 = u32::from(input[0]);
    let c2 = u32::from(input[len >> 1]);
    let c3 = u32::from(input[len - 1]);
    let combinedl = (c1 << 16) | (c2 << 24) | c3 | ((len as u32) << 8);
    let combinedh = combinedl.swap_bytes().rotate_left(13);
    let bitflipl = u64::from(secret.read_le32() ^ secret[4..].read_le32()).wrapping_add(seed);
    let bitfliph = u64::from(secret[8..].read_le32() ^ secret[12..].read_le32()).wrapping_sub(seed);
    let keyed_lo = u64::from(combinedl) ^ bitflipl;
    let keyed_hi = u64::from(combinedh) ^ bitfliph;
    let low64 = xxh64_avalanche(keyed_lo);
    let high64 = xxh64_avalanche(keyed_hi);
    u128::from(low64) + (u128::from(high64) << 64)
}

#[inline(always)]
fn hash_len_4to8_128bits(input: &[u8], len: usize, secret: &[u8], mut seed: u64) -> u128 {
    debug_assert!((4..=8).contains(&len));

    seed ^= u64::from((seed as u32).swap_bytes()) << 32;

    let input_lo = input.read_le32();
    let input_hi = input[input.len() - 4..].read_le32();
    let input_64 = u64::from(input_lo) + (u64::from(input_hi) << 32);
    let bitflip = (secret[16..].read_le64() ^ secret[24..].read_le64()).wrapping_add(seed);
    let keyed = input_64 ^ bitflip;

    // Shift len to the left to ensure it is even, this avoids even multiplies.
    let (mut low64, mut high64) = mult64to128(keyed, PRIME64_1.wrapping_add((len << 2) as u64));
    high64 = high64.wrapping_add(low64 << 1);
    low64 ^= high64 >> 3;

    low64 = xorshift64(low64, 35);
    low64 = low64.wrapping_mul(0x9FB21C651E98DF25);
    low64 = xorshift64(low64, 28);
    high64 = avalanche(high64);

    u128::from(low64) + (u128::from(high64) << 64)
}

#[inline(always)]
fn hash_len_9to16_128bits(input: &[u8], len: usize, secret: &[u8], seed: u64) -> u128 {
    debug_assert!((9..=16).contains(&len));
    let bitflipl = (secret[32..].read_le64() ^ secret[40..].read_le64()).wrapping_sub(seed);
    let bitfliph = (secret[48..].read_le64() ^ secret[56..].read_le64()).wrapping_add(seed);
    let input_lo = input.read_le64();
    let mut input_hi = input[len - 8..].read_le64();
    let (mut low64, mut high64) = mult64to128(input_lo ^ input_hi ^ bitflipl, PRIME64_1);

    /*
     * Put len in the middle of m128 to ensure that the length gets mixed to
     * both the low and high bits in the 128x64 multiply below.
     */
    low64 = low64.wrapping_add(((len - 1) << 54) as u64);
    input_hi ^= bitfliph;

    /*
     * Add the high 32 bits of input_hi to the high 32 bits of m128, then
     * add the long product of the low 32 bits of input_hi and XXH_PRIME32_2 to
     * the high 64 bits of m128.
     *
     * The best approach to this operation is different on 32-bit and 64-bit.
     */
    if cfg!(target_pointer_width = "32") {
        /*
         * 32-bit optimized version, which is more readable.
         *
         * On 32-bit, it removes an ADC and delays a dependency between the two
         * halves of m128.high64, but it generates an extra mask on 64-bit.
         */
        high64 = high64
            .wrapping_add(input_hi % 0xFFFFFFFF00000000)
            .wrapping_add(mult32to64(input_hi as u32, PRIME32_2));
    } else {
        /*
         * 64-bit optimized (albeit more confusing) version.
         *
         * Uses some properties of addition and multiplication to remove the mask:
         *
         * Let:
         *    a = input_hi.lo = (input_hi & 0x00000000FFFFFFFF)
         *    b = input_hi.hi = (input_hi & 0xFFFFFFFF00000000)
         *    c = XXH_PRIME32_2
         *
         *    a + (b * c)
         * Inverse Property: x + y - x == y
         *    a + (b * (1 + c - 1))
         * Distributive Property: x * (y + z) == (x * y) + (x * z)
         *    a + (b * 1) + (b * (c - 1))
         * Identity Property: x * 1 == x
         *    a + b + (b * (c - 1))
         *
         * Substitute a, b, and c:
         *    input_hi.hi + input_hi.lo + ((xxh_u64)input_hi.lo * (XXH_PRIME32_2 - 1))
         *
         * Since input_hi.hi + input_hi.lo == input_hi, we get this:
         *    input_hi + ((xxh_u64)input_hi.lo * (XXH_PRIME32_2 - 1))
         */
        high64 = high64
            .wrapping_add(input_hi)
            .wrapping_add(mult32to64(input_hi as u32, PRIME32_2 - 1));
    }

    // m128 ^= XXH_swap64(m128 >> 64);
    low64 ^= high64.swap_bytes();

    // 128x64 multiply: h128 = m128 * XXH_PRIME64_2;
    let (lo64, hi64) = mult64to128(low64, PRIME64_2);
    let hi64 = hi64.wrapping_add(high64.wrapping_mul(PRIME64_2));

    u128::from(avalanche(lo64)) + (u128::from(avalanche(hi64)) << 64)
}

#[inline(always)]
fn hash_len_17to128_128bits(input: &[u8], len: usize, secret: &[u8], seed: u64) -> u128 {
    debug_assert!((17..=128).contains(&len));
    debug_assert!(secret.len() >= Secret::SIZE_MIN);

    let mut acc = (PRIME64_1.wrapping_mul(len as u64), 0);

    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc = mix32bytes(acc, &input[48..], &input[len - 64..], &secret[96..], seed);
            }
            acc = mix32bytes(acc, &input[32..], &input[len - 48..], &secret[64..], seed);
        }
        acc = mix32bytes(acc, &input[16..], &input[len - 32..], &secret[32..], seed);
    }
    let (low64, high64) = mix32bytes(acc, input, &input[len - 16..], secret, seed);

    let lo64 = low64.wrapping_add(high64);
    let hi64 = low64
        .wrapping_mul(PRIME64_1)
        .wrapping_add(high64.wrapping_mul(PRIME64_4))
        .wrapping_add((len as u64).wrapping_sub(seed).wrapping_mul(PRIME64_2));

    u128::from(avalanche(lo64)) + (u128::from(0u64.wrapping_sub(avalanche(hi64))) << 64)
}

#[inline(always)]
fn hash_len_129to240_128bits(input: &[u8], len: usize, secret: &[u8], seed: u64) -> u128 {
    debug_assert!((129..=MIDSIZE_MAX).contains(&len));
    debug_assert!(secret.len() >= Secret::SIZE_MIN);

    let acc = (PRIME64_1.wrapping_mul(len as u64), 0);

    let (low64, high64) = (0..4).fold(acc, |acc, i| {
        let off = 32 * i;
        mix32bytes(acc, &input[off..], &input[off + 16..], &secret[off..], seed)
    });

    let acc = (avalanche(low64), avalanche(high64));

    let rounds = len / 32;
    debug_assert!(rounds >= 4);

    let acc = (4..rounds).fold(acc, |acc, i| {
        let off = 32 * i;
        mix32bytes(
            acc,
            &input[off..],
            &input[off + 16..],
            &secret[MIDSIZE_START_OFFSET + 32 * (i - 4)..],
            seed,
        )
    });

    // last bytes
    let (low64, high64) = mix32bytes(
        acc,
        &input[len - 16..],
        &input[len - 32..],
        &secret[Secret::SIZE_MIN - MIDSIZE_LAST_OFFSET - 16..],
        0u64.wrapping_sub(seed),
    );

    let lo64 = low64.wrapping_add(high64);
    let hi64 = low64
        .wrapping_mul(PRIME64_1)
        .wrapping_add(high64.wrapping_mul(PRIME64_4))
        .wrapping_add((len as u64).wrapping_sub(seed).wrapping_mul(PRIME64_2));

    u128::from(avalanche(lo64)) + (u128::from(0u64.wrapping_sub(avalanche(hi64))) << 64)
}

#[inline(always)]
fn hash_long_128bits_internal(data: &[u8], secret: &[u8]) -> u128 {
    let mut acc = Acc::default();
    let len = data.len();

    hash_long_internal_loop(&mut acc, data, len, secret);

    debug_assert!(secret.len() >= Acc::SIZE + SECRET_MERGEACCS_START);

    let low64 = merge_accs(
        &acc,
        &secret[SECRET_MERGEACCS_START..],
        (len as u64).wrapping_mul(PRIME64_1),
    );
    let high64 = merge_accs(
        &acc,
        &secret[secret.len() - Acc::SIZE - SECRET_MERGEACCS_START..],
        !(len as u64).wrapping_mul(PRIME64_2),
    );

    u128::from(low64) + (u128::from(high64) << 64)
}

/* ===   XXH3 128-bit streaming   === */

/* all the functions are actually the same as for 64-bit streaming variant,
just the reset one is different (different initial acc values for 0,5,6,7),
and near the end of the digest function */

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::cmp;

    use super::*;

    const PRIME32: u64 = 2654435761;
    const PRIME64: u64 = 11400714785074694797;
    const SANITY_BUFFER_SIZE: usize = 2367;

    fn sanity_buffer() -> [u8; SANITY_BUFFER_SIZE] {
        let mut buf = [0; SANITY_BUFFER_SIZE];
        let mut byte_gen: u64 = PRIME32;

        for b in buf.iter_mut() {
            *b = (byte_gen >> 56) as u8;
            byte_gen = byte_gen.wrapping_mul(PRIME64);
        }

        buf
    }

    #[test]
    fn hash_64bits_sanity_check() {
        let buf = sanity_buffer();

        let test_cases = vec![
            (&[][..], 0, 0x2D06800538D394C2), /* zero-length hash is always 0 */
            (&[][..], PRIME64, 0xA8A6B918B2F0364A),
            (&buf[..1], 0, 0xC44BDFF4074EECDB),       /*  1 -  3 */
            (&buf[..1], PRIME64, 0x032BE332DD766EF8), /*  1 -  3 */
            (&buf[..6], 0, 0x27B56A84CD2D7325),       /*  4 -  8 */
            (&buf[..6], PRIME64, 0x84589C116AB59AB9), /*  4 -  8 */
            (&buf[..12], 0, 0xA713DAF0DFBB77E7),      /*  9 - 16 */
            (&buf[..12], PRIME64, 0xE7303E1B2336DE0E), /*  9 - 16 */
            (&buf[..24], 0, 0xA3FE70BF9D3510EB),      /* 17 - 32 */
            (&buf[..24], PRIME64, 0x850E80FC35BDD690), /* 17 - 32 */
            (&buf[..48], 0, 0x397DA259ECBA1F11),      /* 33 - 64 */
            (&buf[..48], PRIME64, 0xADC2CBAA44ACC616), /* 33 - 64 */
            (&buf[..80], 0, 0xBCDEFBBB2C47C90A),      /* 65 - 96 */
            (&buf[..80], PRIME64, 0xC6DD0CB699532E73), /* 65 - 96 */
            (&buf[..195], 0, 0xCD94217EE362EC3A),     /* 129-240 */
            (&buf[..195], PRIME64, 0xBA68003D370CB3D9), /* 129-240 */
            (&buf[..403], 0, 0xCDEB804D65C6DEA4),     /* one block, last stripe is overlapping */
            (&buf[..403], PRIME64, 0x6259F6ECFD6443FD), /* one block, last stripe is overlapping */
            (&buf[..512], 0, 0x617E49599013CB6B),     /* one block, finishing at stripe boundary */
            (&buf[..512], PRIME64, 0x3CE457DE14C27708), /* one block, finishing at stripe boundary */
            (&buf[..2048], 0, 0xDD59E2C3A5F038E0), /* 2 nb_blocks, finishing at block boundary */
            (&buf[..2048], PRIME64, 0x66F81670669ABABC), /* 2 nb_blocks, finishing at block boundary */
            (&buf[..2240], 0, 0x6E73A90539CF2948), /* 3 nb_blocks, finishing at stripe boundary */
            (&buf[..2240], PRIME64, 0x757BA8487D1B5247), /* 3 nb_blocks, finishing at stripe boundary */
            (&buf[..2367], 0, 0xCB37AEB9E5D361ED), /* 3 nb_blocks, last stripe is overlapping */
            (&buf[..2367], PRIME64, 0xD2DB3415B942B42A), /* 3 nb_blocks, last stripe is overlapping */
        ];

        for (buf, seed, result) in test_cases {
            {
                let hash = hash64_with_seed(buf, seed);

                assert_eq!(
                    hash,
                    result,
                    "hash64_with_seed(&buf[..{}], seed={}) failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    seed,
                    hash,
                    result,
                    buf
                );
            }

            // streaming API test

            // single ingestio
            {
                let mut hasher = Hash64::with_seed(seed);
                hasher.write(buf);
                let hash = hasher.finish();

                assert_eq!(
                    hash,
                    result,
                    "Hash64::update(&buf[..{}]) with seed={} failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    seed,
                    hash,
                    result,
                    buf
                );
            }

            if buf.len() > 3 {
                // 2 ingestions
                let mut hasher = Hash64::with_seed(seed);
                hasher.write(&buf[..3]);
                hasher.write(&buf[3..]);
                let hash = hasher.finish();

                assert_eq!(
                    hash,
                    result,
                    "Hash64::update(&buf[..3], &buf[3..{}]) with seed={} failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    seed,
                    hash,
                    result,
                    buf
                );
            }

            // byte by byte ingestion
            {
                let mut hasher = Hash64::with_seed(seed);

                for chunk in buf.chunks(1) {
                    hasher.write(chunk);
                }

                let hash = hasher.finish();

                assert_eq!(
                    hash,
                    result,
                    "Hash64::update(&buf[..{}].chunks(1)) with seed={} failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    seed,
                    hash,
                    result,
                    buf
                );
            }
        }
    }

    #[test]
    fn hash_64bits_with_secret_sanity_check() {
        let buf = sanity_buffer();
        let secret = &buf[7..7 + Secret::SIZE_MIN + 11];

        let test_cases = vec![
            (&[][..], secret, 0x3559D64878C5C66C), /* zero-length hash is always 0 */
            (&buf[..1], secret, 0x8A52451418B2DA4D), /*  1 -  3 */
            (&buf[..6], secret, 0x82C90AB0519369AD), /*  6 -  8 */
            (&buf[..12], secret, 0x14631E773B78EC57), /*  9 - 16 */
            (&buf[..24], secret, 0xCDD5542E4A9D9FE8), /* 17 - 32 */
            (&buf[..48], secret, 0x33ABD54D094B2534), /* 33 - 64 */
            (&buf[..80], secret, 0xE687BA1684965297), /* 65 - 96 */
            (&buf[..195], secret, 0xA057273F5EECFB20), /* 129-240 */
            (&buf[..403], secret, 0x14546019124D43B8), /* one block, last stripe is overlapping */
            (&buf[..512], secret, 0x7564693DD526E28D), /* one block, finishing at stripe boundary */
            (&buf[..2048], secret, 0xD32E975821D6519F), /* > one block, at least one scrambling */
            (&buf[..2367], secret, 0x293FA8E5173BB5E7), /* > one block, at least one scrambling, last stripe unaligned */
        ];

        for (buf, secret, result) in test_cases {
            {
                let hash = hash64_with_secret(buf, secret);

                assert_eq!(
                    hash,
                    result,
                    "hash64_with_secret(&buf[..{}], secret) failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    hash,
                    result,
                    buf
                );
            }

            // streaming API test

            // single ingestio
            {
                let mut hasher = Hash64::with_secret(secret);
                hasher.write(buf);
                let hash = hasher.finish();

                assert_eq!(
                    hash,
                    result,
                    "Hash64::update(&buf[..{}]) with secret failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    hash,
                    result,
                    buf
                );
            }

            // byte by byte ingestion
            {
                let mut hasher = Hash64::with_secret(secret);

                for chunk in buf.chunks(1) {
                    hasher.write(chunk);
                }

                let hash = hasher.finish();

                assert_eq!(
                    hash,
                    result,
                    "Hash64::update(&buf[..{}].chunks(1)) with secret failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    hash,
                    result,
                    buf
                );
            }
        }
    }

    #[test]
    fn hash_128bits_sanity_check() {
        let buf = sanity_buffer();

        let test_cases = vec![
            (&[][..], 0, 0x6001C324468D497Fu64, 0x99AA06D3014798D8u64), /* zero-length hash is { seed, -seed } by default */
            (&[][..], PRIME32, 0x5444F7869C671AB0, 0x92220AE55E14AB50),
            (&buf[..1], 0, 0xC44BDFF4074EECDB, 0xA6CD5E9392000F6A), /* 1-3 */
            (&buf[..1], PRIME32, 0xB53D5557E7F76F8D, 0x89B99554BA22467C), /* 1-3 */
            (&buf[..6], 0, 0x3E7039BDDA43CFC6, 0x082AFE0B8162D12A), /* 4-8 */
            (&buf[..6], PRIME32, 0x269D8F70BE98856E, 0x5A865B5389ABD2B1), /* 4-8 */
            (&buf[..12], 0, 0x061A192713F69AD9, 0x6E3EFD8FC7802B18), /* 9-16 */
            (&buf[..12], PRIME32, 0x9BE9F9A67F3C7DFB, 0xD7E09D518A3405D3), /* 9-16 */
            (&buf[..24], 0, 0x1E7044D28B1B901D, 0x0CE966E4678D3761), /* 17-32 */
            (&buf[..24], PRIME32, 0xD7304C54EBAD40A9, 0x3162026714A6A243), /* 17-32 */
            (&buf[..48], 0, 0xF942219AED80F67B, 0xA002AC4E5478227E), /* 33-64 */
            (&buf[..48], PRIME32, 0x7BA3C3E453A1934E, 0x163ADDE36C072295), /* 33-64 */
            (&buf[..81], 0, 0x5E8BAFB9F95FB803, 0x4952F58181AB0042), /* 65-96 */
            (&buf[..81], PRIME32, 0x703FBB3D7A5F755C, 0x2724EC7ADC750FB6), /* 65-96 */
            (&buf[..222], 0, 0xF1AEBD597CEC6B3A, 0x337E09641B948717), /* 129-240 */
            (&buf[..222], PRIME32, 0xAE995BB8AF917A8D, 0x91820016621E97F1), /* 129-240 */
            (&buf[..403], 0, 0xCDEB804D65C6DEA4, 0x1B6DE21E332DD73D), /* one block, last stripe is overlapping */
            (&buf[..403], PRIME64, 0x6259F6ECFD6443FD, 0xBED311971E0BE8F2), /* one block, last stripe is overlapping */
            (&buf[..512], 0, 0x617E49599013CB6B, 0x18D2D110DCC9BCA1), /* one block, finishing at stripe boundary */
            (&buf[..512], PRIME64, 0x3CE457DE14C27708, 0x925D06B8EC5B8040), /* one block, finishing at stripe boundary */
            (&buf[..2048], 0, 0xDD59E2C3A5F038E0, 0xF736557FD47073A5), /* two nb_blocks, finishing at block boundary */
            (
                &buf[..2048],
                PRIME32,
                0x230D43F30206260B,
                0x7FB03F7E7186C3EA,
            ), /* two nb_blocks, finishing at block boundary */
            (&buf[..2240], 0, 0x6E73A90539CF2948, 0xCCB134FBFA7CE49D), /* two nb_blocks, ends at stripe boundary */
            (
                &buf[..2240],
                PRIME32,
                0xED385111126FBA6F,
                0x50A1FE17B338995F,
            ), /* two nb_blocks, ends at stripe boundary */
            (&buf[..2367], 0, 0xCB37AEB9E5D361ED, 0xE89C0F6FF369B427), /* two nb_blocks, ends at stripe boundary */
            (
                &buf[..2367],
                PRIME32,
                0x6F5360AE69C2F406,
                0xD23AAE4B76C31ECB,
            ), /* two nb_blocks, ends at stripe boundary */
        ];

        for (buf, seed, lo, hi) in test_cases {
            let result = u128::from(lo) + (u128::from(hi) << 64);

            {
                let hash = hash128_with_seed(buf, seed);

                assert_eq!(
                    hash,
                    result,
                    "hash128_with_seed(&buf[..{}], seed={}) failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    seed,
                    hash,
                    result,
                    buf
                );
            }

            // check that the no-seed variant produces same result as seed==0
            if seed == 0 {
                let hash = hash128(buf);

                assert_eq!(
                    hash,
                    result,
                    "hash128(&buf[..{}]) failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    hash,
                    result,
                    buf
                );
            }

            // streaming API test

            // single ingestio
            {
                let mut hasher = Hash128::with_seed(seed);
                hasher.write(buf);
                let hash = hasher.finish_ext();

                assert_eq!(
                    hash,
                    result,
                    "Hash128::update(&buf[..{}]) with seed={} failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    seed,
                    hash,
                    result,
                    buf
                );
            }

            // random ingestion
            {
                let mut hasher = Hash128::with_seed(seed);
                let len = buf.len();
                let modulo = cmp::max(len, 2);
                let mut n = 0;
                while n < len {
                    let l = (rand::random::<usize>() % modulo).min(len - n);
                    hasher.write(&buf[n..n + l]);
                    n += l;
                }
                let hash = hasher.finish_ext();

                assert_eq!(
                    hash,
                    result,
                    "Hash128::update(&buf[..{}]) with seed={} failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    seed,
                    hash,
                    result,
                    buf
                );
            }

            if buf.len() > 3 {
                // 2 ingestions
                let mut hasher = Hash128::with_seed(seed);
                hasher.write(&buf[..3]);
                hasher.write(&buf[3..]);
                let hash = hasher.finish_ext();

                assert_eq!(
                    hash,
                    result,
                    "Hash128::update(&buf[..3], &buf[3..{}]) with seed={} failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    seed,
                    hash,
                    result,
                    buf
                );
            }

            // byte by byte ingestion
            {
                let mut hasher = Hash128::with_seed(seed);

                for chunk in buf.chunks(1) {
                    hasher.write(chunk);
                }

                let hash = hasher.finish_ext();

                assert_eq!(
                    hash,
                    result,
                    "Hash128::update(&buf[..{}].chunks(1)) with seed={} failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    seed,
                    hash,
                    result,
                    buf
                );
            }
        }
    }

    #[test]
    fn hash_128bits_with_secret_sanity_check() {
        let buf = sanity_buffer();
        let secret = &buf[7..7 + Secret::SIZE_MIN + 11];

        let test_cases = vec![
            (
                &[][..],
                secret,
                0x005923CCEECBE8AEu64,
                0x5F70F4EA232F1D38u64,
            ), /* zero-length hash is always 0 */
            (&buf[..1], secret, 0x8A52451418B2DA4D, 0x3A66AF5A9819198E), /*  1 -  3 */
            (&buf[..6], secret, 0x0B61C8ACA7D4778F, 0x376BD91B6432F36D), /*  6 -  8 */
            (&buf[..12], secret, 0xAF82F6EBA263D7D8, 0x90A3C2D839F57D0F), /*  9 - 16 */
        ];

        for (buf, secret, lo, hi) in test_cases {
            let result = u128::from(lo) + (u128::from(hi) << 64);

            {
                let hash = hash128_with_secret(buf, secret);

                assert_eq!(
                    hash,
                    result,
                    "hash128_with_secret(&buf[..{}], secret) failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    hash,
                    result,
                    buf
                );
            }

            // streaming API test

            // single ingestio
            {
                let mut hasher = Hash128::with_secret(secret);
                hasher.write(buf);
                let hash = hasher.finish_ext();

                assert_eq!(
                    hash,
                    result,
                    "Hash128::update(&buf[..{}]) with secret failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    hash,
                    result,
                    buf
                );
            }

            // byte by byte ingestion
            {
                let mut hasher = Hash128::with_secret(secret);

                for chunk in buf.chunks(1) {
                    hasher.write(chunk);
                }

                let hash = hasher.finish_ext();

                assert_eq!(
                    hash,
                    result,
                    "Hash128::update(&buf[..{}].chunks(1)) with secret failed, got 0x{:X}, expected 0x{:X}, buf: {:?}",
                    buf.len(),
                    hash,
                    result,
                    buf
                );
            }
        }
    }
}
