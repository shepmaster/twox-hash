use core::convert::TryInto;
use core::mem;
use core::ops::{Deref, DerefMut};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use cfg_if::cfg_if;

use crate::sixty_four::{
    PRIME_1 as PRIME64_1, PRIME_2 as PRIME64_2, PRIME_3 as PRIME64_3, PRIME_4 as PRIME64_4,
    PRIME_5 as PRIME64_5,
};
use crate::thirty_two::{PRIME_1 as PRIME32_1, PRIME_2 as PRIME32_2, PRIME_3 as PRIME32_3};

pub fn hash64(data: &[u8]) -> u64 {
    hash64_with_seed(data, 0)
}

pub fn hash64_with_seed(data: &[u8], seed: u64) -> u64 {
    let len = data.len();

    if len <= 16 {
        hash_len_0to16_64bits(data, &SECRET, seed)
    } else if len <= 128 {
        hash_len_17to128_64bits(data, &SECRET, seed)
    } else if len <= MIDSIZE_MAX {
        hash_len_129to240_64bits(data, &SECRET, seed)
    } else {
        hash_long_64bits_with_seed(data, seed)
    }
}

pub fn hash64_with_secret(data: &[u8], secret: &[u8]) -> u64 {
    debug_assert!(secret.len() >= SECRET_SIZE_MIN);

    let len = data.len();

    if len <= 16 {
        hash_len_0to16_64bits(data, secret, 0)
    } else if len <= 128 {
        hash_len_17to128_64bits(data, secret, 0)
    } else if len <= MIDSIZE_MAX {
        hash_len_129to240_64bits(data, secret, 0)
    } else {
        hash_long_64bits_with_secret(data, secret)
    }
}

/* ==========================================
 * XXH3 default settings
 * ========================================== */

const SECRET_DEFAULT_SIZE: usize = 192;
const SECRET_SIZE_MIN: usize = 136;

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
struct Secret([u8; SECRET_DEFAULT_SIZE]);

impl Default for Secret {
    fn default() -> Self {
        SECRET
    }
}

impl Deref for Secret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl Secret {
    pub fn with_seed(seed64: u64) -> Self {
        let mut secret = [0; SECRET_DEFAULT_SIZE];

        for off in (0..SECRET_DEFAULT_SIZE).step_by(16) {
            secret[off..].write_u64_le(SECRET[off..].read_u64_le().wrapping_add(seed64));
            secret[off + 8..].write_u64_le(SECRET[off + 8..].read_u64_le().wrapping_sub(seed64));
        }

        Secret(secret)
    }
}

cfg_if! {
    if #[cfg(any(target_feature = "avx2", feature = "avx2"))] {
        #[repr(align(32))]
        struct Acc([u64; ACC_NB]);
    } else if #[cfg(any(target_feature = "sse2", feature = "sse2"))] {
        #[repr(align(16))]
        struct Acc([u64; ACC_NB]);
    } else {
        #[repr(align(8))]
        struct Acc([u64; ACC_NB]);
    }
}

impl Default for Acc {
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

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Acc {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

trait Buf {
    fn read_u32_le(&self) -> u32;

    fn read_u64_le(&self) -> u64;
}

trait BufMut {
    fn write_u32_le(&mut self, n: u32);

    fn write_u64_le(&mut self, n: u64);
}

impl Buf for [u8] {
    fn read_u32_le(&self) -> u32 {
        let buf = &self[..mem::size_of::<u32>()];
        u32::from_le_bytes(buf.try_into().unwrap())
    }

    fn read_u64_le(&self) -> u64 {
        let buf = &self[..mem::size_of::<u64>()];
        u64::from_le_bytes(buf.try_into().unwrap())
    }
}

impl BufMut for [u8] {
    fn write_u32_le(&mut self, n: u32) {
        self[..mem::size_of::<u32>()].copy_from_slice(&n.to_le_bytes()[..]);
    }

    fn write_u64_le(&mut self, n: u64) {
        self[..mem::size_of::<u64>()].copy_from_slice(&n.to_le_bytes()[..]);
    }
}

/* ==========================================
 * Short keys
 * ========================================== */

#[inline(always)]
fn hash_len_0to16_64bits(data: &[u8], key: &[u8], seed: u64) -> u64 {
    let len = data.len();

    debug_assert!(len <= 16);

    if len > 8 {
        hash_len_9to16_64bits(data, key, seed)
    } else if len >= 4 {
        hash_len_4to8_64bits(data, key, seed)
    } else if len > 0 {
        hash_len_1to3_64bits(data, key, seed)
    } else {
        0
    }
}

#[inline(always)]
fn hash_len_9to16_64bits(data: &[u8], key: &[u8], seed64: u64) -> u64 {
    let len = data.len();

    debug_assert!((9..=16).contains(&len));

    let ll1 = data.read_u64_le() ^ key.read_u64_le().wrapping_add(seed64);
    let ll2 = data[len - 8..].read_u64_le() ^ key[8..].read_u64_le().wrapping_sub(seed64);
    let acc = (len as u64)
        .wrapping_add(ll1)
        .wrapping_add(ll2)
        .wrapping_add(mul128_fold64(ll1, ll2));

    avalanche(acc)
}

#[inline(always)]
fn hash_len_4to8_64bits(data: &[u8], key: &[u8], seed: u64) -> u64 {
    let len = data.len();

    debug_assert!((4..=8).contains(&len));

    let in1 = u64::from(data.read_u32_le());
    let in2 = u64::from(data[len - 4..].read_u32_le());
    let in64 = in1.wrapping_add(in2 << 32);
    let keyed = in64 ^ key.read_u64_le().wrapping_add(seed);
    let mix64 =
        (len as u64).wrapping_add((keyed ^ (keyed >> 51)).wrapping_mul(u64::from(PRIME32_1)));

    avalanche((mix64 ^ (mix64 >> 47)).wrapping_mul(PRIME64_2))
}

#[inline(always)]
fn hash_len_1to3_64bits(data: &[u8], key: &[u8], seed: u64) -> u64 {
    let len = data.len();

    debug_assert!((1..=3).contains(&len));

    let c1 = u32::from(data[0]);
    let c2 = u32::from(data[len >> 1]);
    let c3 = u32::from(data[len - 1]);
    let combined = c1 + (c2 << 8) + (c3 << 16) + ((len as u32) << 24);
    let keyed = u64::from(combined) ^ u64::from(key.read_u32_le()).wrapping_add(seed);
    let mixed = keyed.wrapping_mul(PRIME64_1);
    avalanche(mixed)
}

fn hash_len_17to128_64bits(data: &[u8], key: &[u8], seed: u64) -> u64 {
    let len = data.len();

    debug_assert!((17..=128).contains(&len));

    let mut acc = PRIME64_1.wrapping_mul(len as u64);

    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc = acc
                    .wrapping_add(mix_16bytes(&data[48..], &key[96..], seed))
                    .wrapping_add(mix_16bytes(&data[len - 64..], &key[112..], seed));
            }
            acc = acc
                .wrapping_add(mix_16bytes(&data[32..], &key[64..], seed))
                .wrapping_add(mix_16bytes(&data[len - 48..], &key[80..], seed));
        }

        acc = acc
            .wrapping_add(mix_16bytes(&data[16..], &key[32..], seed))
            .wrapping_add(mix_16bytes(&data[len - 32..], &key[48..], seed));
    }

    acc = acc
        .wrapping_add(mix_16bytes(data, &key[..], seed))
        .wrapping_add(mix_16bytes(&data[len - 16..], &key[16..], seed));

    avalanche(acc)
}

const MIDSIZE_MAX: usize = 240;
const MIDSIZE_STARTOFFSET: usize = 3;
const MIDSIZE_LASTOFFSET: usize = 17;

fn hash_len_129to240_64bits(data: &[u8], key: &[u8], seed: u64) -> u64 {
    let len = data.len();

    debug_assert!((129..=MIDSIZE_MAX).contains(&len));

    let acc = (len as u64).wrapping_mul(PRIME64_1);
    let acc = (0..8).fold(acc, |acc, i| {
        acc.wrapping_add(mix_16bytes(&data[16 * i..], &key[16 * i..], seed))
    });
    let acc = avalanche(acc);

    let nb_rounds = len / 16;
    debug_assert!(nb_rounds >= 8);

    let acc = (8..nb_rounds).fold(acc, |acc, i| {
        acc.wrapping_add(mix_16bytes(
            &data[16 * i..],
            &key[16 * (i - 8) + MIDSIZE_STARTOFFSET..],
            seed,
        ))
    });

    avalanche(acc.wrapping_add(mix_16bytes(
        &data[len - 16..],
        &key[SECRET_SIZE_MIN - MIDSIZE_LASTOFFSET..],
        seed,
    )))
}

/* ==========================================
 * Long keys
 * ========================================== */

const STRIPE_LEN: usize = 64;
const SECRET_CONSUME_RATE: usize = 8; // nb of secret bytes consumed at each accumulation
const SECRET_MERGEACCS_START: usize = 11; // do not align on 8, so that secret is different from accumulator
const SECRET_LASTACC_START: usize = 7; // do not align on 8, so that secret is different from scrambler
const ACC_NB: usize = STRIPE_LEN / mem::size_of::<u64>();

#[derive(Debug, Clone, Copy, PartialEq)]
enum AccWidth {
    Acc64Bits,
    Acc128Bits,
}

fn hash_long_64bits_with_default_secret(data: &[u8]) -> u64 {
    hash_long_internal(data, &SECRET)
}

fn hash_long_64bits_with_secret(data: &[u8], secret: &[u8]) -> u64 {
    hash_long_internal(data, secret)
}

/// Generate a custom key, based on alteration of default kSecret with the seed,
/// and then use this key for long mode hashing.
///
/// This operation is decently fast but nonetheless costs a little bit of time.
/// Try to avoid it whenever possible (typically when `seed.is_none()`).
fn hash_long_64bits_with_seed(data: &[u8], seed: u64) -> u64 {
    if seed == 0 {
        hash_long_64bits_with_default_secret(data)
    } else {
        let secret = Secret::with_seed(seed);

        hash_long_internal(data, &secret)
    }
}

#[inline(always)]
fn hash_long_internal(data: &[u8], secret: &[u8]) -> u64 {
    let mut acc = Acc::default();

    hash_long_internal_loop(&mut acc, data, secret, AccWidth::Acc64Bits);

    merge_accs(
        &acc,
        &secret[SECRET_MERGEACCS_START..],
        (data.len() as u64).wrapping_mul(PRIME64_1),
    )
}

#[inline(always)]
fn hash_long_internal_loop(acc: &mut [u64], data: &[u8], secret: &[u8], acc_width: AccWidth) {
    let nb_rounds = (secret.len() - STRIPE_LEN) / SECRET_CONSUME_RATE;
    let block_len = STRIPE_LEN * nb_rounds;
    let len = data.len();
    let nb_blocks = len / block_len;

    debug_assert!(secret.len() >= SECRET_SIZE_MIN);

    for n in 0..nb_blocks {
        accumulate(acc, &data[n * block_len..], secret, nb_rounds, acc_width);
        unsafe {
            scramble_acc(acc, &secret[secret.len() - STRIPE_LEN..]);
        }
    }

    /* last partial block */
    debug_assert!(len > STRIPE_LEN);

    let nb_stripes = (len - (block_len * nb_blocks)) / STRIPE_LEN;

    debug_assert!(nb_stripes < (secret.len() / SECRET_CONSUME_RATE));

    accumulate(
        acc,
        &data[nb_blocks * block_len..],
        secret,
        nb_stripes,
        acc_width,
    );

    /* last stripe */
    if (len & (STRIPE_LEN - 1)) != 0 {
        unsafe {
            accumulate512(
                acc,
                &data[len - STRIPE_LEN..],
                &secret[secret.len() - STRIPE_LEN - SECRET_LASTACC_START..],
                acc_width,
            );
        }
    }
}

#[inline(always)]
fn accumulate(acc: &mut [u64], data: &[u8], secret: &[u8], nb_stripes: usize, acc_width: AccWidth) {
    for n in 0..nb_stripes {
        unsafe {
            accumulate512(
                acc,
                &data[n * STRIPE_LEN..],
                &secret[n * SECRET_CONSUME_RATE..],
                acc_width,
            );
        }
    }
}

const fn _mm_shuffle(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cfg_if! {
    if #[cfg(any(target_feature = "avx2", feature = "avx2"))] {
        #[target_feature(enable = "avx2")]
        unsafe fn accumulate512(acc: &mut [u64], data: &[u8], keys: &[u8], acc_width: AccWidth) {
            let xacc = acc.as_mut_ptr() as *mut __m256i;
            let xdata = data.as_ptr() as *const __m256i;
            let xkey = keys.as_ptr() as *const __m256i;

            for i in 0..STRIPE_LEN / mem::size_of::<__m256i>() {
                let d = _mm256_loadu_si256(xdata.add(i));
                let k = _mm256_loadu_si256(xkey.add(i));
                let dk = _mm256_xor_si256(d, k); // uint32 dk[8]  = {d0+k0, d1+k1, d2+k2, d3+k3, ...}
                let mul = _mm256_mul_epu32(dk, _mm256_shuffle_epi32(dk, 0x31)); // uint64 res[4] = {dk0*dk1, dk2*dk3, ...}

                xacc.add(i).write(if acc_width == AccWidth::Acc128Bits {
                    let dswap = _mm256_shuffle_epi32(d, _mm_shuffle(1,0,3,2));
                    let add = _mm256_add_epi64(xacc.add(i).read(), dswap);
                    _mm256_add_epi64(mul, add)
                } else {
                    let add = _mm256_add_epi64(xacc.add(i).read(), d);
                    _mm256_add_epi64(mul, add)
                })
            }
        }

        #[target_feature(enable = "avx2")]
        unsafe fn scramble_acc(acc: &mut [u64], key: &[u8]) {
            let xacc = acc.as_mut_ptr() as *mut __m256i;
            let xkey = key.as_ptr() as *const __m256i;
            let prime32 = _mm256_set1_epi32(PRIME32_1 as i32);

            for i in 0..STRIPE_LEN / mem::size_of::<__m256i>() {
                let data = xacc.add(i).read();
                let shifted = _mm256_srli_epi64(data, 47);
                let data = _mm256_xor_si256(data, shifted);

                let k = _mm256_loadu_si256(xkey.add(i));
                let dk = _mm256_xor_si256(data, k); /* U32 dk[4]  = {d0+k0, d1+k1, d2+k2, d3+k3} */
                let dk1 = _mm256_mul_epu32(dk, prime32);

                let d2 = _mm256_shuffle_epi32(dk, 0x31);
                let dk2 = _mm256_mul_epu32(d2, prime32);
                let dk2h= _mm256_slli_epi64 (dk2, 32);

                xacc.add(i).write(_mm256_add_epi64(dk1, dk2h));
            }
        }
    } else if #[cfg(any(target_feature = "sse2", feature = "sse2"))] {
        #[target_feature(enable = "sse2")]
        unsafe fn accumulate512(acc: &mut [u64], data: &[u8], keys: &[u8], acc_width: AccWidth) {
            let xacc = acc.as_mut_ptr() as *mut __m128i;
            let xdata = data.as_ptr() as *const __m128i;
            let xkey = keys.as_ptr() as *const __m128i;

            for i in 0..STRIPE_LEN / mem::size_of::<__m128i>() {
                let d = _mm_loadu_si128(xdata.add(i));
                let k = _mm_loadu_si128(xkey.add(i));
                let dk = _mm_xor_si128(d, k); // uint32 dk[4]  = {d0+k0, d1+k1, d2+k2, d3+k3} */
                let mul = _mm_mul_epu32(dk, _mm_shuffle_epi32(dk, 0x31)); // uint64 res[4] = {dk0*dk1, dk2*dk3, ...} */

                xacc.add(i).write(if acc_width == AccWidth::Acc128Bits {
                    let dswap = _mm_shuffle_epi32(d, _mm_shuffle(1,0,3,2));
                    let add = _mm_add_epi64(xacc.add(i).read(), dswap);
                    _mm_add_epi64(mul, add)
                } else {
                    let add = _mm_add_epi64(xacc.add(i).read(), d);
                    _mm_add_epi64(mul, add)
                })
            }
        }

        #[target_feature(enable = "sse2")]
        unsafe fn scramble_acc(acc: &mut [u64], key: &[u8]) {
            let xacc = acc.as_mut_ptr() as *mut __m128i;
            let xkey = key.as_ptr() as *const __m128i;
            let prime32 = _mm_set1_epi32(PRIME32_1 as i32);

            for i in 0..STRIPE_LEN / mem::size_of::<__m128i>() {
                let data = xacc.add(i).read();
                let shifted = _mm_srli_epi64(data, 47);
                let data = _mm_xor_si128(data, shifted);

                let k = _mm_loadu_si128(xkey.add(i));
                let dk = _mm_xor_si128(data, k);

                let dk1 = _mm_mul_epu32(dk, prime32);

                let d2 = _mm_shuffle_epi32(dk, 0x31);
                let dk2 = _mm_mul_epu32(d2, prime32);
                let  dk2h= _mm_slli_epi64(dk2, 32);

                xacc.add(i).write(_mm_add_epi64(dk1, dk2h));
            }
        }
    } else {
        unsafe fn accumulate512(acc: &mut [u64], data: &[u8], key: &[u32], acc_width: AccWidth) {
            for i in (0..ACC_NB).step_by(2) {
                let in1 = data[8*i..].read_u64_le();
                let in2 = data[8*(i+1)..].read_u64_le();
                let key1 = key[8*i..].read_u64_le();
                let key2 = key[8*(i+1)..].read_u64_le();
                let data_key1 = key1 ^ in1;
                let data_key2 = key2 ^ in2;
                acc[i] = acc[i].wrapping_add(mul32_to64(data_key1 as u32, (data_key1 >> 32)as u32));
                acc[i+1] = acc[i].wrapping_add(mul32_to64(data_key2 as u32, (data_key2 >> 32)as u32));

                if acc_width == AccWidth::Acc128Bits {
                    acc[i] = acc[i].wrapping_add(in2);
                    acc[i+1] = acc[i+1].wrapping_add(in1);
                } else {
                    acc[i] = acc[i].wrapping_add(in1);
                    acc[i+1] = acc[i+1].wrapping_add(in2);
                }
            }
        }

        unsafe fn scramble_acc(acc: &mut [u64], key: &[u8]) {
            for i in 0..ACC_NB {
                let key64 = key[8*i].read_u64_le();
                let mut acc64 = acc[i];
                 acc64 ^= acc64 >> 47;
                  acc64 ^=key64;
                  acc64 = acc64.wrapping_mul(u64::from(PRIME32_1));
                  acc[i] = acc64;
            }
        }
    }
}

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
        acc[0] ^ secret.read_u64_le(),
        acc[1] ^ secret[8..].read_u64_le(),
    )
}

#[inline(always)]
fn mix_16bytes(data: &[u8], key: &[u8], seed64: u64) -> u64 {
    let ll1 = data.read_u64_le();
    let ll2 = data[8..].read_u64_le();

    mul128_fold64(
        ll1 ^ key.read_u64_le().wrapping_add(seed64),
        ll2 ^ key[8..].read_u64_le().wrapping_sub(seed64),
    )
}

#[inline(always)]
fn mul128_fold64(ll1: u64, ll2: u64) -> u64 {
    let lll = u128::from(ll1).wrapping_mul(u128::from(ll2));

    (lll as u64) ^ ((lll >> 64) as u64)
}

#[inline(always)]
fn avalanche(mut h64: u64) -> u64 {
    h64 ^= h64 >> 37;
    h64 = h64.wrapping_mul(PRIME64_3);
    h64 ^ (h64 >> 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SANITY_BUFFER_SIZE: usize = 2243;

    #[test]
    fn sanity_check() {
        let prime64 = 11400714785074694797;
        let mut buf = [0; SANITY_BUFFER_SIZE];
        let mut byte_gen: u64 = 2654435761;

        for i in 0..SANITY_BUFFER_SIZE {
            buf[i] = (byte_gen >> 56) as u8;
            byte_gen = byte_gen.wrapping_mul(prime64);
        }

        test_xxh3(b"", 0, 0); /* zero-length hash is always 0 */
        test_xxh3(b"", prime64, 0);
        test_xxh3(&buf[..1], 0, 0x7198D737CFE7F386); /*  1 -  3 */
        test_xxh3(&buf[..1], prime64, 0xB70252DB7161C2BD); /*  1 -  3 */
        test_xxh3(&buf[..6], 0, 0x22CBF5F3E1F6257C); /*  4 -  8 */
        test_xxh3(&buf[..6], prime64, 0x6398631C12AB94CE); /*  4 -  8 */
        test_xxh3(&buf[..12], 0, 0xD5361CCEEBB5A0CC); /*  9 - 16 */
        test_xxh3(&buf[..12], prime64, 0xC4C125E75A808C3D); /*  9 - 16 */
        test_xxh3(&buf[..24], 0, 0x46796F3F78B20F6B); /* 17 - 32 */
        test_xxh3(&buf[..24], prime64, 0x60171A7CD0A44C10); /* 17 - 32 */
        test_xxh3(&buf[..48], 0, 0xD8D4D3590D136E11); /* 33 - 64 */
        test_xxh3(&buf[..48], prime64, 0x05441F2AEC2A1296); /* 33 - 64 */
        test_xxh3(&buf[..80], 0, 0xA1DC8ADB3145B86A); /* 65 - 96 */
        test_xxh3(&buf[..80], prime64, 0xC9D55256965B7093); /* 65 - 96 */
        test_xxh3(&buf[..112], 0, 0xE43E5717A61D3759); /* 97 -128 */
        test_xxh3(&buf[..112], prime64, 0x5A5F89A3FECE44A5); /* 97 -128 */
        test_xxh3(&buf[..195], 0, 0x6F747739CBAC22A5); /* 129-240 */
        test_xxh3(&buf[..195], prime64, 0x33368E23C7F95810); /* 129-240 */

        test_xxh3(&buf[..403], 0, 0x4834389B15D981E8); /* one block, last stripe is overlapping */
        test_xxh3(&buf[..403], prime64, 0x85CE5DFFC7B07C87); /* one block, last stripe is overlapping */
        test_xxh3(&buf[..512], 0, 0x6A1B982631F059A8); /* one block, finishing at stripe boundary */
        test_xxh3(&buf[..512], prime64, 0x10086868CF0ADC99); /* one block, finishing at stripe boundary */
        test_xxh3(&buf[..2048], 0, 0xEFEFD4449323CDD4); /* 2 blocks, finishing at block boundary */
        test_xxh3(&buf[..2048], prime64, 0x01C85E405ECA3F6E); /* 2 blocks, finishing at block boundary */
        test_xxh3(&buf[..2240], 0, 0x998C0437486672C7); /* 3 blocks, finishing at stripe boundary */
        test_xxh3(&buf[..2240], prime64, 0x4ED38056B87ABC7F); /* 3 blocks, finishing at stripe boundary */
        test_xxh3(&buf[..2243], 0, 0xA559D20581D742D3); /* 3 blocks, last stripe is overlapping */
        test_xxh3(&buf[..2243], prime64, 0x96E051AB57F21FC8); /* 3 blocks, last stripe is overlapping */

        let secret = &buf[7..7 + SECRET_SIZE_MIN + 11];

        test_xxh3_with_secret(b"", secret, 0); /* zero-length hash is always 0 */
        test_xxh3_with_secret(&buf[..1], secret, 0x7F69735D618DB3F0); /*  1 -  3 */
        test_xxh3_with_secret(&buf[..6], secret, 0xBFCC7CB1B3554DCE); /*  6 -  8 */
        test_xxh3_with_secret(&buf[..12], secret, 0x8C50DC90AC9206FC); /*  9 - 16 */
        test_xxh3_with_secret(&buf[..24], secret, 0x1CD2C2EE9B9A0928); /* 17 - 32 */
        test_xxh3_with_secret(&buf[..48], secret, 0xA785256D9D65D514); /* 33 - 64 */
        test_xxh3_with_secret(&buf[..80], secret, 0x6F3053360D21BBB7); /* 65 - 96 */
        test_xxh3_with_secret(&buf[..112], secret, 0x560E82D25684154C); /* 97 -128 */
        test_xxh3_with_secret(&buf[..195], secret, 0xBA5BDDBC5A767B11); /* 129-240 */

        test_xxh3_with_secret(&buf[..403], secret, 0xFC3911BBA656DB58); /* one block, last stripe is overlapping */
        test_xxh3_with_secret(&buf[..512], secret, 0x306137DD875741F1); /* one block, finishing at stripe boundary */
        test_xxh3_with_secret(&buf[..2048], secret, 0x2836B83880AD3C0C); /* > one block, at least one scrambling */
        test_xxh3_with_secret(&buf[..2243], secret, 0x3446E248A00CB44A); /* > one block, at least one scrambling, last stripe unaligned */
    }

    fn test_xxh3(buf: &[u8], seed: u64, result: u64) {
        let hash = hash64_with_seed(buf, seed);

        assert_eq!(
            hash,
            result,
            "hash64_with_seed(&buf[..{}], seed={}) failed, got 0x{:X}, expected 0x{:X}",
            buf.len(),
            seed,
            hash,
            result
        );
    }

    fn test_xxh3_with_secret(buf: &[u8], secret: &[u8], result: u64) {
        let hash = hash64_with_secret(buf, secret);

        assert_eq!(
            hash,
            result,
            "hash64_with_secret(&buf[..{}], secret) failed, got 0x{:X}, expected 0x{:X}",
            buf.len(),
            hash,
            result
        );
    }
}
