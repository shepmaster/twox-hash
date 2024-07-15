#![allow(missing_docs)]

use core::{mem, slice};

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

pub struct XxHash3_64;

type Stripe = [u64; 8];

impl XxHash3_64 {
    #[inline(never)]
    pub fn oneshot(input: &[u8]) -> u64 {
        impl_oneshot(&DEFAULT_SECRET, DEFAULT_SEED, input)
    }

    #[inline(never)]
    pub fn oneshot_with_seed(seed: u64, input: &[u8]) -> u64 {
        let secret = if seed != 0 && input.len() > 240 {
            &derive_secret(seed)
        } else {
            &DEFAULT_SECRET
        };

        impl_oneshot(secret, seed, input)
    }

    #[inline(never)]
    pub fn oneshot_with_secret(secret: &[u8], input: &[u8]) -> u64 {
        assert!(secret.len() >= SECRET_MINIMUM_LENGTH); // TODO: ERROR
        impl_oneshot(secret, DEFAULT_SEED, input)
    }
}

#[inline]
fn derive_secret(seed: u64) -> [u8; 192] {
    let mut derived_secret = DEFAULT_SECRET;
    let base = derived_secret.as_mut_ptr().cast::<u64>();

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

    derived_secret
}

#[inline]
fn impl_oneshot(secret: &[u8], seed: u64, input: &[u8]) -> u64 {
    match input.len() {
        0 => impl_0_bytes(secret, seed),

        1..=3 => impl_1_to_3_bytes(secret, seed, input),

        4..=8 => impl_4_to_8_bytes(secret, seed, input),

        9..=16 => impl_9_to_16_bytes(secret, seed, input),

        17..=128 => impl_17_to_128_bytes(secret, seed, input),

        129..=240 => impl_129_to_240_bytes(secret, seed, input),

        _ => impl_241_plus_bytes(secret, input),
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

    let num_rounds = ((input.len() - 1) >> 5) + 1;

    let (fwd, _) = input.bp_as_chunks();
    let (_, bwd) = input.bp_as_rchunks();

    let fwd = fwd.iter();
    let bwd = bwd.iter().rev();

    for (i, (fwd_chunk, bwd_chunk)) in fwd.zip(bwd).enumerate().take(num_rounds) {
        acc = acc.wrapping_add(mix_step(fwd_chunk, secret, i * 32, seed));
        acc = acc.wrapping_add(mix_step(bwd_chunk, secret, i * 32 + 16, seed));
    }

    avalanche(acc)
}

#[inline]
fn impl_129_to_240_bytes(secret: &[u8], seed: u64, input: &[u8]) -> u64 {
    let mut acc = input.len().into_u64().wrapping_mul(PRIME64_1);

    let (head, _tail) = input.bp_as_chunks();
    let mut head = head.iter();

    for (i, chunk) in head.by_ref().take(8).enumerate() {
        acc = acc.wrapping_add(mix_step(chunk, secret, i * 16, seed));
    }

    acc = avalanche(acc);

    for (i, chunk) in head.enumerate() {
        acc = acc.wrapping_add(mix_step(chunk, secret, i * 16 + 3, seed));
    }

    acc = acc.wrapping_add(mix_step(input.last_chunk().unwrap(), secret, 119, seed));

    avalanche(acc)
}

#[inline]
fn mix_step(data: &[u8; 16], secret: &[u8], secret_offset: usize, seed: u64) -> u64 {
    // TODO: Should these casts / reads happen outside this function?
    let data_words = unsafe { data.as_ptr().cast::<[u64; 2]>().read_unaligned() };
    let secret_words = unsafe {
        secret
            .as_ptr()
            .add(secret_offset)
            .cast::<[u64; 2]>()
            .read_unaligned()
    };

    let mul_result = {
        let a = (data_words[0] ^ secret_words[0].wrapping_add(seed)).into_u128();
        let b = (data_words[1] ^ secret_words[1].wrapping_sub(seed)).into_u128();

        a.wrapping_mul(b)
    };

    mul_result.lower_half() ^ mul_result.upper_half()
}

// fn mix_two_chunks(
//     acc: &mut [u64; 2],
//     data1: &[u8; 16],
//     data2: &[u8; 16],
//     secret: &[u8],
//     secret_offset: usize,
//     seed: u64,
// ) {
//     // TODO: Should these casts / reads happen outside this function?
//     let data_words1 = unsafe { data1.as_ptr().cast::<[u64; 2]>().read_unaligned() }; // TODO:little-endian conversion
//     let data_words2 = unsafe { data2.as_ptr().cast::<[u64; 2]>().read_unaligned() }; // TODO:little-endian conversion

//     acc[0] = acc[0] + mix_step(data1, secret, secret_offset, seed);
//     acc[1] = acc[1] + mix_step(data2, secret, secret_offset + 16, seed);
//     acc[0] = acc[0] ^ data_words2[0].wrapping_add(data_words2[1]);
//     acc[1] = acc[1] ^ data_words1[0].wrapping_add(data_words1[1]);
// }

#[rustfmt::skip]
const INITIAL_ACCUMULATORS: [u64; 8] = [
    PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3,
    PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1,
];

#[inline]
fn impl_241_plus_bytes(secret: &[u8], input: &[u8]) -> u64 {
    let mut acc = INITIAL_ACCUMULATORS;

    let stripes_per_block = (secret.len() - 64) / 8;
    let block_size = 64 * stripes_per_block;

    let mut blocks = input.chunks(block_size).fuse();
    let last_block = blocks.next_back().unwrap();
    let last_stripe: &[u8; 64] = unsafe {
        &*input
            .as_ptr()
            .add(input.len())
            .sub(mem::size_of::<[u8; 64]>())
            .cast()
    };

    for block in blocks {
        round(&mut acc, block, secret);
    }

    last_round(&mut acc, last_block, last_stripe, secret);

    final_merge(
        &mut acc,
        input.len().into_u64().wrapping_mul(PRIME64_1),
        secret,
        11,
    )
}

#[inline]
fn round(acc: &mut [u64; 8], block: &[u8], secret: &[u8]) {
    round_accumulate(acc, block, secret);
    round_scramble(acc, secret);
}

#[inline]
fn round_accumulate(acc: &mut [u64; 8], block: &[u8], secret: &[u8]) {
    let (stripes, _) = block.bp_as_chunks::<{ mem::size_of::<Stripe>() }>();
    let secrets =
        (0..stripes.len()).map(|i| unsafe { &*secret.get_unchecked(i * 8..).as_ptr().cast() });

    for (stripe, secret) in stripes.iter().zip(secrets) {
        accumulate(acc, stripe, secret);
    }
}

#[inline]
fn round_scramble(acc: &mut [u64; 8], secret: &[u8]) {


    // let last = secret
    //     .last_chunk::<{ mem::size_of::<[u8; 64]>() }>()
    //     .unwrap();
    // let (last, _) = last.bp_as_chunks();
    // let last = last.iter().copied().map(u64::from_ne_bytes);

    // for (acc, secret) in acc.iter_mut().zip(last) {
    //     *acc ^= *acc >> 47;
    //     *acc ^= secret;
    //     *acc = acc.wrapping_mul(PRIME32_1);
    // }

    unsafe {
        use core::arch::aarch64::*;

        let secret_base = secret.as_ptr().add(secret.len()).sub(64).cast::<u64>();
        let (acc, _) = acc.bp_as_chunks_mut::<2>();
        for (i, acc) in acc.iter_mut().enumerate() {
            let mut accv = vld1q_u64(acc.as_ptr());
            let secret = vld1q_u64(secret_base.add(i * 2));

            let shifted = vshrq_n_u64::<47>(accv);
            accv = veorq_u64(accv, shifted);
            accv = veorq_u64(accv, secret);

            accv = neon::xx_vmulq_u32_u64(accv, PRIME32_1 as u32);

            vst1q_u64(acc.as_mut_ptr(), accv);
        }
    }
}

mod neon {
    use core::arch::aarch64::*;

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
}

#[inline]
fn last_round(acc: &mut [u64; 8], block: &[u8], last_stripe: &[u8; 64], secret: &[u8]) {
    // Accumulation steps are run for the stripes in the last block,
    // except for the last stripe (whether it is full or not)
    let stripes = match block.bp_as_chunks() {
        ([stripes @ .., _last], []) => stripes,
        (stripes, _last) => stripes,
    };
    let secrets =
        (0..stripes.len()).map(|i| unsafe { &*secret.get_unchecked(i * 8..).as_ptr().cast() });

    for (stripe, secret) in stripes.iter().zip(secrets) {
        accumulate(acc, stripe, secret);
    }

    let q = &secret[secret.len() - 71..];
    let q: &[u8; 64] = unsafe { &*q.as_ptr().cast() };
    accumulate(acc, last_stripe, q);
}

#[inline]
fn final_merge(acc: &mut [u64; 8], init_value: u64, secret: &[u8], secret_offset: usize) -> u64 {
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

#[inline]
fn accumulate(acc: &mut [u64; 8], stripe: &[u8; 64], secret: &[u8; 64]) {
    use core::arch::aarch64::*;

    // unsafe {
    //     _prefetch::<_PREFETCH_READ, _PREFETCH_LOCALITY3>(stripe.as_ptr().cast());
    //     _prefetch::<_PREFETCH_READ, _PREFETCH_LOCALITY3>(secret.as_ptr().cast());
    // }

    // eprintln!("{acc:x?}");
    // for i in 0..8 {
    //     // TODO: Should these casts / reads happen outside this function?
    //     let stripe = unsafe { stripe.as_ptr().cast::<u64>().add(i).read_unaligned() };
    //     let secret = unsafe { secret.as_ptr().cast::<u64>().add(i).read_unaligned() };

    //     eprintln!("{:x?}, {:x?}", stripe, secret);

    //     let value = stripe ^ secret;
    //     acc[i ^ 1] = acc[i ^ 1].wrapping_add(stripe);
    //     acc[i] = multiply_64_as_32_and_add(value, value >> 32, acc[i]);
    // }

    // We process 4x u64 at a time as that allows us to completely
    // fill a `uint64x2_t` with useful values when performing the
    // `vmull_{high_}u32`.
    let (acc2, _) = acc.bp_as_chunks_mut::<4>();
    for (i, acc) in acc2.into_iter().enumerate() {
        unsafe {
            let mut accv_0 = vld1q_u64(acc.as_ptr().cast::<u64>());
            let mut accv_1 = vld1q_u64(acc.as_ptr().cast::<u64>().add(2));
            let stripe_0 = vld1q_u64(stripe.as_ptr().cast::<u64>().add(i * 4));
            let stripe_1 = vld1q_u64(stripe.as_ptr().cast::<u64>().add(i * 4 + 2));
            let secret_0 = vld1q_u64(secret.as_ptr().cast::<u64>().add(i * 4));
            let secret_1 = vld1q_u64(secret.as_ptr().cast::<u64>().add(i * 4 + 2));

            let value_0 = veorq_u64(stripe_0, secret_0);
            let value_1 = veorq_u64(stripe_1, secret_1);

            let parts_0 = vreinterpretq_u32_u64(value_0);
            let parts_1 = vreinterpretq_u32_u64(value_1);

            let hi = vuzp1q_u32(parts_0, parts_1);
            let lo = vuzp2q_u32(parts_0, parts_1);

            let product_0 = vmull_u32(vget_low_u32(hi), vget_low_u32(lo));
            let product_1 = vmull_high_u32(hi, lo);

            accv_0 = vaddq_u64(accv_0, product_0);
            accv_1 = vaddq_u64(accv_1, product_1);

            let stripe_rot_0 = vextq_u64::<1>(stripe_0, stripe_0);
            let stripe_rot_1 = vextq_u64::<1>(stripe_1, stripe_1);
            accv_0 = vaddq_u64(accv_0, stripe_rot_0);
            accv_1 = vaddq_u64(accv_1, stripe_rot_1);

            vst1q_u64(acc.as_mut_ptr().cast::<u64>(), accv_0);
            vst1q_u64(acc.as_mut_ptr().cast::<u64>().add(2), accv_1);
        };
    }


    // Pseudo-SIMD

    // for (acc, (str, sec)) in acc.iter_mut().zip(stripe_x.into_iter().zip(secret_x)) {
    //     let value = str ^ sec;
    //     *acc = multiply_64_as_32_and_add(value, value >> 32, *acc);
    // }

    // let mut stripe_x = stripe_x;

    // stripe_x.swap(0, 1);
    // stripe_x.swap(2, 3);
    // stripe_x.swap(4, 5);
    // stripe_x.swap(6, 7);

    // for (acc, str) in acc.iter_mut().zip(stripe_x) {
    //     *acc = acc.wrapping_add(str);
    // }
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
fn multiply_64_as_32_and_add(lhs: u64, rhs: u64, acc: u64) -> u64 {
    let lhs = (lhs as u32).into_u64();
    let rhs = (rhs as u32).into_u64();

    let product = lhs.wrapping_mul(rhs);
    acc.wrapping_add(product)
}

#[inline]
// https://github.com/Cyan4973/xxHash/blob/d5fe4f54c47bc8b8e76c6da9146c32d5c720cd79/xxhash.h#L5595-L5610
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
    use std::array;

    use super::*;

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

    #[test]
    fn hash_empty() {
        let hash = XxHash3_64::oneshot(&[]);
        assert_eq!(hash, 0x2d06_8005_38d3_94c2);
    }

    #[test]
    fn hash_1_to_3_bytes() {
        let inputs = bytes![1, 2, 3];

        let expected = [
            0xc44b_dff4_074e_ecdb,
            0xd664_5fc3_051a_9457,
            0x5f42_99fc_161c_9cbb,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn hash_4_to_8_bytes() {
        let inputs = bytes![4, 5, 6, 7, 8];

        let expected = [
            0x60da_b036_a582_11f2,
            0xb075_753a_84ca_0fbe,
            0xa658_4d1d_9a6a_e704,
            0x0cd2_084a_6240_6b69,
            0x3a1c_2d7c_85af_88f8,
        ];

        for (input, expected) in inputs.iter().zip(expected) {
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn hash_9_to_16_bytes() {
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
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn hash_17_to_128_bytes() {
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
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn hash_129_to_240_bytes() {
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
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn hash_241_plus_bytes() {
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
            let hash = XxHash3_64::oneshot(input);
            assert_eq!(hash, expected, "input was {} bytes", input.len());
        }
    }

    #[test]
    fn hash_with_seed() {
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
            let hash = XxHash3_64::oneshot_with_seed(0xdead_cafe, input);
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
