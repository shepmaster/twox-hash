#[test]
fn seeded_oneshot_matches_c_across_short_lengths_and_cutoff() {
    let data: Vec<u8> = (0..4104).map(|i| (i * 37 + i / 7) as u8).collect();
    for seed in [0, 1, 0xdead_beef, 1 << 63, u64::MAX] {
        for offset in [0, 1, 7] {
            for len in (0..=1025).chain([4096]) {
                let input = &data[offset..][..len];
                assert_eq!(
                    twox_hash::XxHash3_64::oneshot_with_seed(seed, input),
                    xx_hash_sys::XxHash3_64::oneshot_with_seed(seed, input),
                    "64-bit: seed={seed}, offset={offset}, len={len}"
                );
                assert_eq!(
                    twox_hash::XxHash3_128::oneshot_with_seed(seed, input),
                    xx_hash_sys::XxHash3_128::oneshot_with_seed(seed, input),
                    "128-bit: seed={seed}, offset={offset}, len={len}"
                );
            }
        }
    }
}
