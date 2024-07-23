use std::{env, path::PathBuf};

fn main() {
    // TODO: CARGO_CFG_TARGET_FEATURE has `Some(adx,aes,avx,avx2,...`

    let base = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let mut base: PathBuf = base.into();
    base.push("xxHash");
    base.push("xxhash.c");

    let build = {
        let mut build = cc::Build::new();
        build.file(base);
        build
    };

    let mut scalar_build = build.clone();
    scalar_build
        .define("XXH_VECTOR", "XXH_SCALAR")
        .define("XXH_NAMESPACE", "scalar_")
        .compile("xxhash_scalar");

    let mut avx2_build = build.clone();
    avx2_build
        .flag("-march=x86-64-v3")
        .define("XXH_VECTOR", "XXH_AVX2")
        .define("XXH_NAMESPACE", "avx2_")
        .compile("xxhash_avx2");

    let native_build = build;
    native_build.compile("xxhash_native");
}
