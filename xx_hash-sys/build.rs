use std::{env, path::PathBuf, str::FromStr};

fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Need to know target architecture");
    let target_arch = target_arch.parse::<Arch>().ok();

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

    match target_arch {
        Some(Arch::Aarch64) => {
            let mut neon_build = build.clone();
            neon_build
                .define("XXH_VECTOR", "XXH_NEON")
                .define("XXH_NAMESPACE", "neon_")
                .compile("xxhash_neon");
        }

        Some(Arch::X86_64) => {
            let mut avx2_build = build.clone();

            // TODO: check for msvc, not "windows"
            if cfg!(target_os = "windows") {
                // This seems to make the code slower
                // avx2_build.flag("/arch:AVX2");
            } else {
                avx2_build.flag("-march=x86-64-v3");
            }

            avx2_build
                .define("XXH_VECTOR", "XXH_AVX2")
                .define("XXH_NAMESPACE", "avx2_")
                .compile("xxhash_avx2");

            let mut sse2_build = build.clone();
            sse2_build
                .define("XXH_VECTOR", "XXH_SSE2")
                .define("XXH_NAMESPACE", "sse2_")
                .compile("xxhash_sse2");
        }

        None => {}
    }

    let native_build = build;
    native_build.compile("xxhash_native");
}

enum Arch {
    Aarch64,
    X86_64,
}

impl FromStr for Arch {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "aarch64" => Self::Aarch64,
            "x86_64" => Self::X86_64,
            _ => return Err(()),
        })
    }
}
