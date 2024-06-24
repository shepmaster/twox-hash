use std::{env, path::PathBuf};

fn main() {
    let base = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let base: PathBuf = base.into();
    let xxhash = base.join("xxHash");

    println!("cargo::rustc-link-lib=static=xxhash");
    println!("cargo::rustc-link-search={}", xxhash.display());
}
