use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let base = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let base: PathBuf = base.into();
    let xxhash = base.join("xxHash");

    let out = env::var("OUT_DIR").expect("no OUT_DIR");
    let mut out = PathBuf::from(out);
    out.push("xxhash");
    fs::create_dir_all(&out).expect("make it");

    let make_cmd = || {
        let mut c = Command::new("make");
        c.current_dir(&xxhash);
        c
    };

    let s = make_cmd()
        .arg("clean")
        .status()
        .expect("Could not run clean for scalar build");
    assert!(s.success(), "Scalar clean failed");

    let s = make_cmd()
        .arg("libxxhash.a")
        .env(
            "CFLAGS",
            "-O3 -DXXH_VECTOR=XXH_SCALAR -DXXH_NAMESPACE=scalar_",
        )
        .status()
        .expect("Could not run scalar build");
    assert!(s.success(), "Scalar build failed");

    let name = xxhash.join("libxxhash.a");
    let new =  out.join("libxxhash_scalar.a");
    fs::copy(name, new).expect("Copy scalar");

    let s = make_cmd()
        .arg("clean")
        .status()
        .expect("Could not run clean for optimized build");
    assert!(s.success(), "Optimized clean failed");

    let s = make_cmd()
        .arg("libxxhash.a")
        .status()
        .expect("Could not run optimized build");
    assert!(s.success(), "Optimized build failed");

    let name = xxhash.join("libxxhash.a");
    let new =  out.join("libxxhash_optimized.a");
    fs::copy(name, new).expect("Copy scalar");


    println!("cargo::rustc-link-lib=static=xxhash_scalar");
    println!("cargo::rustc-link-lib=static=xxhash_optimized");
    println!("cargo::rustc-link-search={}", out.display());
}
