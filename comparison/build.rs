fn main() {
    cc::Build::new().file("xxHash/xxhash.c").compile("xxhash");
}
