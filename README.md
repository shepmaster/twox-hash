cargo test # unit tests
cargo test -p comparison # proptests
cargo miri test # unsafe
cargo miri test --target s390x-unknown-linux-gnu # big-endian

cargo -Z profile-rustflags --config 'profile.test.package.xx-renu.rustflags=["--cfg=_internal_xxhash3_force_scalar"]' test

minimal versions
no-features
all-features

features for 32 / 64 / xx3


rand feature instead of `std`?
remove digest as we aren't crypto?
