cargo test # unit tests
cargo test -p comparison # proptests
cargo miri test # unsafe
cargo miri test --target s390x-unknown-linux-gnu # big-endian

minimal versions
no-features
all-features

features for 32 / 64 / xx3


rand feature instead of `std`?
remove digest as we aren't crypto?
