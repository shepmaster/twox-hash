cargo test # unit tests
cargo test -p comparison # proptests
cargo miri test # unsafe
cargo miri test --target s390x-unknown-linux-gnu # big-endian
