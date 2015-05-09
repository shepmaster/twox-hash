# TwoX-Hash

A Rust implementation of the [XXHash] algorithm.

[XXHash]: https://github.com/Cyan4973/xxHash

## Examples

### With a fixed seed

```rust
#![feature(std_misc)]

use std::collections::HashMap;
use std::collections::hash_state::DefaultState;
use hash::XxHash;

let mut hash: HashMap<_, _, DefaultState<XxHash>> = Default::default();
hash.insert(42, "the answer");
assert_eq!(hash.get(&42), Some(&"the answer"));
```

### With a random seed

```rust
use std::collections::HashMap;
use hash::RandomXxHashState;

let mut hash: HashMap<_, _, RandomXxHashState> = Default::default();
hash.insert(42, "the answer");
assert_eq!(hash.get(&42), Some(&"the answer"));
```

## Benchmarks

|   Bytes | SipHasher (MB/s) | XXHash (MB/s) | Speedup |
|---------|------------------|---------------|---------|
|       1 |               66 |            41 |     62% |
|       4 |              210 |           166 |     79% |
|      16 |              615 |           666 |    108% |
|      32 |              800 |          1523 |    190% |
|     128 |             1007 |          4129 |    410% |
|     256 |             1057 |          5818 |    550% |
|     512 |             1084 |          7111 |    656% |
|    1024 |             1092 |          8062 |    738% |
| 1048576 |             1113 |          9381 |    843% |

## Contributing

1. Fork it ( https://github.com/shepmaster/twox-hash/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Add a failing test.
4. Add code to pass the test.
5. Commit your changes (`git commit -am 'Add some feature'`)
6. Ensure tests pass.
7. Push to the branch (`git push origin my-new-feature`)
8. Create a new Pull Request
