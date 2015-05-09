# TwoX-Hash

A Rust implementation of the [XXHash] algorithm.

[![Build Status](https://travis-ci.org/shepmaster/twox-hash.svg)](https://travis-ci.org/shepmaster/twox-hash) [![Current Version](http://meritbadge.herokuapp.com/twox-hash)](https://crates.io/crates/twox-hash)

[Documentation](https://shepmaster.github.io/twox-hash/)

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

|   Bytes | SipHasher (MB/s) | XXHash (MB/s) |   Ratio |
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

|   Bytes | [FnvHasher] (MB/s) | XXHash (MB/s) |    Ratio |
|---------|--------------------|---------------|----------|
|       1 |               1000 |            40 |    4.00% |
|       4 |                800 |           160 |   20.00% |
|      16 |                761 |           640 |   84.10% |
|      32 |                800 |          1523 |  190.38% |
|     128 |                766 |          4129 |  539.03% |
|     256 |                768 |          5688 |  740.63% |
|     512 |                812 |          6826 |  840.64% |
|    1024 |                771 |          7585 |  983.79% |
| 1048576 |                794 |          9270 | 1167.51% |

[FnvHasher]: https://github.com/servo/rust-fnv

## Contributing

1. Fork it ( https://github.com/shepmaster/twox-hash/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Add a failing test.
4. Add code to pass the test.
5. Commit your changes (`git commit -am 'Add some feature'`)
6. Ensure tests pass.
7. Push to the branch (`git push origin my-new-feature`)
8. Create a new Pull Request
