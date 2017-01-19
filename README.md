# TwoX-Hash

A Rust implementation of the [XXHash] algorithm.

[![Build Status](https://travis-ci.org/shepmaster/twox-hash.svg)](https://travis-ci.org/shepmaster/twox-hash) [![Current Version](http://meritbadge.herokuapp.com/twox-hash)](https://crates.io/crates/twox-hash)

[Documentation](https://docs.rs/twox-hash/)

[XXHash]: https://github.com/Cyan4973/xxHash

## Examples

### With a fixed seed

```rust
use std::hash::BuildHasherDefault;
use std::collections::HashMap;
use twox_hash::XxHash;

let mut hash: HashMap<_, _, BuildHasherDefault<XxHash>> = Default::default();
hash.insert(42, "the answer");
assert_eq!(hash.get(&42), Some(&"the answer"));
```

### With a random seed

```rust
use std::collections::HashMap;
use twox_hash::RandomXxHashBuilder;

let mut hash: HashMap<_, _, RandomXxHashBuilder> = Default::default();
hash.insert(42, "the answer");
assert_eq!(hash.get(&42), Some(&"the answer"));
```

## Benchmarks

|   Bytes | SipHasher (MB/s) | XXHash (MB/s) | Ratio |
|---------|------------------|---------------|-------|
|       1 |               62 |            37 |   60% |
|       4 |              190 |           153 |   81% |
|      16 |              695 |           640 |   92% |
|      32 |             1000 |          1391 |  139% |
|     128 |             1376 |          3555 |  258% |
|     256 |             1422 |          4740 |  333% |
|     512 |             1492 |          5752 |  386% |
|    1024 |             1558 |          5919 |  380% |
| 1048576 |             1581 |          7243 |  458% |

|   Bytes | [FnvHasher][fnv] (MB/s) | XXHash (MB/s) | Ratio |
|---------|-------------------------|---------------|-------|
|       1 |                    1000 |            37 |    4% |
|       4 |                     800 |           153 |   19% |
|      16 |                     761 |           640 |   84% |
|      32 |                     727 |          1391 |  191% |
|     128 |                     735 |          3555 |  484% |
|     256 |                     715 |          4740 |  663% |
|     512 |                     760 |          5752 |  757% |
|    1024 |                     763 |          5919 |  776% |
| 1048576 |                     696 |          7243 | 1041% |

[fnv]: https://github.com/servo/rust-fnv

## Contributing

1. Fork it ( https://github.com/shepmaster/twox-hash/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Add a failing test.
4. Add code to pass the test.
5. Commit your changes (`git commit -am 'Add some feature'`)
6. Ensure tests pass.
7. Push to the branch (`git push origin my-new-feature`)
8. Create a new Pull Request
