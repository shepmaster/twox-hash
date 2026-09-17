# Benchmark harness

`harness` is a small CLI that automates the benchmarking workflow for
this crate: it checks out commits, runs the benchmarks from the
`comparison` crate, stores the results, and renders SVG reports.

```
cargo +nightly run -- fullstack-delta HEAD
```

## Prerequisites

For data gathering:

- A nightly Rust toolchain
- [`cargo-criterion`][]

For report generation:

- R with the appropriate packages installed (see `shared.R`)
- [`svgo`][]

## Recipes

### Quickly compare C vs Rust for a commit

```
cargo +nightly run -- fullstack-comparison HEAD
```

C vs Rust graphs (`<algo>-<bench>-<fn_name>-<arch>.svg`) are written
to the commit's capture directory, which is printed when the run
finishes.

To publish them, copy the SVGs into `results/`, where [the comparison
README](../README.md) references them.

### Quickly evaluate if a commit improves performance

```
cargo +nightly run -- fullstack-delta HEAD
```

Delta graphs (`delta-*.svg`) showing speed factors relative to the
parent are written to the commit's capture directory, which is printed
when the run finishes.

### Capture data on a different machine and combine it locally

On the other machine, check out the repository and capture the commits
of interest:

```
cargo +nightly run -- capture <commit-or-range>
```

Copy that machine's `comparison/captures` directory somewhere the
local machine can read and merge it in:

```
cargo +nightly run -- absorb /path/to/copied/captures
```

`absorb` adds the other machine's data as new trials, so data from
both machines will coexist in one capture directory.

### Compare two arbitrary commits

Capture both commits in one command and report the delta between them:

```
cargo +nightly run -- fullstack-delta-of v2.1.4 HEAD
```

Delta graphs are written into the second commit's capture
directory. This works for any pair of revisions.

## Common arguments

- `--new-trial` — capture data for a commit again if something changes
outside of the code. Each new trial supplants any existing data, so
you can incrementally run benchmarks to iterate quicker.

- `--subset <filter>` — benchmark only part of the suite. The filter
is handed to `cargo criterion`.

- Hash arguments accept anything `git rev-list` understands;
expressions containing `..` expand to every commit in the range.

## Other subcommands

| Command                              | Purpose                                                                  |
|--------------------------------------|--------------------------------------------------------------------------|
| `report-delta <hashes>`              | Delta reports against each commit's parent, for already-captured commits |
| `capture --include-parents <hashes>` | Also capture each commit's parent (useful before `report-delta`)         |
| `directory-list <hashes>`            | Print which capture directory each commit maps to                        |
| `clean-again`                        | Regenerate every `clean.json` from its `raw.json`                        |
| `clean-raw-json <path>`              | Clean an arbitrary raw JSON file to stdout                               |


## Data storage

Captures are stored in `captures/<tree-hash>/`, keyed by the **tree**
hash of the commit, so two commits with identical contents share one
directory. Each directory contains:

- `raw.json` — the JSON lines emitted by `cargo criterion`
- `clean.json` — one record per benchmark (`algo`, `arch`, `bench`,
  `impl`, `size`, `chunk_size`, `function`, `mean_estimate`)
- `*.svg` — graphs produced by the reporting commands

Capturing **checks out the given commit** so commit or stash local
changes first.

[cargo-criterion]: https://crates.io/crates/cargo-criterion
[svgo]: https://github.com/svg/svgo
