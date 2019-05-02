#!/usr/bin/env bash

set -eu

# Investigate `cargo nono` when it's more mature
# https://github.com/hobofan/cargo-nono/issues/26

echo "Checking for stdlib symbols"

cargo build

symbols=$(nm target/debug/libtwox_hash.rlib 2> /dev/null || true)

if [[ $symbols != *"std"* ]]; then
    echo 'Did not find symbols that look like the standard library'
    exit 1
fi

echo "Checking for no stdlib symbols"

cargo build --no-default-features

symbols=$(nm target/debug/libtwox_hash.rlib 2> /dev/null || true)

if [[ $symbols == *"std"* ]]; then
    echo 'Found symbols that look like the standard library:'
    grep std <<< "${symbols}"
    exit 1
fi
