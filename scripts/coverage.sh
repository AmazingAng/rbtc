#!/usr/bin/env bash
# Run unit tests with coverage. Requires: cargo install cargo-llvm-cov
set -e
cd "$(dirname "$0")/.."
cargo llvm-cov --workspace --all-features --tests "$@"
