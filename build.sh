#!/bin/zsh

cargo build
cargo test
cargo clippy
cargo fmt
cargo sqlx prepare -- --lib
