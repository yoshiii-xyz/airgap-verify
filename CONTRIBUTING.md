# Contributing

Keep changes inside docs/product-brief.md. This repository is a focused
Rust library and CLI. Do not add a frontend, hosted service, cloud backend,
telemetry, or unrelated format support.

## Local checks

Run these commands before proposing a release:

~~~
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked
cargo package --locked
cargo publish --dry-run --locked
cargo audit
cargo audit --file fuzz/Cargo.lock
~~~

Run the bounded fuzz command in docs/release.md when changing input parsing
or evidence limits.

## Change process

Explain the failure mode or user need, make a narrow change, and add a
regression test when practical. Read back changed files, inspect the diff, and
record exact validation output in private QA evidence for release work.

Do not commit credentials, private keys, registry login files, private audit
output, generated targets, or unredacted artifact traces.
