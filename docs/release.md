# Release

Run the local release gates from the repository root:

~~~
git diff --check
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

Run the parser fuzz target with two bounded termination predicates:

~~~
timeout --foreground 60s env RUSTUP_TOOLCHAIN=nightly cargo fuzz run bundle-json -- -max_total_time=10 -verbosity=0 -print_final_stats=1
~~~

The timeout is the outer wall-clock cap. The libFuzzer time budget is the
inner cap. Record exit status, executions, and any crash artifact in private
QA evidence. Do not commit fuzz corpus, target output, or private evidence.

## Publication order

1. Complete the local gates and inspect the package contents.
2. Review the diff and commit the release candidate.
3. Push main and wait for CI, Security, and CodeQL.
4. Publish the crate from the reviewed commit.
5. Verify the crates.io API and docs.rs pages.
6. Push an annotated v0.1.0 tag and wait for the tag package workflow.
7. Create the GitHub release with the changelog.
8. Download the published crate independently, compare its contents, install it
   in a fresh Cargo home, and run inspect and verify smoke tests.
9. Record exact results, commit, URLs, and validation limits in private QA.

Hosted actions are pinned to reviewed immutable commits. Branch protection,
security settings, hosted run results, and release artifacts must be checked
before calling the release complete.

## Completeness boundary

No release statement may claim support for formats, trust roots, platforms, or
network conditions that were not tested and recorded. This release is a
narrow local verifier with explicit failure on incomplete evidence.
