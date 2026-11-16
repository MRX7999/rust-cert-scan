# Contributing

The public documents are English: this file, `README.md`, `SECURITY.md`, `docs/README.md`, and the READMEs under `fuzz/` and `tests/`. The design record stays Russian: `docs/ARCHITECTURE.md`, `docs/PLAN.md`, `docs/DECISIONS.md`. Rust comments and rustdoc stay Russian, matching the code already in the tree. Do not translate those unless the task is a translation.

## Before you change code

Read the task you are implementing in [docs/PLAN.md](docs/PLAN.md) and the decisions that constrain it in [docs/DECISIONS.md](docs/DECISIONS.md). On conflict, the decision log wins.

New dependencies go in through `cargo add` so the version is real and lands in `Cargo.lock`. Then `cargo deny check`. Git dependencies and registries other than crates.io are denied.

Do not add a check, fixture or test that contacts anything except `127.0.0.1` or the docker-compose network in `tests/`. Do not commit keys, live certificates, or captures from a host you do not own.

## Bar

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

`unsafe_code` is forbidden for the whole workspace (D-10). The `fuzz/` workspace is excluded and is the only place a fuzzer harness may break that rule.

Parsers do not use `unwrap`, `expect`, `panic!` or unchecked indexing. Public items have rustdoc. Those comments are Russian.

Integration tests that need docker or `openssl` are `#[ignore]`.

## Development commands

```sh
cargo xtask --help
cargo xtask ci
cargo xtask update-data
cargo xtask record-fixture --help
cargo xtask fuzz-seeds
```

`xtask` help is Russian. `schema` exits non-zero until P4-08.

## Pull requests

Say which plan task the change closes, or say that it is outside the plan and why. Keep the diff to that task. Do not reformat unrelated files.

CI runs on Linux x86_64 (glibc and musl), Linux arm64, macOS arm64 and Windows x86_64. It builds a release binary, smoke-tests it, and uploads an archive. A docs-only change does not start that matrix.
