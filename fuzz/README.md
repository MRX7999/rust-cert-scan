# Fuzzing

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets for the certscan parsers. `fuzz/` is its own workspace: the root `Cargo.toml` excludes it (`exclude = ["fuzz"]`), so `cargo build`, `clippy` and `test --workspace` do not see it. Workspace lints do not apply. A broken invariant in a target is an `assert!`.

## Layout

- `src/lib.rs` — target bodies and their invariants (crate `certscan_fuzz`). The module does not use `libfuzzer-sys`, so it builds and tests on stable.
- `fuzz_targets/<target>.rs` — a `fuzz_target!` wrapper that calls the function of the same name.
- `seeds/<target>/` — initial inputs from recorded fixtures, versioned.
- `corpus/<target>/` — corpus the fuzzer grows. Not in git.

Target inputs are raw bytes (a record stream, or a message body) with no control prefix, so seed files copied from fixtures are used as-is. Chunk sizes for the incremental decoders are derived from a hash of the input. `server_kx` parses one body for every key-exchange kind and every version.

## Targets

| Target | Input | What it checks |
|---|---|---|
| `record_layer` | TLS record stream | `Decoder`: one-shot and chunked parses yield the same events and the same error; every handshake message goes through the dispatcher; every alert goes through `Alert::parse` |
| `server_hello` | ServerHello or HRR body | `ServerHello::parse` and the dispatcher agree (same result, HRR recognized the same way); extensions of a parsed hello read without error |
| `certificate` | Certificate body (TLS up to 1.2) | `CertificateList`: iterator length equals `len()`, certificates are non-empty, slices plus length prefixes cover the body |
| `server_kx` | ServerKeyExchange body | `ServerKeyExchange::parse` for 12 key-exchange kinds and 6 versions: an unsupported kind or version is `Unparsed` and not an error; `signed_params` is a prefix of the body; signature and algorithm presence match the kind and version; fields cover the body |
| `sslv2` | reply to an SSLv2 CLIENT-HELLO | `Sslv2Decoder` one-shot and chunked; `TlsReply` and errors are final; `parse_message`, `Sslv2RecordHeader`, `Sslv2ClientHelloView`; builder/parser round-trip for CLIENT-HELLO |
| `server_message` | handshake type byte and body | `ServerMessage` dispatcher and every typed method: a method returns a value only for its own type; an error is possible only for ServerHello and ServerHelloDone |
| `client_hello` | ClientHello body | `ClientHelloView`; a parsed hello with no extensions, rebuilt by the builder, matches the input byte for byte; a hello built from fields derived from the input parses back to those fields, and fragmented records of that hello reassemble to the same message |
| `alert` | alert message | `Alert::parse` accepts exactly two bytes |

Invariants of the incremental decoders (`record_layer`, `sslv2`, and every place a target feeds assembled records back through a decoder):

- `NeedMore` is returned only when the chunk just fed is exhausted;
- `Decoder::stream_offset()` equals the number of bytes taken from the input;
- bytes attributed to events do not exceed bytes taken; the number of `feed` calls is bounded by the stream length — an event that does not advance the input is impossible;
- after an error, a further `feed` returns the same error and takes no input.

`NotTls` is compared across chunkings only by the fact of the error: the bytes it carries are whatever was available at the check.

The plan (P1-09) names five targets. `server_message`, `client_hello` and `alert` were added beyond it. Targets for X.509, HTTP headers and STARTTLS parsers arrive with those parsers. See `docs/ARCHITECTURE.md`, section 9.

## Seed files

Initial inputs are built from recorded fixtures in `crates/tls-probe/tests/fixtures/*.hex`:

```sh
cargo xtask fuzz-seeds
```

The command is deterministic: it deletes the previous `*.bin` files under `fuzz/seeds/<target>/` and writes a new set. Re-run it after recording or replacing fixtures. The xtask test `seeds_on_disk_match_fixtures` fails if the directory on disk disagrees with the fixtures.

| Directory | Contents |
|---|---|
| `seeds/record_layer/` | record stream of each fixture |
| `seeds/sslv2/` | server fixture streams (the branch where an SSLv2 hello was answered with a TLS record) |
| `seeds/server_message/` | type byte and body of each server handshake message |
| `seeds/server_hello/` | ServerHello and HelloRetryRequest bodies |
| `seeds/certificate/` | Certificate bodies |
| `seeds/server_kx/` | ServerKeyExchange bodies |
| `seeds/client_hello/` | ClientHello bodies |

There are no SSLv2 seed files: the OpenSSL 4.1.0 stand does not support SSLv2, and synthetic bytes are not presented as recordings (`docs/PLAN.md`, P1-28). `alert` has no seed files: a two-byte input is something the fuzzer finds on its own.

## Check without nightly

```sh
cargo check --manifest-path fuzz/Cargo.toml
cargo test --manifest-path fuzz/Cargo.toml
```

The test runs each target on its own seed files, on every prefix of those files, on the seed files of the other targets, and on mutated inputs. That checks invariants on known inputs. It is not fuzzing: the test does not generate new inputs.

## Install

Fuzzing itself needs a nightly toolchain and cargo-fuzz. The project build stays on stable.

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

`cargo +nightly` works only with cargo installed through rustup. Cargo from Homebrew does not provide it.

## Run

Run from the repository root. The seed directory is passed as a second corpus directory: libFuzzer reads inputs from both, and writes new inputs only to the first (`fuzz/corpus/<target>/`).

```sh
cargo +nightly fuzz list
cargo +nightly fuzz build
cargo +nightly fuzz run record_layer fuzz/corpus/record_layer fuzz/seeds/record_layer
cargo +nightly fuzz run server_kx fuzz/corpus/server_kx fuzz/seeds/server_kx -- -max_total_time=600
```

P1-09 acceptance is 10 minutes on each target with no crash and no hang (`-max_total_time=600`).

Reproduce a crash:

```sh
cargo +nightly fuzz run record_layer fuzz/artifacts/record_layer/<file>
```

## Directories

| Directory | Contents | In git |
|---|---|---|
| `fuzz/seeds/<target>/` | initial inputs from fixtures, written by `cargo xtask fuzz-seeds` | yes |
| `fuzz/corpus/<target>/` | local input corpus, grown by a run | no |
| `fuzz/artifacts/<target>/` | inputs that crashed, timed out, or OOM'd | no |
| `fuzz/coverage/<target>/` | `cargo fuzz coverage` data | no |
| `fuzz/target/` | build output | no |

The last four are listed in `.gitignore`. An input that reproduces a bug, once the bug is fixed, moves into the crate's fixtures as a regression test. The format is in [tests/fixtures/README.md](../tests/fixtures/README.md).
