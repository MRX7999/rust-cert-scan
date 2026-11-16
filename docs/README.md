# certscan documentation

`certscan` is an authorized-use TLS and certificate scanner. Output will be JSON and NDJSON only. The binary in this tree does not scan.

This page is the English map. The design record, the task plan and the decision log are maintained in Russian. On conflict, [DECISIONS.md](DECISIONS.md) wins.

## What runs today

```sh
cargo run -p cli -- --version
# certscan 0.1.0
```

No arguments, `-V`, `--version` and `version` print that line and exit 0. `-h`, `--help` and `help` print usage and exit 0. Any other argument, including a host name, exits 2 and opens no connection (decision D-22).

`cargo xtask ci` runs fmt, clippy and the workspace tests. The xtask help text is Russian.

## What is implemented

| Crate | In the tree | Not yet |
|---|---|---|
| `tls-data` | IANA cipher, alert, group, signature-scheme and extension tables. testssl.sh `cipher-mapping.txt` (GPLv2, unchanged). Lookup by code and name. | ALPN registry, client-simulation data, DH primes |
| `tls-probe` | Record layer, incremental decoder, ClientHello builder, ServerHello / HelloRetryRequest, Certificate (TLS 1.2 and earlier), ServerKeyExchange, SSLv2 CLIENT-HELLO and reply decoder | TLS 1.3 Certificate wire format |
| `net` | TCP connect, system resolver, DNS cache, address-family filter, probe exchange, per-stage timeouts, connection counters | Proxy, STARTTLS |
| `engine` | Host and global limits, GCRA rate limit, AIMD backoff, circuit breaker, target parser (name, IP, URL, CIDR, file) | Scheduler, per-target pipeline, checkpoint |
| `checks` | Crate skeleton | Every check |
| `output` | Crate skeleton | JSON and NDJSON writers |
| `x509-check` | Crate skeleton | Parse, chain building, Mozilla trust store, OCSP, CRL |
| `tls-session` | Crate skeleton. `openssl-fallback` feature is declared and empty | TLS 1.3 key schedule, TLS 1.0–1.2 handshake |
| `cli` | Version, help, reject-by-default argv | Flags, TOML, `CERTSCAN_*`, engine wiring |

Fuzz targets cover the parsers that exist. See [fuzz/README.md](../fuzz/README.md). Loopback stands and the fixture format are in [tests/README.md](../tests/README.md).

## Defaults already decided

These numbers are in code. They are preliminary and will be calibrated later. Details are D-04, D-17, D-18, D-19 and D-20 in [DECISIONS.md](DECISIONS.md).

| Limit | Default |
|---|---|
| Connections per host | 2 (`gentle`: 1) |
| Hosts in parallel | 16 |
| Connections, global | 64 |
| Global rate | 200 connections/s, burst 16 |
| Per-host rate | 10 connections/s, burst 2 |
| Connect timeout | 5 s per address |
| Handshake timeout | 10 s to the first response byte |
| Read / write timeout | 5 s |
| Exchange deadline | 30 s |
| DNS cache | 1024 entries, 300 s positive, 30 s negative |

The host limit key is the IP address actually connected to, not the name and not the port (D-18).

## CI artifacts

Every push to `main` and every pull request that changes code builds five release binaries:

| Archive triple | Runner |
|---|---|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` |
| `x86_64-unknown-linux-musl` | `ubuntu-latest`, static musl |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| `aarch64-apple-darwin` | `macos-latest` |
| `x86_64-pc-windows-msvc` | `windows-latest` |

Each job uploads `certscan-<sha>-<target>.tar.gz` or `.zip`, and a matching `.sha256`. A following job checks those hashes and uploads `SHA256SUMS`. Artifacts are kept for 14 days.

A tag matching `v*` runs [Release](../.github/workflows/release.yml). That workflow adds `x86_64-apple-darwin` (cross-compiled on the arm64 macOS runner, packaged, not executed) and, after `cargo deny check`, publishes a GitHub Release. A manual run of the same workflow builds the archives and does not publish.

Ignored paths: a change that only touches `docs/` or other Markdown does not start the matrix.

Tests that need docker or `openssl s_server` are `#[ignore]` on every OS.

## Data provenance

IANA snapshots and the testssl.sh cipher map are vendored. `build.rs` does not use the network. Refresh IANA with `cargo xtask update-data`. The cipher map is pinned to a commit and is not refreshed by that command.

The provenance table is [crates/tls-data/data/SOURCES.md](../crates/tls-data/data/SOURCES.md). The block between the `iana:begin` and `iana:end` markers is rewritten by xtask; do not edit it by hand. The narrative in that file is Russian because the rewriter emits Russian column headers.

## Where to read next

| If you need | Read |
|---|---|
| How to build, and the license | [README.md](../README.md) |
| What you may test, and how to report a defect | [SECURITY.md](../SECURITY.md) |
| The review bar | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Why a crate is shaped this way | [ARCHITECTURE.md](ARCHITECTURE.md) (Russian) |
| The next task and its acceptance check | [PLAN.md](PLAN.md) (Russian) |
| A number or a naming choice | [DECISIONS.md](DECISIONS.md) (Russian) |
| The JSON and NDJSON shape, with real scan examples | [output.md](output.md) |
| A parser invariant | [fuzz/README.md](../fuzz/README.md) |
| A loopback server | [tests/stands/README.md](../tests/stands/README.md) |
| How a `.hex` fixture is recorded | [tests/fixtures/README.md](../tests/fixtures/README.md) |
