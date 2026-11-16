# Byte fixture format

A fixture is the recorded bytes of one direction of an exchange (a ClientHello that was sent, or a server reply) plus a description of where those bytes came from. Parsers and builders are tested on fixtures without a network (`docs/ARCHITECTURE.md`, section 9).

Recorded fixtures live in `crates/tls-probe/tests/fixtures/` as `.hex` + `.meta.toml` pairs, captured by `cargo xtask record-fixture` from the `openssl-basic` stand (`tests/stands/README.md`). Tests in `crates/tls-probe/src/fixture_tests.rs` read them. New fixtures are added with the same subcommand, together with the parser that consumes them.

## Where they live

| Directory | What is stored |
|---|---|
| `crates/<crate>/tests/fixtures/` | fixtures for that crate's unit tests, for example `crates/tls-probe/tests/fixtures/` |
| `tests/fixtures/` | fixtures shared by more than one crate or by integration tests |

The format is the same in both places.

## Pair

A fixture is two files with the same stem:

```text
<name>.hex         bytes
<name>.meta.toml   metadata
```

The name is lowercase ASCII letters, digits and hyphens, shaped `<protocol>-<message>-<source>[-<qualifier>]`. Examples: `tls13-serverhello-openssl-basic`, `tls12-alert-openssl-basic-no-shared-cipher`.

A request/response exchange is two fixtures: the ClientHello that was sent (`direction = "client"`, for example `tls13-clienthello-openssl-basic`) and the server reply (`direction = "server"`), which points at the request with `request`.

A HelloRetryRequest exchange is four fixtures: the first ClientHello, the reply to it (HRR and the ChangeCipherSpec that follows), the second ClientHello, and the full server stream. The full stream points at the first request with `request`, at the second with `second_request`, and `second_request_offset` is how many bytes of the server stream were sent before the second ClientHello.

A synthetic fixture (bytes written by hand, not captured from a server) has the word `synthetic` in the `<source>` segment, for example `tls12-serverhello-synthetic-truncated`, and `[source].kind = "synthetic"` in the metadata. Synthetic bytes must not be presented as a recording of a real server.

## `.hex` file

- Bytes in the order they were sent on the TCP connection, starting at the first byte of that direction (the server reply, or the ClientHello that was sent). One fixture is one direction.
- Lowercase hexadecimal, 16 bytes per line, bytes separated by a space.
- Spaces and newlines are ignored on read.
- A line that starts with `#` is a comment. A comment at the end of a data line is not allowed.
- Bytes are written by the tool from a real server and are not edited by hand. A deliberately damaged input is a separate fixture, and the metadata names the source fixture and the change (`derived_from`, `mutation`). Exception: synthetic fixtures. Their bytes are written by hand, and the first line is the comment `# SYNTHETIC: composed by hand, not a server recording`.

## `.meta.toml`

| Field | Required | Contents |
|---|---|---|
| `format` | yes | metadata format version, currently `1` |
| `description` | yes | what was recorded, one line |
| `direction` | yes | `"server"` (server reply) or `"client"` (ClientHello that was sent) |
| `request` | no | for `direction = "server"`: name of the fixture that holds the ClientHello this reply answers |
| `second_request` | no | for `direction = "server"` in a HelloRetryRequest exchange: name of the fixture that holds the second ClientHello sent on the same connection |
| `second_request_offset` | with `second_request` | number of bytes of this fixture the server sent before the second ClientHello (an integer, not a string); bytes from that offset are the reply to the second request |
| `length` | yes | number of bytes in the `.hex`, for an integrity check |
| `derived_from` | no | name of the source fixture, if the bytes were changed on purpose |
| `mutation` | no | description of that change |
| `[source].kind` | yes | `"stand"` (local stand), `"fuzz"` (an input from `fuzz/artifacts/`) or `"synthetic"` (bytes composed by hand) |
| `[source].stand` | for `stand` | stand name from `tests/stands/` |
| `[source].server` | for `stand` | product and version, the output of `openssl version` or the equivalent |
| `[source].server_command` | for `stand` | command that started the server |
| `[source].capture_command` | yes | command that captured the bytes; for `synthetic`, a description of how the bytes were composed |
| `[source].date` | yes | capture date, `YYYY-MM-DD` |
| `[source.conditions]` | no | capture conditions as key = value: variant parameters and stream properties checked at capture time. Used today: `max_send_frag = "512"` and `handshake_message_spans_records = "true"` (fragmentation variant), `key_type = "rsa"` and `cipher = "DHE-RSA-AES256-GCM-SHA384"` (RSA certificate and DHE-RSA variant). These are not an expected parse result, so they are not written under `[expected.fields]` |
| `[expected].outcome` | yes | `"ok"` (parse succeeds) or `"error"` (the parser must return an error) |
| `[expected].exchange` | for `direction = "server"` from `record-fixture` | exchange result at which capture stopped: `server_hello_done`, `alert`, `encrypted` (first encrypted record, not included in the fixture), `retry_complete` (HRR, second ServerHello and the first encrypted record). A capture with `--force` may also record `timeout`, `closed`, `too_large`, `parse_error` |
| `[expected].summary` | yes | expected parse result, in words |
| `[expected.fields]` | no | expected field values as key = value; the test that reads the fixture decides the key set |

Template. Values in angle brackets are filled at capture time. Commented lines are not present on every fixture.

```toml
format = 1
description = "<what was recorded>"
direction = "server"
request = "<ClientHello fixture name>"
# only the full stream of a HelloRetryRequest exchange:
second_request = "<second ClientHello fixture name>"
second_request_offset = <bytes before the second ClientHello>
length = <byte count>

[source]
kind = "stand"
stand = "openssl-basic"
server = "<output of openssl version>"
server_command = "tests/stands/openssl-basic/run.sh"
capture_command = "<capture command>"
date = "<YYYY-MM-DD>"

# only if the capture used a stand variant:
[source.conditions]
max_send_frag = "512"

[expected]
outcome = "ok"
exchange = "server_hello_done"
summary = "<expected parse result>"

[expected.fields]
# the test decides the keys, for example: legacy_version = "0x0303"
```

## Capture

The capture tool is `cargo xtask record-fixture` (`xtask/src/record_fixture.rs`; help: `cargo xtask record-fixture --help`). It accepts only loopback addresses given as an IP literal.

1. Start a local stand from `tests/stands/` (see [stands/README.md](../stands/README.md)).
2. Record, naming the scenario and the stand's server version:

   ```sh
   cargo xtask record-fixture --addr 127.0.0.1:4433 --scenario tls12 \
     --server "$(openssl version)"
   ```

   The subcommand builds a ClientHello with the `tls-probe` builder, sends it, and saves the raw bytes of both directions up to encryption, without normalizing them. It writes `.hex` and `.meta.toml` itself: `length` is the actual byte count, the date is the capture day, and `capture_command` is the argument list that reproduces the capture (including `--random` and `--key-share`).
3. `[expected]` values come from the scenario and stand configuration, not from the output of the parser under test. What the parser saw during capture is printed to stderr for comparison.
4. If the exchange result does not match the scenario, no fixture is written and the exit code is non-zero. Existing fixtures are not overwritten without `--force`. With `--force`, capture proceeds even when the result disagrees: `[expected].exchange` receives the actual result, and `[expected.fields]` and `[source.conditions]` are not written. In the `tls13-hrr` scenario, if the second ClientHello was not sent, the subcommand refuses even with `--force`: that reply is not an HRR exchange, it is not recorded under the scenario's fixture names, and existing fixtures are left unchanged.

Synthetic fixtures and fixtures taken from fuzzer inputs are written by hand, following the rules above.

## Use in unit tests

- A test includes `.hex` and `.meta.toml` with `include_str!`. A helper in the crate's test code decodes the bytes (skip comments and whitespace, turn hex pairs into bytes). No extra dependency is added for that.
- Tests read individual keys from `.meta.toml` with `meta_value(section, key)` (`crates/tls-probe/src/fixture_tests.rs`). `section` is the section name without brackets (`"source"`, `"source.conditions"`, `"expected"`, `"expected.fields"`) or an empty string for keys before the first section. That parser accepts the subset of TOML that `record-fixture` writes: one key = value pair per line, value an integer or a double-quoted string with no escape expansion. `tls-probe` does not gain a TOML dependency.
- Tests check `length`, the `request` and `second_request` links, `second_request_offset`, source data and stand conditions against the metadata. Field values in `assert` must match `[expected]`.
- Parser tests read fixtures with `direction = "server"`. ClientHello builder tests compare assembled bytes with a fixture of `direction = "client"` (P1-05).
- The fixture loader (`Fixture`, the `fixture!` macro) is test code in the `tls-probe` crate. There is no loader shared across crates.

## Rules

- Fixtures are captured only from local stands under `tests/stands/`, or taken from fuzzer inputs. Synthetic fixtures are marked as such (see above). Replies from external hosts are not recorded.
- Private keys do not enter a fixture. Stand certificates are self-signed and generated on the fly, so a certificate inside a recorded reply belongs to a key that no longer exists.
- A fixture without `.meta.toml`, or with a required field left empty, is not accepted.
