# Test stands and fixtures

Integration-test infrastructure for certscan (`docs/PLAN.md`, P0-06; `docs/ARCHITECTURE.md`, section 9). Integration tests talk only to local stands. Contacting an external host is not allowed.

## Layout

| Path | Role |
|---|---|
| `tests/docker-compose.yml` | stand definitions for docker compose |
| `tests/stands/<name>/` | one stand: launch scripts, certificate generation, Dockerfile |
| `tests/fixtures/` | shared byte fixtures. Format: [fixtures/README.md](fixtures/README.md) |

## Stands

| Stand | Address | What it runs |
|---|---|---|
| `openssl-basic` | `127.0.0.1:4433` | `openssl s_server`, TLS 1.2 and TLS 1.3, self-signed ECDSA P-256 certificate (`CN=localhost`) |

Stands with intentionally weak configurations (SSLv2/SSLv3, export ciphers, compression) and STARTTLS servers are added in later phases, together with the checks that need them. Per-stand details, including the fragmentation and DHE-RSA variants, are in [stands/README.md](stands/README.md).

## Run

Directly. OpenSSL 3.0 or newer must be on `PATH`:

```sh
tests/stands/openssl-basic/run.sh
# listens on 127.0.0.1:4433; stop with Ctrl+C
```

Through docker compose:

```sh
docker compose -f tests/docker-compose.yml up -d openssl-basic
docker compose -f tests/docker-compose.yml down
```

Check the connection:

```sh
openssl s_client -connect 127.0.0.1:4433 -brief </dev/null
```

`run.sh` reads `STAND_BIND` (default `127.0.0.1`), `STAND_PORT` (`4433`) and `STAND_TMP` (key and certificate directory, default `.tmp/` next to the script).

## Keys and certificates

Test keys and certificates are not stored in the repository. `gen-cert.sh` creates them on every stand start: locally in `tests/stands/<name>/.tmp/` (gitignored), in the container in `/tmp/stand` on tmpfs. The certificate is valid for 30 days.

## Rules for a new stand

- The stand listens only on `127.0.0.1`. Compose publishes the port as `127.0.0.1:<port>:<port>`. `0.0.0.0` is allowed only inside the container.
- Keys and certificates are generated into a temporary directory. They do not enter git or the image.
- Shell scripts start with `set -euo pipefail`, have the executable bit, and pass `shellcheck`.
- Images with weak configurations run only on the stand's isolated network.
- Each new stand is added to the table above with its address and what it runs.
