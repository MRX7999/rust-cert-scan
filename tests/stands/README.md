# Stands

Local TLS servers for certscan integration tests (`docs/PLAN.md`, P0-06). The `tests/` layout and the rules for a new stand are in [../README.md](../README.md).

## What exists

| Stand | Address | Configuration | How to start |
|---|---|---|---|
| `openssl-basic` | `127.0.0.1:4433` | `openssl s_server -www`, TLS 1.2 and TLS 1.3 (`-min_protocol TLSv1.2 -max_protocol TLSv1.3`), self-signed ECDSA P-256 certificate, `CN=localhost`, SAN `DNS:localhost`, `IP:127.0.0.1`, 30-day lifetime | `run.sh` directly; service `openssl-basic` in `tests/docker-compose.yml` |

There is no other stand in Phase 0: P0-06 asks for one. Stands with weak configurations arrive in later phases, together with the checks that need them.

## Start and stop

Directly. OpenSSL 3.0 or newer must be on `PATH`. The server runs in the foreground. Stop it with Ctrl+C:

```sh
tests/stands/openssl-basic/run.sh
```

In the background, stopped by PID:

```sh
tests/stands/openssl-basic/run.sh &
STAND_PID=$!
kill "$STAND_PID"
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

`run.sh` environment variables: `STAND_BIND` (default `127.0.0.1`), `STAND_PORT` (`4433`), `STAND_TMP` (key and certificate directory, default `.tmp/` next to the script, gitignored), `STAND_MAX_SEND_FRAG` and `STAND_EXTRA_SAN` (fragmentation variant), `STAND_KEY_TYPE` and `STAND_CIPHER` (RSA certificate and DHE-RSA variant). The key and certificate are created fresh on every start and are not committed.

## Fragmentation variant

The same `openssl-basic` stand, on port `4434`, with two extra variables. It exists so the Certificate handshake message arrives in several records (reassembly in `Decoder`, scenario `tls12-fragmented` of `record-fixture`).

| Variable | Effect |
|---|---|
| `STAND_MAX_SEND_FRAG` | passed to `s_server -max_send_frag`: maximum outgoing record fragment, 512 to 16384. `run.sh` only checks that the value is an integer; OpenSSL checks the range. Without the variable the flag is not passed |
| `STAND_EXTRA_SAN` | extra `subjectAltName` entries, comma-separated. `gen-cert.sh` appends them to `DNS:localhost,IP:127.0.0.1`. They grow the certificate so Certificate does not fit in one 512-byte record |

Start (same values as `[source].server_command` of the fixture `tls12-serverhello-openssl-basic-max-send-frag`):

```sh
STAND_PORT=4434 STAND_MAX_SEND_FRAG=512 \
STAND_EXTRA_SAN="DNS:fragment-padding-01.stand.localhost,DNS:fragment-padding-02.stand.localhost,DNS:fragment-padding-03.stand.localhost,DNS:fragment-padding-04.stand.localhost,DNS:fragment-padding-05.stand.localhost,DNS:fragment-padding-06.stand.localhost,DNS:fragment-padding-07.stand.localhost,DNS:fragment-padding-08.stand.localhost" \
tests/stands/openssl-basic/run.sh
```

Record fixtures from this variant:

```sh
cargo xtask record-fixture --addr 127.0.0.1:4434 --scenario tls12-fragmented \
  --stand openssl-basic --server "$(openssl version)"
```

The variant uses the same `STAND_TMP` as the main stand. To run both at once, give the variant its own `STAND_TMP`. Otherwise the second start overwrites the first stand's key and certificate. A server that is already running is unaffected: it read the files at startup.

## RSA certificate and DHE-RSA variant

The same `openssl-basic` stand, on port `4435`, with an RSA certificate and a single TLS 1.2 cipher. It exists to obtain a ServerKeyExchange with DH parameters (`p`, `g`, `Ys`) and an RSA signature (parsed in `tls-probe`, P1-07; scenario `tls12-dhe-rsa` of `record-fixture`).

| Variable | Effect |
|---|---|
| `STAND_KEY_TYPE` | certificate key type: `ecdsa` (default, P-256) or `rsa` (RSA 2048). Any other value is an error from `gen-cert.sh` |
| `STAND_CIPHER` | passed to `s_server -cipher`: TLS 1.2-and-below cipher list in OpenSSL syntax. `run.sh` only checks the character set; OpenSSL checks the list. It does not affect TLS 1.3 ciphers. Without the variable the flag is not passed |

The stand does not set DH parameters (`-dhparam` is not passed). The server chooses them. In the `s_server` log that is the line `Using default temp DH parameters`.

Start (same values as `[source].server_command` of the fixture `tls12-serverhello-openssl-basic-dhe-rsa`; a separate `STAND_TMP` is needed only if another variant is running at the same time):

```sh
STAND_PORT=4435 STAND_KEY_TYPE=rsa STAND_CIPHER=DHE-RSA-AES256-GCM-SHA384 \
tests/stands/openssl-basic/run.sh
```

Record fixtures from this variant:

```sh
cargo xtask record-fixture --addr 127.0.0.1:4435 --scenario tls12-dhe-rsa \
  --stand openssl-basic --server "$(openssl version)"
```

Reference check for values used in tests:

```sh
openssl s_client -connect 127.0.0.1:4435 -tls1_2 -cipher DHE-RSA-AES256-GCM-SHA384 </dev/null
```

## What a run actually checked

Checked on 2026-11-11, macOS arm64, `OpenSSL 4.1.0 23 Oct 2026` from Homebrew (`/opt/homebrew/bin/openssl`).

| What | Result |
|---|---|
| `run.sh` directly | checked: `lsof` shows a listener only on `127.0.0.1:4433` |
| TLS 1.2 connection | checked: `s_client -tls1_2`, selected `ECDHE-ECDSA-AES256-GCM-SHA384` |
| TLS 1.3 connection | checked: `s_client -tls1_3`, selected `TLS_AES_256_GCM_SHA384` |
| Stop | checked: after `kill`, port 4433 is free |
| Keys stay out of git | checked: `git status --short` does not show the contents of `.tmp/` |
| Fragmentation variant (`127.0.0.1:4434`, `STAND_MAX_SEND_FRAG=512`, eight extra SANs) | checked by recording the fixture `tls12-serverhello-openssl-basic-max-send-frag` (902 bytes, cipher `0xc02c`, result `server_hello_done`): `record-fixture` confirmed at capture time that the handshake message spans several records (`handshake_message_spans_records = "true"` in `[source.conditions]`) |
| RSA certificate and DHE-RSA variant (`127.0.0.1:4435`, `STAND_KEY_TYPE=rsa`, `STAND_CIPHER=DHE-RSA-AES256-GCM-SHA384`, separate `STAND_TMP`) | checked: `s_client -tls1_2 -cipher DHE-RSA-AES256-GCM-SHA384` showed `Cipher is DHE-RSA-AES256-GCM-SHA384`, `Peer Temp Key: DH, 2048 bits`, `Peer signature type: rsa_pss_rsae_sha256`, `Server public key is 2048 bit`; fixture `tls12-serverhello-openssl-basic-dhe-rsa` was recorded (1650 bytes, cipher `0x009f`, result `server_hello_done`); after `kill`, port 4435 is free |
| Other values of `STAND_MAX_SEND_FRAG` and `STAND_CIPHER`, and running several variants at once | not checked |
| Rejection of TLS 1.1 and below | not checked: `s_client -tls1_1` failed on the client side (`no protocols available`) and the probe never reached the server |
| `docker compose up -d openssl-basic` | not run: docker is not used on the development machine |
| `Dockerfile` build | not checked; the `alpine:3` base image was not pulled |
| `shellcheck` on `run.sh` and `gen-cert.sh` | not run |

During that check the server log showed one `ssl3_read_bytes:unexpected message` line. Both probes still completed. The cause of the line was not investigated.

## Limits of this OpenSSL build

The notes on SSLv2, SSLv3 and compression come from `openssl s_server -help`. Those configurations were not started. The other points were checked on 2026-11-11 with a one-off `openssl s_server` on `127.0.0.1:4436` and `127.0.0.1:4437` (not through `run.sh`) and `openssl s_client`. The servers were stopped after the check. No fixtures were recorded.

- SSLv2: no flag, the protocol is not supported. Needs a docker stand with an old OpenSSL build.
- SSLv3: `s_server` has no `-ssl3` flag. Needs a docker stand.
- TLS 1.0 and TLS 1.1: work with `-min_protocol TLSv1` and a cipher list that includes `@SECLEVEL=0` on both sides. `s_client -tls1` and `s_client -tls1_1` completed a handshake against a server with an RSA certificate: cipher `ECDHE-RSA-AES256-SHA`, `Peer signature type: rsa_pkcs1_md5_sha1` (ServerKeyExchange signature with no algorithm field), `Peer Temp Key: X25519`. `run.sh` does not support this variant: it hard-codes `-min_protocol TLSv1.2`.
- Anonymous ciphers: work with `s_server -nocert -tls1_2 -cipher 'aNULL:@SECLEVEL=0'`. Checked: `ADH-AES256-GCM-SHA384` (`Peer Temp Key: DH, 2048 bits`) and `AECDH-AES256-SHA` (`Peer Temp Key: X25519`). `run.sh` does not support this variant: a certificate is always passed.
- TLS compression: the `-comp` flag exists. Whether this build includes zlib was not checked.
- Export ciphers: absent. `openssl ciphers -v 'ALL:COMPLEMENTOFALL:@SECLEVEL=0'` prints no cipher with `EXP`. Needs a docker stand.

SSLv2, SSLv3 and export ciphers are not emulated on `openssl s_server`. The plan does not name images for them, so `tests/docker-compose.yml` has no services for them. The image name and tag are chosen and checked in the task that adds the corresponding stand. ServerKeyExchange parse branches for export-RSA, anonymous ciphers, and a signature with no algorithm (TLS 1.0 and 1.1) are covered in `tls-probe` by synthetic tests. There are no recorded fixtures for them.
