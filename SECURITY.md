# Security

## Authorized use

`certscan` is a TLS and certificate configuration scanner. It is for systems you own, or systems whose owner has given you explicit written permission.

Do not point it at hosts, networks or services you are not authorized to test. The current binary does not open connections. Later versions will open many connections and send non-standard TLS messages. Some planned vulnerability checks are active probes, not passive observation.

This repository does not document how to evade detection, bypass access controls, or scan third-party systems.

## What to report

Report a defect in the parser, the connector, the limiters, or the build if it can crash, hang, mis-parse a local fixture, or open a connection it was not asked to open.

Do not open a public issue that includes:

- a host name, IP address or URL you do not own;
- credentials, private keys, session cookies or live certificates from a system that is not a local stand;
- a request to scan, exploit or bypass a specific third-party service.

A self-signed certificate from `tests/stands/` is fine. Those keys are generated at stand startup and are not secrets.

## How to report

Prefer a private report.

1. Open a [GitHub security advisory](https://github.com/MRX7999/rust-cert-scan/security/advisories/new) if private vulnerability reporting is enabled.
2. Otherwise open a [public issue](https://github.com/MRX7999/rust-cert-scan/issues/new/choose) with no target names and no captured traffic from a host you do not own. Say which commit, OS and Rust version you used, and attach a fixture or a minimized input.

There is no bug-bounty program. A fix, if one is needed, lands in this repository. The project is early: the binary does not scan, so most reports at this stage will be about the codec, the engine limits, or CI.

## Supported versions

| Version | Supported |
|---|---|
| `main` | yes, best-effort |
| tagged releases | only after the first `v*` tag exists |

There is no stability promise on the crate APIs. They are `publish = false`.
