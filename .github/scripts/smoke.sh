#!/usr/bin/env bash
# Run a native release binary and check the Phase 0 contract:
# version prints, help exits 0, a target name is rejected.
set -euo pipefail

if [[ -z "${TARGET:-}" ]]; then
  echo "smoke.sh: TARGET is required" >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ "$TARGET" == *windows* ]]; then
  bin="${root}/target/${TARGET}/release/certscan.exe"
else
  bin="${root}/target/${TARGET}/release/certscan"
fi

if [[ ! -f "$bin" ]]; then
  echo "smoke.sh: missing binary: ${bin}" >&2
  exit 1
fi

ver="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${root}/Cargo.toml" | head -n 1)"
if [[ -z "$ver" ]]; then
  echo "smoke.sh: version not found in Cargo.toml" >&2
  exit 1
fi

out="$("$bin" --version | tr -d '\r')"
if [[ "$out" != "certscan ${ver}" ]]; then
  echo "smoke.sh: unexpected version output: ${out}" >&2
  exit 1
fi

"$bin" --help >/dev/null

set +e
"$bin" example.com >/dev/null 2>&1
code=$?
set -e
if [[ "$code" -eq 0 ]]; then
  echo "smoke.sh: a target name exited 0; scanning must not look successful" >&2
  exit 1
fi

echo "smoke.sh: ${TARGET} ok (${out}, rejected target with ${code})"
