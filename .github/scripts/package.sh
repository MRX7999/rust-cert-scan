#!/usr/bin/env bash
# Package a release binary built with:
#   cargo build --release --locked -p cli --target "$TARGET"
#
# Required: TARGET
# Optional: REF_NAME (tag, or a 40-character commit sha which is shortened)
# Writes dist/<archive> and dist/<archive>.sha256 in the current directory.
set -euo pipefail

if [[ -z "${TARGET:-}" ]]; then
  echo "package.sh: TARGET is required" >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
label="${REF_NAME:-dev}"
if [[ "$label" =~ ^[0-9a-fA-F]{40}$ ]]; then
  label="${label:0:12}"
fi
# Tags and branch names may contain slashes. Archive names must not.
label="${label//\//-}"

name="certscan-${label}-${TARGET}"
if [[ "$TARGET" == *windows* ]]; then
  bin="certscan.exe"
  archive="${name}.zip"
else
  bin="certscan"
  archive="${name}.tar.gz"
fi

src="${root}/target/${TARGET}/release/${bin}"
if [[ ! -f "$src" ]]; then
  echo "package.sh: missing binary: ${src}" >&2
  exit 1
fi

for required in LICENSE README.md SECURITY.md; do
  if [[ ! -f "${root}/${required}" ]]; then
    echo "package.sh: missing ${required}" >&2
    exit 1
  fi
done
notice="${root}/crates/tls-data/data/testssl/NOTICE.md"
if [[ ! -f "$notice" ]]; then
  echo "package.sh: missing ${notice}" >&2
  exit 1
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "${stage}/${name}" "dist"
cp "$src" "${stage}/${name}/"
cp "${root}/LICENSE" "${root}/README.md" "${root}/SECURITY.md" "${stage}/${name}/"
cp "$notice" "${stage}/${name}/NOTICE-testssl.md"

(
  cd "$stage"
  if [[ "$archive" == *.zip ]]; then
    if command -v 7z >/dev/null 2>&1; then
      7z a -tzip "${root}/dist/${archive}" "$name" >/dev/null
    else
      python3 - "$name" "${root}/dist/${archive}" <<'PY'
import os
import sys
import zipfile

name, archive = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
    for dirpath, _, files in os.walk(name):
        for filename in files:
            path = os.path.join(dirpath, filename)
            zf.write(path)
PY
    fi
  else
    tar -czf "${root}/dist/${archive}" "$name"
  fi
)

(
  cd "${root}/dist"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$archive" > "${archive}.sha256"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$archive" > "${archive}.sha256"
  else
    echo "package.sh: need sha256sum or shasum" >&2
    exit 1
  fi
  ls -l "$archive" "${archive}.sha256"
)
