#!/usr/bin/env bash
# Генерирует тестовый ключ (по умолчанию ECDSA P-256) и самоподписанный
# сертификат для стенда openssl-basic. Файлы создаются на лету во временном
# каталоге и в репозиторий не попадают (.gitignore: /tests/stands/*/.tmp/).
# Переменные окружения:
#   STAND_TMP        каталог для server.key и server.crt (по умолчанию .tmp рядом со скриптом)
#   STAND_KEY_TYPE   тип ключа сертификата: ecdsa (по умолчанию, P-256) или rsa
#                    (RSA 2048); rsa нужен варианту стенда с шифром DHE-RSA
#   STAND_EXTRA_SAN  дополнительные записи subjectAltName через запятую, например
#                    "DNS:a.localhost,DNS:b.localhost"; нужны варианту стенда с
#                    фрагментацией, чтобы Certificate не помещался в одну запись
# Нужен OpenSSL 3.0 или новее (параметр -noenc).
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE}")" && pwd)"
out_dir="${STAND_TMP:-${script_dir}/.tmp}"

if ! command -v openssl >/dev/null 2>&1; then
    echo "gen-cert: openssl не найден в PATH" >&2
    exit 1
fi

san="DNS:localhost,IP:127.0.0.1"
if [ -n "${STAND_EXTRA_SAN:-}" ]; then
    san="${san},${STAND_EXTRA_SAN}"
fi

case "${STAND_KEY_TYPE:-ecdsa}" in
    ecdsa)
        key_args=(-newkey ec -pkeyopt ec_paramgen_curve:P-256)
        ;;
    rsa)
        key_args=(-newkey rsa:2048)
        ;;
    *)
        echo "gen-cert: STAND_KEY_TYPE должен быть ecdsa или rsa" >&2
        exit 1
        ;;
esac

umask 077
mkdir -p "${out_dir}"

openssl req -x509 "${key_args[@]}" -noenc \
    -keyout "${out_dir}/server.key" \
    -out "${out_dir}/server.crt" \
    -days 30 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=${san}"

echo "gen-cert: ключ и сертификат записаны в ${out_dir}" >&2
