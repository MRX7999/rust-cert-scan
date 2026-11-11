#!/usr/bin/env bash
# Стенд openssl-basic: openssl s_server с TLS 1.2 и TLS 1.3 и самоподписанным
# сертификатом (по умолчанию ECDSA P-256). Ключ и сертификат генерируются при
# каждом запуске.
# Переменные окружения:
#   STAND_BIND           адрес прослушивания (по умолчанию 127.0.0.1)
#   STAND_PORT           порт (по умолчанию 4433)
#   STAND_TMP            каталог для ключа и сертификата (по умолчанию .tmp рядом со скриптом)
#   STAND_MAX_SEND_FRAG  наибольший размер отправляемого фрагмента записи
#                        (s_server -max_send_frag, от 512 до 16384); по умолчанию
#                        параметр не передаётся
#   STAND_EXTRA_SAN      дополнительные записи subjectAltName, см. gen-cert.sh
#   STAND_KEY_TYPE       тип ключа сертификата (ecdsa или rsa), см. gen-cert.sh
#   STAND_CIPHER         список шифров TLS 1.2 и ниже в синтаксисе OpenSSL
#                        (s_server -cipher), например DHE-RSA-AES256-GCM-SHA384;
#                        по умолчанию параметр не передаётся. Параметры DH
#                        сервер выбирает сам (без -dhparam)
# Варианты стенда — с фрагментацией handshake-сообщений (Certificate в
# нескольких записях) и с RSA-сертификатом и шифром DHE-RSA — описаны в
# tests/stands/README.md.
# Остановка: Ctrl+C.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE}")" && pwd)"
bind_addr="${STAND_BIND:-127.0.0.1}"
port="${STAND_PORT:-4433}"
tmp_dir="${STAND_TMP:-${script_dir}/.tmp}"

frag_args=()
if [ -n "${STAND_MAX_SEND_FRAG:-}" ]; then
    case "${STAND_MAX_SEND_FRAG}" in
        *[!0-9]*)
            echo "openssl-basic: STAND_MAX_SEND_FRAG должен быть целым числом" >&2
            exit 1
            ;;
    esac
    frag_args=(-max_send_frag "${STAND_MAX_SEND_FRAG}")
fi

cipher_args=()
if [ -n "${STAND_CIPHER:-}" ]; then
    case "${STAND_CIPHER}" in
        *[!A-Za-z0-9:@=_+-]*)
            echo "openssl-basic: STAND_CIPHER содержит недопустимые символы" >&2
            exit 1
            ;;
    esac
    cipher_args=(-cipher "${STAND_CIPHER}")
fi

STAND_TMP="${tmp_dir}" "${script_dir}/gen-cert.sh"

echo "openssl-basic: $(openssl version), слушаю ${bind_addr}:${port}" >&2

exec openssl s_server \
    -accept "${bind_addr}:${port}" \
    -cert "${tmp_dir}/server.crt" \
    -key "${tmp_dir}/server.key" \
    -min_protocol TLSv1.2 \
    -max_protocol TLSv1.3 \
    -www \
    ${frag_args[@]+"${frag_args[@]}"} \
    ${cipher_args[@]+"${cipher_args[@]}"}
