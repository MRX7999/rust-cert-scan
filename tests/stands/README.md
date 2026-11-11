# Стенды

Локальные TLS-серверы для интеграционных тестов certscan (`docs/PLAN.md`, P0-06). Общая раскладка каталога `tests/` и правила для новых стендов — в [../README.md](../README.md).

## Состав

| Стенд | Адрес | Конфигурация | Способы запуска |
|---|---|---|---|
| `openssl-basic` | `127.0.0.1:4433` | `openssl s_server -www`, TLS 1.2 и TLS 1.3 (`-min_protocol TLSv1.2 -max_protocol TLSv1.3`), самоподписанный сертификат ECDSA P-256, `CN=localhost`, SAN `DNS:localhost`, `IP:127.0.0.1`, срок 30 дней | `run.sh` напрямую; сервис `openssl-basic` в `tests/docker-compose.yml` |

Других стендов в Фазе 0 нет: P0-06 требует один. Стенды с уязвимыми конфигурациями появляются в следующих фазах вместе с проверками, которым они нужны.

## Запуск и остановка

Напрямую, нужен OpenSSL 3.0 или новее в `PATH`. Сервер работает на переднем плане, остановка — Ctrl+C:

```sh
tests/stands/openssl-basic/run.sh
```

В фоне, с остановкой по PID:

```sh
tests/stands/openssl-basic/run.sh &
STAND_PID=$!
kill "$STAND_PID"
```

Через docker compose:

```sh
docker compose -f tests/docker-compose.yml up -d openssl-basic
docker compose -f tests/docker-compose.yml down
```

Проверка соединения:

```sh
openssl s_client -connect 127.0.0.1:4433 -brief </dev/null
```

Переменные окружения `run.sh`: `STAND_BIND` (по умолчанию `127.0.0.1`), `STAND_PORT` (`4433`), `STAND_TMP` (каталог ключа и сертификата, по умолчанию `.tmp/` рядом со скриптом, в `.gitignore`), `STAND_MAX_SEND_FRAG` и `STAND_EXTRA_SAN` (раздел «Вариант с фрагментацией»), `STAND_KEY_TYPE` и `STAND_CIPHER` (раздел «Вариант с RSA-сертификатом и DHE-RSA»). Ключ и сертификат создаются заново при каждом запуске и в репозиторий не попадают.

## Вариант с фрагментацией

Тот же стенд `openssl-basic`, запущенный на порту `4434` с двумя дополнительными переменными. Нужен, чтобы handshake-сообщение Certificate пришло в нескольких записях (склейка в `Decoder`, сценарий `tls12-fragmented` подкоманды `record-fixture`).

| Переменная | Действие |
|---|---|
| `STAND_MAX_SEND_FRAG` | передаётся в `s_server -max_send_frag`: наибольший размер отправляемого фрагмента записи, от 512 до 16384. `run.sh` проверяет только то, что значение — целое число; диапазон проверяет сам OpenSSL. Без переменной параметр не передаётся |
| `STAND_EXTRA_SAN` | дополнительные записи `subjectAltName` через запятую, `gen-cert.sh` дописывает их к `DNS:localhost,IP:127.0.0.1`. Увеличивают сертификат, чтобы Certificate не помещался в одну запись длиной 512 байт |

Запуск (значения те же, что в `[source].server_command` фикстуры `tls12-serverhello-openssl-basic-max-send-frag`):

```sh
STAND_PORT=4434 STAND_MAX_SEND_FRAG=512 \
STAND_EXTRA_SAN="DNS:fragment-padding-01.stand.localhost,DNS:fragment-padding-02.stand.localhost,DNS:fragment-padding-03.stand.localhost,DNS:fragment-padding-04.stand.localhost,DNS:fragment-padding-05.stand.localhost,DNS:fragment-padding-06.stand.localhost,DNS:fragment-padding-07.stand.localhost,DNS:fragment-padding-08.stand.localhost" \
tests/stands/openssl-basic/run.sh
```

Запись фикстур с этого варианта:

```sh
cargo xtask record-fixture --addr 127.0.0.1:4434 --scenario tls12-fragmented \
  --stand openssl-basic --server "$(openssl version)"
```

Вариант использует тот же каталог `STAND_TMP`, что и основной стенд. Чтобы держать оба одновременно, задайте варианту отдельный `STAND_TMP`, иначе второй запуск перезапишет ключ и сертификат первого (уже запущенному серверу это не мешает: файлы он прочитал при старте).

## Вариант с RSA-сертификатом и DHE-RSA

Тот же стенд `openssl-basic`, запущенный на порту `4435` с RSA-сертификатом и одним шифром TLS 1.2. Нужен, чтобы получить ServerKeyExchange с параметрами DH (`p`, `g`, `Ys`) и подписью RSA (разбор в `tls-probe`, P1-07; сценарий `tls12-dhe-rsa` подкоманды `record-fixture`).

| Переменная | Действие |
|---|---|
| `STAND_KEY_TYPE` | тип ключа сертификата: `ecdsa` (по умолчанию, P-256) или `rsa` (RSA 2048). Другое значение — ошибка `gen-cert.sh` |
| `STAND_CIPHER` | передаётся в `s_server -cipher`: список шифров TLS 1.2 и ниже в синтаксисе OpenSSL. `run.sh` проверяет только набор символов; сам список проверяет OpenSSL. На шифры TLS 1.3 не влияет. Без переменной параметр не передаётся |

Параметры DH стенд не задаёт (`-dhparam` не передаётся): сервер выбирает их сам, в журнале `s_server` это строка `Using default temp DH parameters`.

Запуск (значения те же, что в `[source].server_command` фикстуры `tls12-serverhello-openssl-basic-dhe-rsa`; отдельный `STAND_TMP` нужен, только если одновременно работает другой вариант):

```sh
STAND_PORT=4435 STAND_KEY_TYPE=rsa STAND_CIPHER=DHE-RSA-AES256-GCM-SHA384 \
tests/stands/openssl-basic/run.sh
```

Запись фикстур с этого варианта:

```sh
cargo xtask record-fixture --addr 127.0.0.1:4435 --scenario tls12-dhe-rsa \
  --stand openssl-basic --server "$(openssl version)"
```

Эталон для сверки значений в тестах:

```sh
openssl s_client -connect 127.0.0.1:4435 -tls1_2 -cipher DHE-RSA-AES256-GCM-SHA384 </dev/null
```

## Что проверено запуском

Проверка 2026-11-11, macOS arm64, `OpenSSL 4.1.0 23 Oct 2026` из Homebrew (`/opt/homebrew/bin/openssl`).

| Что | Результат |
|---|---|
| `run.sh` напрямую | проверено: `lsof` показывает прослушивание только на `127.0.0.1:4433` |
| Соединение TLS 1.2 | проверено: `s_client -tls1_2`, выбран `ECDHE-ECDSA-AES256-GCM-SHA384` |
| Соединение TLS 1.3 | проверено: `s_client -tls1_3`, выбран `TLS_AES_256_GCM_SHA384` |
| Остановка | проверено: после `kill` порт 4433 свободен |
| Ключи вне git | проверено: `git status --short` не показывает содержимое `.tmp/` |
| Вариант с фрагментацией (`127.0.0.1:4434`, `STAND_MAX_SEND_FRAG=512`, восемь дополнительных SAN) | проверено записью фикстуры `tls12-serverhello-openssl-basic-max-send-frag` (902 байта, шифр `0xc02c`, итог `server_hello_done`): подкоманда `record-fixture` при записи убедилась, что handshake-сообщение занимает несколько записей (`handshake_message_spans_records = "true"` в `[source.conditions]`) |
| Вариант с RSA-сертификатом и DHE-RSA (`127.0.0.1:4435`, `STAND_KEY_TYPE=rsa`, `STAND_CIPHER=DHE-RSA-AES256-GCM-SHA384`, отдельный `STAND_TMP`) | проверено: `s_client -tls1_2 -cipher DHE-RSA-AES256-GCM-SHA384` показал `Cipher is DHE-RSA-AES256-GCM-SHA384`, `Peer Temp Key: DH, 2048 bits`, `Peer signature type: rsa_pss_rsae_sha256`, `Server public key is 2048 bit`; записана фикстура `tls12-serverhello-openssl-basic-dhe-rsa` (1650 байт, шифр `0x009f`, итог `server_hello_done`); после `kill` порт 4435 свободен |
| Другие значения `STAND_MAX_SEND_FRAG`, `STAND_CIPHER` и одновременная работа нескольких вариантов | не проверялись |
| Отказ в TLS 1.1 и ниже | не проверено: `s_client -tls1_1` завершился на стороне клиента (`no protocols available`), до сервера проба не дошла |
| `docker compose up -d openssl-basic` | не запускалось: docker на машине разработки не используется |
| Сборка `Dockerfile` | не проверялась; базовый образ `alpine:3` не скачивался |
| `shellcheck` для `run.sh` и `gen-cert.sh` | не запускался |

При проверке в логе сервера появилась одна запись `ssl3_read_bytes:unexpected message`. Обе пробы при этом завершились успешно, причина записи не выяснялась.

## Ограничения этой сборки OpenSSL

Выводы по SSLv2, SSLv3 и сжатию сделаны по `openssl s_server -help`, эти конфигурации не запускались. Остальные пункты проверены 2026-11-11 разовым запуском `openssl s_server` на `127.0.0.1:4436` и `127.0.0.1:4437` (не через `run.sh`) и `openssl s_client`; серверы после проверки остановлены, фикстуры не записывались.

- SSLv2: параметра нет, протокол не поддерживается. Нужен docker-стенд со старой сборкой OpenSSL.
- SSLv3: параметра `-ssl3` у `s_server` нет. Нужен docker-стенд.
- TLS 1.0 и TLS 1.1: работают при `-min_protocol TLSv1` и списке шифров с `@SECLEVEL=0` на обеих сторонах. `s_client -tls1` и `s_client -tls1_1` к серверу с RSA-сертификатом завершили рукопожатие: шифр `ECDHE-RSA-AES256-SHA`, `Peer signature type: rsa_pkcs1_md5_sha1` (подпись ServerKeyExchange без поля алгоритма), `Peer Temp Key: X25519`. `run.sh` такой вариант не поддерживает: в нём жёстко задано `-min_protocol TLSv1.2`.
- Анонимные шифры: работают при `s_server -nocert -tls1_2 -cipher 'aNULL:@SECLEVEL=0'`. Проверены `ADH-AES256-GCM-SHA384` (`Peer Temp Key: DH, 2048 bits`) и `AECDH-AES256-SHA` (`Peer Temp Key: X25519`). `run.sh` такой вариант не поддерживает: сертификат передаётся всегда.
- Сжатие TLS: параметр `-comp` есть, наличие zlib в сборке не проверялось.
- Export-шифры: отсутствуют, `openssl ciphers -v 'ALL:COMPLEMENTOFALL:@SECLEVEL=0'` не выводит ни одного шифра с `EXP`. Нужен docker-стенд.

SSLv2, SSLv3 и export-шифры на `openssl s_server` не эмулируются. Образы для них в плане не названы, поэтому сервисы в `tests/docker-compose.yml` для них не заведены; имя и тег образа выбираются и проверяются в задаче, которая добавляет соответствующий стенд. Ветки разбора ServerKeyExchange для export-RSA, анонимных шифров и подписи без алгоритма (TLS 1.0 и 1.1) в `tls-probe` покрыты синтетическими тестами; записанных фикстур для них нет.
