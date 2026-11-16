# Происхождение данных tls-data

> English: vendored snapshots. Do not edit the table between the `iana:begin` and `iana:end` markers by hand; `cargo xtask update-data` rewrites it, including the Russian column headers. The cipher map is pinned to a commit and is not refreshed by that command. See [docs/README.md](../../../docs/README.md).

Все файлы в этом каталоге — снимки внешних источников, сохранённые без правок. `build.rs` читает только их и к сети не обращается.

## Реестры IANA

Источник: группы реестров [Transport Layer Security (TLS) Parameters](https://www.iana.org/assignments/tls-parameters/) и [Transport Layer Security (TLS) Extensions](https://www.iana.org/assignments/tls-extensiontype-values/).

Таблицу ниже перезаписывает `cargo xtask update-data`: команда скачивает снимки, пересчитывает sha256, размер и число строк. Столбец «Last Updated» — дата с индексной страницы группы реестров на момент загрузки; в самих CSV этой даты нет.

<!-- iana:begin (блок перезаписывает cargo xtask update-data) -->
| Файл | Реестр | URL | Дата загрузки (UTC) | sha256 | Размер, байт | Строк | Last Updated |
|---|---|---|---|---|---|---|---|
| `iana/tls-parameters-4.csv` | TLS Cipher Suites | <https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv> | 2026-11-11 | `949ed87e901bb77314a96ad5a7b78c0b4b38ec56d16425efa2057a2efbd1570f` | 30018 | 455 | 2026-11-05 |
| `iana/tls-parameters-6.csv` | TLS Alerts | <https://www.iana.org/assignments/tls-parameters/tls-parameters-6.csv> | 2026-11-11 | `fbceabdb7bc783af630fb2500ff500525358edf8dec1702a3db40840d1725866` | 2049 | 51 | 2026-11-05 |
| `iana/tls-parameters-8.csv` | TLS Supported Groups | <https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv> | 2026-11-11 | `d35959b23d588f8b4daa038788f168227cc1e909500a8a4d8412b0f6aeffbc17` | 5653 | 106 | 2026-11-05 |
| `iana/tls-signaturescheme.csv` | TLS SignatureScheme | <https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv> | 2026-11-11 | `df70d06b074d8ef96d978ac83f5b3e232d04b59bb88a986dbc73a2242513dbf9` | 26528 | 564 | 2026-11-05 |
| `iana/tls-extensiontype-values-1.csv` | TLS ExtensionType Values | <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv> | 2026-11-11 | `604ba20c430663a611c6ecead55bf7fbbf768b10d90f7d551abc669f2e9cb879` | 4937 | 105 | 2026-11-09 |
<!-- iana:end -->

Реестры ALPN Protocol IDs и TLS HandshakeType в снимки не входят: P1-01 их не требует.

## testssl.sh

Источник: репозиторий <https://github.com/testssl/testssl.sh>, лицензия GPLv2 (см. [testssl/NOTICE.md](testssl/NOTICE.md) и решение D-01 в `docs/DECISIONS.md`). Файл скачан по хешу коммита, а не по имени ветки, и обновляется вручную вместе с этой записью; `cargo xtask update-data` его не трогает.

| Файл | Путь в репозитории | Тег | Коммит | URL | Дата загрузки (UTC) | sha256 | Размер, байт | Строк |
|---|---|---|---|---|---|---|---|---|
| `testssl/cipher-mapping.txt` | `etc/cipher-mapping.txt` | `v3.2.5` (голова ветки `3.2` на дату загрузки) | `4f17be931a9d60f3f987975aea8221f1a8eaf7aa` | <https://raw.githubusercontent.com/testssl/testssl.sh/4f17be931a9d60f3f987975aea8221f1a8eaf7aa/etc/cipher-mapping.txt> | 2026-11-11 | `7a5efe10907d68de2c4c9ac29e9944817fa647e6c4e5673e16ec9cf20b54d944` | 71389 | 372 |

Другие файлы testssl.sh (`client-simulation.txt`, DH primes, trust stores) относятся к задачам P2-03 и P3-10 и здесь пока отсутствуют.

## Проверка целостности

```sh
shasum -a 256 crates/tls-data/data/iana/*.csv crates/tls-data/data/testssl/cipher-mapping.txt
```
