# Rust-Cert-Scan

`certscan` — сканер конфигурации TLS и сертификатов на Rust, порт [testssl.sh](https://github.com/testssl/testssl.sh). Результаты выдаются только в JSON и NDJSON.

## Назначение

- покрыть проверки testssl.sh на уровне результата: протоколы, шифры, forward secrecy, сертификаты, известные уязвимости, HTTP-заголовки, STARTTLS;
- массовые сканы с жёсткими лимитами на соединения, скорость и память;
- минимум соединений на хост за счёт общего кэша фактов.

Архитектура описана в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), план работ — в [docs/PLAN.md](docs/PLAN.md), принятые решения — в [docs/DECISIONS.md](docs/DECISIONS.md).

## Статус

Ранняя разработка, Фаза 0: каркас workspace, линты, CI, заготовки xtask, фаззинга и тестовых стендов. Сканирование не реализовано; бинарник пока только печатает версию.

## Только для собственных и авторизованных систем

Сканер открывает множество соединений и отправляет нестандартные TLS-сообщения, а часть проверок уязвимостей является активной. Используйте его только на системах, которые принадлежат вам, или на которые у вас есть явное письменное разрешение владельца. Сканирование чужих систем без разрешения может быть незаконным.

## Сборка

Нужен stable toolchain Rust не ниже 1.96 (см. `rust-toolchain.toml` и `rust-version` в `Cargo.toml`).

```sh
cargo build --workspace
cargo run -p cli -- --version
cargo build --release -p cli    # бинарник: target/release/certscan
```

Проверки перед коммитом:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

`cargo deny` и `cargo audit` ставятся отдельно: `cargo install cargo-deny cargo-audit`.

Служебные команды — `cargo xtask <подкоманда>`, список выводит `cargo xtask --help`. `cargo xtask ci` последовательно запускает fmt, clippy и test; `cargo xtask update-data` обновляет снимки реестров IANA в `crates/tls-data/data/iana/` (нужны `curl` и сеть); `schema` объявлена, но ещё не реализована.

Фаззинг: цели cargo-fuzz лежат в `fuzz/` (отдельный workspace, нужен nightly), установка и запуск описаны в [fuzz/README.md](fuzz/README.md).

Тестовые стенды: локальные серверы для интеграционных тестов слушают только `127.0.0.1`, запуск описан в [tests/README.md](tests/README.md), формат байтовых фикстур — в [tests/fixtures/README.md](tests/fixtures/README.md).

## Структура workspace

| Крейт | Назначение |
|---|---|
| `crates/tls-data` | таблицы IANA и дополнения |
| `crates/tls-probe` | wire-формат TLS без I/O |
| `crates/tls-session` | key schedule TLS 1.3, handshake TLS 1.0–1.2 |
| `crates/net` | connector: TCP, DNS-кэш, proxy, STARTTLS, таймауты |
| `crates/x509-check` | сертификаты, цепочки, trust stores, OCSP/CRL |
| `crates/checks` | проверки и общий trait |
| `crates/engine` | цели, планировщик, лимиты, backoff, checkpoint |
| `crates/output` | типы результата, JSON и NDJSON |
| `crates/cli` | интерфейс командной строки, бинарник `certscan` |

## Лицензия

GPL-2.0-only, полный текст — в файле [LICENSE](LICENSE).

Проект является производной работой от [testssl.sh](https://github.com/testssl/testssl.sh), который распространяется под GPLv2.
В репозитории без изменений хранится файл testssl.sh `etc/cipher-mapping.txt` (`crates/tls-data/data/testssl/`, GPLv2, решение D-01); версия, коммит и sha256 записаны в [crates/tls-data/data/SOURCES.md](crates/tls-data/data/SOURCES.md).
