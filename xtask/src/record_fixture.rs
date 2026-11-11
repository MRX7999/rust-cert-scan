//! Подкоманда `record-fixture`: запись байтовых фикстур с локального стенда.
//!
//! Собирает ClientHello билдером `tls-probe`, отправляет его на заданный
//! адрес и читает ответ до итога обмена, которого ждёт сценарий:
//!
//! - `tls12` — ServerHelloDone;
//! - `tls12-fragmented` — тот же ClientHello к варианту стенда с
//!   `-max_send_frag`: ServerHelloDone, причём хотя бы одно
//!   handshake-сообщение разбито между записями;
//! - `tls13` — первая зашифрованная запись;
//! - `tls13-hrr` — HelloRetryRequest, затем второй ClientHello с `key_share`
//!   для запрошенной группы (те же `random`, `session_id` и шифры) и чтение
//!   до первой зашифрованной записи после второго ServerHello;
//! - `no-shared-cipher` — alert `handshake_failure` уровня fatal.
//!
//! Если фактический итог не совпал с ожидаемым (таймаут, закрытие
//! соединения, ошибка разбора, превышение объёма, другой alert), подкоманда
//! завершается с ненулевым кодом и ничего не пишет. `--force` разрешает
//! запись при несовпадении: в `.meta.toml` тогда попадает фактический итог, а
//! ожидаемые поля сценария и условия стенда не пишутся.
//!
//! Имена файлов при записи с `--force` отражают фактическое содержимое. В
//! сценарии `tls13-hrr`, если второй ClientHello был отправлен, ответ
//! делится так же, как при совпавшем итоге: байты до второго ClientHello
//! идут в фикстуру `tls13-hrr-…`, весь поток — в `tls13-serverhello-…-after-hrr`,
//! то есть перезаписываются обе серверные фикстуры и устаревшей пары не
//! остаётся. Если второй ClientHello отправлен не был (сервер не ответил
//! HelloRetryRequest либо запросил то, что подкоманда не умеет), ответ не
//! является обменом с HRR: под именами сценария он не записывается даже с
//! `--force`, подкоманда отказывает с ошибкой и ничего не пишет. Удалять
//! существующую пару `…-after-hrr` подкоманда не стала бы и в этом случае:
//! на неё ссылаются тесты через `include_str!`.
//!
//! Превышение объёма ответа даёт один итог — `too_large`: декодер создаётся
//! с `max_total_bytes`, равным пределу подкоманды, и его ошибка
//! `LimitExceeded` по этому лимиту переводится в тот же итог, что и
//! проверка числа принятых байтов.
//!
//! Время: `--timeout-ms` ограничивает соединение и каждое отдельное чтение,
//! а весь обмен, считая соединение, длится не дольше трёх таких таймаутов:
//! таймаут каждого чтения и записи ограничен остатком до общего дедлайна.
//!
//! Фикстуры сохраняются в формате `tests/fixtures/README.md`: отправленный
//! ClientHello (`direction = "client"`) и ответ сервера
//! (`direction = "server"` со ссылкой `request`). Сценарий `tls13-hrr` пишет
//! четыре фикстуры: первый ClientHello, ответ на него (HRR и CCS), второй
//! ClientHello и полный поток сервера, который ссылается на второй запрос
//! полями `second_request` и `second_request_offset`. В ответ попадают
//! только байты до шифрования; исключение — полный поток `tls13-hrr`, в
//! который входит первая зашифрованная запись после второго ServerHello.
//!
//! Существующие фикстуры без `--force` не перезаписываются. Файлы одной
//! записи сначала пишутся под временными именами и затем переименовываются.
//! Переименование группы файлов не атомарно, см. комментарий у
//! `write_fixtures`.
//!
//! Подкоманда принимает только loopback-адреса (127.0.0.0/8 и ::1), заданные
//! IP-литералом; имена не разрешаются. Сетевой код для реальных целей — это
//! крейт `net` (P1-10), а не xtask.
//!
//! Значения `[expected]` в `.meta.toml` берутся из конфигурации сценария и
//! стенда, а не из вывода парсера; то, что парсер увидел на самом деле,
//! печатается в stderr для сверки. Версию сервера задаёт параметр
//! `--server`: стенд может работать в контейнере, локальный `openssl
//! version` о нём ничего не говорит.

use std::fmt::Write as _;
use std::fs;
use std::io::{ErrorKind, Read, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tls_data::{NamedGroup, SignatureScheme};
use tls_probe::server_hello::RANDOM_LEN;
use tls_probe::{
    Alert, ClientHello, Decoder, EncodeError, Event, Extension, KeyShareEntry, ParseError,
    ParseLimits, ProtocolVersion, Reader, ServerExtension, ServerHello, ServerMessage,
};

/// Справка подкоманды.
const USAGE: &str = "\
Запись фикстур (ClientHello и ответ сервера) с локального стенда.

Использование: cargo xtask record-fixture --addr <ip:порт> --scenario <имя> --server <строка> [параметры]

Сценарии и ожидаемый итог обмена:
  tls12             TLS 1.2 ClientHello -> ServerHello ... ServerHelloDone
  tls12-fragmented  тот же ClientHello к варианту стенда с -max_send_frag
                    (tests/stands/README.md): ServerHelloDone, Certificate
                    разбит на несколько записей
  tls12-dhe-rsa     TLS 1.2 ClientHello с шифрами DHE-RSA к варианту стенда с
                    RSA-сертификатом (tests/stands/README.md): ServerHelloDone,
                    ServerKeyExchange с параметрами DH
  tls13             TLS 1.3 ClientHello с key_share x25519 -> ServerHello,
                    до первой зашифрованной записи
  tls13-hrr         TLS 1.3 ClientHello с пустым key_share -> HelloRetryRequest
                    -> второй ClientHello с key_share x25519 -> ServerHello,
                    до первой зашифрованной записи (четыре фикстуры)
  no-shared-cipher  TLS 1.2 ClientHello только с RSA-шифрами -> alert
                    handshake_failure

Если итог обмена не совпал с ожидаемым, фикстуры не пишутся, код возврата
ненулевой.

Параметры:
  --addr <ip:порт>      адрес стенда; только loopback (127.0.0.0/8, ::1)
  --scenario <имя>      сценарий из списка выше
  --server <строка>     продукт и версия сервера стенда, например вывод
                        `openssl version` в окружении, где запущен стенд
  --out-dir <каталог>   куда писать (по умолчанию crates/tls-probe/tests/fixtures)
  --stand <имя>         имя стенда из tests/stands (по умолчанию openssl-basic)
  --random <hex>        32 байта random для ClientHello (по умолчанию /dev/urandom)
  --key-share <hex>     32 байта публичного значения x25519 (по умолчанию /dev/urandom)
  --timeout-ms <число>  таймаут соединения и одного чтения, от 1 до 60000
                        (по умолчанию 3000); весь обмен, считая соединение,
                        длится не дольше трёх таких таймаутов
  --force               перезаписать существующие фикстуры; записать и при
                        несовпадении итога обмена (в метаданные попадёт
                        фактический итог, ожидаемые поля сценария — нет);
                        в сценарии tls13-hrr без отправленного второго
                        ClientHello запись не выполняется и с --force
  -h, --help            эта справка
";

const EXIT_FAILURE: u8 = 1;
const EXIT_USAGE: u8 = 2;

const DEFAULT_OUT_DIR: &str = "crates/tls-probe/tests/fixtures";
const DEFAULT_STAND: &str = "openssl-basic";
const DEFAULT_TIMEOUT_MS: u64 = 3000;

/// Наибольший таймаут соединения и чтения.
const MAX_TIMEOUT_MS: u64 = 60_000;

/// Во сколько таймаутов укладывается весь обмен, считая соединение.
const EXCHANGE_TIMEOUTS: u32 = 3;

/// Наибольший объём ответа сервера; больше — итог `too_large`. Это же
/// значение передаётся декодеру как `ParseLimits::max_total_bytes`.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Название лимита общего объёма потока в `ParseError::LimitExceeded`.
const TOTAL_BYTES_LIMIT: &str = "max_total_bytes";

/// Длина публичного значения x25519 в байтах (RFC 7748, раздел 5).
const X25519_KEY_LEN: usize = 32;

/// Группа x25519: единственная, для которой сценарий `tls13-hrr` умеет
/// отправить второй ClientHello.
const X25519: NamedGroup = NamedGroup(0x001D);

/// Код расширения `cookie` (RFC 8446, раздел 4.2.2).
const COOKIE_EXTENSION: u16 = 0x002C;

/// Уровень alert `fatal`.
const ALERT_FATAL: u8 = 2;

/// Описание alert `handshake_failure`.
const ALERT_HANDSHAKE_FAILURE: u8 = 40;

/// Тип содержимого записи `handshake`.
const HANDSHAKE_CONTENT_TYPE: u8 = 22;

/// Значение `STAND_MAX_SEND_FRAG` варианта стенда с фрагментацией:
/// наименьшее, которое принимает `openssl s_server -max_send_frag`.
const FRAGMENT_MAX_SEND_FRAG: u32 = 512;

/// Число дополнительных SAN в сертификате варианта стенда с фрагментацией:
/// с ними Certificate не помещается в один фрагмент.
const FRAGMENT_EXTRA_SAN_COUNT: u32 = 8;

/// Порт варианта стенда с RSA-сертификатом и шифром DHE-RSA.
const DHE_RSA_PORT: u16 = 4435;

/// Значение `STAND_CIPHER` варианта стенда с шифром DHE-RSA (код 0x009F).
const DHE_RSA_CIPHER: &str = "DHE-RSA-AES256-GCM-SHA384";

/// Ожидаемые поля полного потока сервера в сценарии `tls13-hrr`.
const RETRY_EXCHANGE_FIELDS: &[(&str, &str)] = &[
    ("legacy_version", "0x0303"),
    ("version", "0x0304"),
    ("cipher_suite", "0x1302"),
    ("compression_method", "0x00"),
    ("hello_retry_request", "false"),
    ("key_share_group", "0x001d"),
    (
        "messages",
        "server_hello (HelloRetryRequest), change_cipher_spec, server_hello, application_data (зашифрована)",
    ),
    ("session_id_len", "32"),
    ("extensions", "0x002b, 0x0033"),
];

/// Сценарий записи: какой ClientHello отправить и чего ждать от стенда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Tls12,
    Tls12Fragmented,
    Tls12DheRsa,
    Tls13,
    Tls13Hrr,
    NoSharedCipher,
}

impl Scenario {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "tls12" => Some(Self::Tls12),
            "tls12-fragmented" => Some(Self::Tls12Fragmented),
            "tls12-dhe-rsa" => Some(Self::Tls12DheRsa),
            "tls13" => Some(Self::Tls13),
            "tls13-hrr" => Some(Self::Tls13Hrr),
            "no-shared-cipher" => Some(Self::NoSharedCipher),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Tls12 => "tls12",
            Self::Tls12Fragmented => "tls12-fragmented",
            Self::Tls12DheRsa => "tls12-dhe-rsa",
            Self::Tls13 => "tls13",
            Self::Tls13Hrr => "tls13-hrr",
            Self::NoSharedCipher => "no-shared-cipher",
        }
    }

    /// Нужен ли сценарию `key_share`: в первом ClientHello (`tls13`) или во
    /// втором (`tls13-hrr`).
    fn uses_key_share(self) -> bool {
        matches!(self, Self::Tls13 | Self::Tls13Hrr)
    }

    /// Сценарий, ClientHello которого отправляется после HelloRetryRequest:
    /// тот же hello, но с `key_share`.
    fn retry_scenario(self) -> Option<Self> {
        (self == Self::Tls13Hrr).then_some(Self::Tls13)
    }

    /// Итог обмена, при котором запись считается состоявшейся.
    fn expected_stop(self) -> Stop {
        match self {
            Self::Tls12 | Self::Tls12Fragmented | Self::Tls12DheRsa => Stop::ServerHelloDone,
            Self::Tls13 => Stop::Encrypted,
            Self::Tls13Hrr => Stop::RetryComplete,
            Self::NoSharedCipher => Stop::Alert {
                level: ALERT_FATAL,
                description: ALERT_HANDSHAKE_FAILURE,
            },
        }
    }

    fn client_fixture(self, stand: &str) -> String {
        match self {
            Self::Tls12 => format!("tls12-clienthello-{stand}"),
            Self::Tls12Fragmented => format!("tls12-clienthello-{stand}-max-send-frag"),
            Self::Tls12DheRsa => format!("tls12-clienthello-{stand}-dhe-rsa"),
            Self::Tls13 => format!("tls13-clienthello-{stand}"),
            Self::Tls13Hrr => format!("tls13-clienthello-{stand}-no-key-share"),
            Self::NoSharedCipher => format!("tls12-clienthello-{stand}-rsa-only"),
        }
    }

    fn server_fixture(self, stand: &str) -> String {
        match self {
            Self::Tls12 => format!("tls12-serverhello-{stand}"),
            Self::Tls12Fragmented => format!("tls12-serverhello-{stand}-max-send-frag"),
            Self::Tls12DheRsa => format!("tls12-serverhello-{stand}-dhe-rsa"),
            Self::Tls13 => format!("tls13-serverhello-{stand}"),
            Self::Tls13Hrr => format!("tls13-hrr-{stand}"),
            Self::NoSharedCipher => format!("tls12-alert-{stand}-no-shared-cipher"),
        }
    }

    /// Имена фикстур второй части обмена: второй ClientHello и полный поток
    /// сервера. Есть только у сценария с HelloRetryRequest.
    fn retry_fixtures(self, stand: &str) -> Option<(String, String)> {
        self.retry_scenario().map(|_| {
            (
                format!("tls13-clienthello-{stand}-after-hrr"),
                format!("tls13-serverhello-{stand}-after-hrr"),
            )
        })
    }

    /// Команда запуска стенда для `.meta.toml`.
    fn server_command(self, stand: &str) -> String {
        let script = format!("tests/stands/{stand}/run.sh");
        match self {
            Self::Tls12Fragmented => {
                let extra_san = (1..=FRAGMENT_EXTRA_SAN_COUNT)
                    .map(|index| format!("DNS:fragment-padding-0{index}.stand.localhost"))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "STAND_PORT=4434 STAND_MAX_SEND_FRAG={FRAGMENT_MAX_SEND_FRAG} STAND_EXTRA_SAN={extra_san} {script}"
                )
            }
            Self::Tls12DheRsa => format!(
                "STAND_PORT={DHE_RSA_PORT} STAND_KEY_TYPE=rsa STAND_CIPHER={DHE_RSA_CIPHER} {script}"
            ),
            Self::Tls12 | Self::Tls13 | Self::Tls13Hrr | Self::NoSharedCipher => script,
        }
    }

    fn client_description(self) -> &'static str {
        match self {
            Self::Tls12 => {
                "ClientHello TLS 1.2: три ECDHE-ECDSA AEAD-шифра и SCSV, без supported_versions"
            }
            Self::Tls12Fragmented => {
                "ClientHello TLS 1.2 для варианта стенда с -max_send_frag: тот же, что в сценарии tls12"
            }
            Self::Tls12DheRsa => {
                "ClientHello TLS 1.2: два DHE-RSA AEAD-шифра и SCSV, без supported_versions"
            }
            Self::Tls13 => "ClientHello TLS 1.3: supported_versions 0x0304, key_share x25519",
            Self::Tls13Hrr => {
                "ClientHello TLS 1.3 с пустым key_share: сервер должен ответить HelloRetryRequest"
            }
            Self::NoSharedCipher => {
                "ClientHello TLS 1.2 только с RSA-шифрами, которых стенд с ECDSA-сертификатом не поддерживает"
            }
        }
    }

    fn server_description(self) -> &'static str {
        match self {
            Self::Tls12 => {
                "Ответ на ClientHello TLS 1.2: ServerHello, Certificate, ServerKeyExchange, ServerHelloDone"
            }
            Self::Tls12Fragmented => {
                "Ответ на ClientHello TLS 1.2 от стенда с -max_send_frag 512: Certificate разбит на несколько записей"
            }
            Self::Tls12DheRsa => {
                "Ответ на ClientHello TLS 1.2 от стенда с RSA-сертификатом и шифром DHE-RSA: ServerHello, Certificate, ServerKeyExchange, ServerHelloDone"
            }
            Self::Tls13 => {
                "Ответ на ClientHello TLS 1.3: ServerHello и ChangeCipherSpec, без зашифрованных записей"
            }
            Self::Tls13Hrr => {
                "Ответ на ClientHello TLS 1.3 без key_share: HelloRetryRequest и ChangeCipherSpec"
            }
            Self::NoSharedCipher => "Ответ на ClientHello без общих шифров: alert",
        }
    }

    fn server_summary(self) -> &'static str {
        match self {
            Self::Tls12 => {
                "ServerHello TLS 1.2 с первым шифром из списка клиента, затем Certificate, ServerKeyExchange и ServerHelloDone"
            }
            Self::Tls12Fragmented => {
                "ServerHello TLS 1.2, Certificate, собранный из нескольких записей, ServerKeyExchange и ServerHelloDone"
            }
            Self::Tls12DheRsa => {
                "ServerHello TLS 1.2 с шифром DHE-RSA, затем Certificate с RSA-сертификатом, ServerKeyExchange с параметрами DH (p, g, Ys) и подписью, ServerHelloDone"
            }
            Self::Tls13 => {
                "ServerHello с supported_versions = TLS 1.3 и key_share x25519, не HelloRetryRequest; затем ChangeCipherSpec"
            }
            Self::Tls13Hrr => {
                "HelloRetryRequest (random из RFC 8446, раздел 4.1.3) с supported_versions = TLS 1.3 и key_share с группой без ключа; затем ChangeCipherSpec"
            }
            Self::NoSharedCipher => "alert уровня fatal с описанием handshake_failure",
        }
    }

    /// Ожидаемые поля ответа по конфигурации сценария и стенда.
    fn server_fields(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Tls12 => &[
                ("legacy_version", "0x0303"),
                ("version", "0x0303"),
                ("cipher_suite", "0xc02c"),
                ("compression_method", "0x00"),
                ("hello_retry_request", "false"),
                (
                    "messages",
                    "server_hello, certificate, server_key_exchange, server_hello_done",
                ),
                ("session_id_len", "0"),
                ("downgrade_marker", "tls12"),
                ("extensions", "0xff01, 0x000b, 0x0023, 0x0017"),
            ],
            Self::Tls12Fragmented => &[
                ("legacy_version", "0x0303"),
                ("version", "0x0303"),
                ("cipher_suite", "0xc02c"),
                ("compression_method", "0x00"),
                ("hello_retry_request", "false"),
                (
                    "messages",
                    "server_hello, certificate, server_key_exchange, server_hello_done",
                ),
                ("session_id_len", "0"),
                ("downgrade_marker", "tls12"),
                ("extensions", "0xff01, 0x000b, 0x0023, 0x0017"),
            ],
            // Шифр не использует эллиптические кривые, поэтому сервер не
            // отправляет ec_point_formats (0x000b).
            Self::Tls12DheRsa => &[
                ("legacy_version", "0x0303"),
                ("version", "0x0303"),
                ("cipher_suite", "0x009f"),
                ("compression_method", "0x00"),
                ("hello_retry_request", "false"),
                (
                    "messages",
                    "server_hello, certificate, server_key_exchange, server_hello_done",
                ),
                ("session_id_len", "0"),
                ("downgrade_marker", "tls12"),
                ("extensions", "0xff01, 0x0023, 0x0017"),
            ],
            Self::Tls13 => &[
                ("legacy_version", "0x0303"),
                ("version", "0x0304"),
                ("cipher_suite", "0x1302"),
                ("compression_method", "0x00"),
                ("hello_retry_request", "false"),
                ("key_share_group", "0x001d"),
                ("messages", "server_hello, change_cipher_spec"),
                ("session_id_len", "32"),
                ("extensions", "0x002b, 0x0033"),
            ],
            Self::Tls13Hrr => &[
                ("legacy_version", "0x0303"),
                ("version", "0x0304"),
                ("cipher_suite", "0x1302"),
                ("compression_method", "0x00"),
                ("hello_retry_request", "true"),
                ("key_share_group", "0x001d"),
                (
                    "messages",
                    "server_hello (HelloRetryRequest), change_cipher_spec",
                ),
                ("session_id_len", "32"),
                ("extensions", "0x002b, 0x0033"),
            ],
            Self::NoSharedCipher => &[
                ("alert_level", "2 (fatal)"),
                ("alert_description", "40 (handshake_failure)"),
            ],
        }
    }

    /// Условия записи ответа сервера для секции `[source.conditions]`:
    /// параметры варианта стенда и свойства потока, проверенные при записи.
    /// Это не ожидаемый результат разбора, поэтому в `[expected.fields]` они
    /// не попадают.
    fn stand_conditions(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Tls12Fragmented => &[
                ("max_send_frag", "512"),
                ("handshake_message_spans_records", "true"),
            ],
            Self::Tls12DheRsa => &[("key_type", "rsa"), ("cipher", DHE_RSA_CIPHER)],
            Self::Tls12 | Self::Tls13 | Self::Tls13Hrr | Self::NoSharedCipher => &[],
        }
    }

    /// Собирает ClientHello сценария. `session_id` для TLS 1.3 выводится из
    /// `random` (побитовое отрицание), чтобы запись воспроизводилась по
    /// аргументам команды.
    fn build(
        self,
        random: [u8; RANDOM_LEN],
        key_share: &[u8; X25519_KEY_LEN],
    ) -> Result<ClientHello, EncodeError> {
        let session_id: Vec<u8> = random.iter().map(|byte| !byte).collect();
        let groups = [X25519, NamedGroup(0x0017), NamedGroup(0x0018)];
        let schemes = [
            SignatureScheme(0x0403),
            SignatureScheme(0x0503),
            SignatureScheme(0x0804),
            SignatureScheme(0x0805),
            SignatureScheme(0x0401),
            SignatureScheme(0x0501),
        ];
        let base = ClientHello::new(random);
        let hello = match self {
            Self::Tls12 | Self::Tls12Fragmented => base
                .with_cipher_suites([0xC02C_u16, 0xC02B, 0xCCA9, 0x00FF])
                .with_extensions([
                    Extension::server_name(b"localhost")?,
                    Extension::supported_groups(&groups)?,
                    Extension::ec_point_formats(&[0x00])?,
                    Extension::signature_algorithms(&schemes)?,
                    Extension::extended_master_secret(),
                    Extension::session_ticket(&[]),
                ]),
            Self::Tls12DheRsa => base
                .with_cipher_suites([0x009F_u16, 0x009E, 0x00FF])
                .with_extensions([
                    Extension::server_name(b"localhost")?,
                    Extension::supported_groups(&groups)?,
                    Extension::signature_algorithms(&schemes)?,
                    Extension::extended_master_secret(),
                    Extension::session_ticket(&[]),
                ]),
            Self::Tls13 | Self::Tls13Hrr => {
                let entry = KeyShareEntry {
                    group: X25519,
                    key_exchange: key_share,
                };
                let shares: &[KeyShareEntry<'_>] = if self == Self::Tls13 {
                    std::slice::from_ref(&entry)
                } else {
                    &[]
                };
                base.with_session_id(&session_id)
                    .with_cipher_suites([0x1302_u16, 0x1301, 0x1303])
                    .with_extensions([
                        Extension::server_name(b"localhost")?,
                        Extension::supported_versions(&[ProtocolVersion::TLS1_3])?,
                        Extension::supported_groups(&groups)?,
                        Extension::signature_algorithms(&schemes)?,
                        Extension::psk_key_exchange_modes(&[0x01])?,
                        Extension::key_share(shares)?,
                    ])
            }
            Self::NoSharedCipher => base
                .with_cipher_suites([0x009D_u16, 0x009C, 0x003D, 0x002F])
                .with_extensions([
                    Extension::server_name(b"localhost")?,
                    Extension::signature_algorithms(&schemes)?,
                    Extension::extended_master_secret(),
                ]),
        };
        Ok(hello)
    }
}

/// Разобранные аргументы подкоманды.
#[derive(Debug)]
struct Options {
    addr: String,
    scenario: Scenario,
    out_dir: Option<PathBuf>,
    stand: String,
    server: String,
    random: Option<[u8; RANDOM_LEN]>,
    key_share: Option<[u8; X25519_KEY_LEN]>,
    timeout: Duration,
    force: bool,
}

/// Итог обмена: причина остановки чтения ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stop {
    ServerHelloDone,
    Alert { level: u8, description: u8 },
    Encrypted,
    RetryComplete,
    Timeout,
    Closed,
    TooLarge,
    Failed(String),
}

impl Stop {
    /// Короткий код итога для `.meta.toml`.
    fn code(&self) -> &'static str {
        match self {
            Self::ServerHelloDone => "server_hello_done",
            Self::Alert { .. } => "alert",
            Self::Encrypted => "encrypted",
            Self::RetryComplete => "retry_complete",
            Self::Timeout => "timeout",
            Self::Closed => "closed",
            Self::TooLarge => "too_large",
            Self::Failed(_) => "parse_error",
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::ServerHelloDone => "получен ServerHelloDone".to_owned(),
            Self::Alert { level, description } => {
                format!("получен alert: уровень {level}, описание {description}")
            }
            Self::Encrypted => "первая зашифрованная запись (в фикстуру не вошла)".to_owned(),
            Self::RetryComplete => {
                "HelloRetryRequest, второй ServerHello и первая зашифрованная запись".to_owned()
            }
            Self::Timeout => "таймаут чтения".to_owned(),
            Self::Closed => "сервер закрыл соединение".to_owned(),
            Self::TooLarge => format!("ответ больше {MAX_RESPONSE_BYTES} байт"),
            Self::Failed(reason) => format!("ошибка разбора: {reason}"),
        }
    }
}

/// Сопоставляет сценарий с фактическим итогом обмена.
fn check_outcome(scenario: Scenario, stop: &Stop) -> Result<(), String> {
    let expected = scenario.expected_stop();
    if *stop == expected {
        return Ok(());
    }
    Err(format!(
        "сценарий {}: ожидался итог обмена `{}` ({}), получен `{}` ({})",
        scenario.name(),
        expected.code(),
        expected.describe(),
        stop.code(),
        stop.describe()
    ))
}

/// Для сценария с фрагментацией проверяет, что сервер действительно разбил
/// handshake-сообщение между записями.
fn check_fragmentation(scenario: Scenario, bytes: &[u8]) -> Result<(), String> {
    if scenario != Scenario::Tls12Fragmented || handshake_spans_records(bytes) {
        return Ok(());
    }
    Err(format!(
        "сценарий {}: сервер не разбил ни одно handshake-сообщение между записями (стенд запущен без STAND_MAX_SEND_FRAG или сертификат помещается в один фрагмент)",
        scenario.name()
    ))
}

/// Истина, если в потоке записей есть handshake-сообщение, продолжающееся в
/// следующей handshake-записи. Обрезанный или некорректный поток — ложь.
fn handshake_spans_records(bytes: &[u8]) -> bool {
    let mut reader = Reader::new(bytes);
    // Предыдущая handshake-запись закончилась посреди сообщения.
    let mut partial = false;
    while !reader.is_empty() {
        let Ok(content_type) = reader.u8() else {
            return false;
        };
        if reader.skip(2).is_err() {
            return false;
        }
        let Ok(mut fragment) = reader.sub_u16() else {
            return false;
        };
        if content_type != HANDSHAKE_CONTENT_TYPE || fragment.is_empty() {
            continue;
        }
        if partial {
            return true;
        }
        while !fragment.is_empty() {
            let body_len = fragment
                .skip(1)
                .and_then(|()| fragment.u24())
                .ok()
                .and_then(|length| usize::try_from(length).ok());
            match body_len {
                Some(length) if fragment.skip(length).is_ok() => {}
                _ => {
                    partial = true;
                    break;
                }
            }
        }
    }
    false
}

/// Результат обмена.
#[derive(Debug)]
struct Capture {
    /// Байты ответа, вошедшие в фикстуру.
    bytes: Vec<u8>,
    stop: Stop,
    /// Что увидел парсер, по строке на событие.
    observed: Vec<String>,
    /// Сколько байтов ответа относится к первой части обмена (HRR и
    /// следующий за ним CCS), если второй ClientHello был отправлен.
    retry_offset: Option<usize>,
}

/// Точка входа подкоманды.
pub fn run(root: &Path, args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match parse_args(args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("xtask record-fixture: {message}");
            eprintln!("Подсказка: `cargo xtask record-fixture --help`");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match record(root, &options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask record-fixture: {message}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut addr = None;
    let mut scenario = None;
    let mut out_dir = None;
    let mut stand = DEFAULT_STAND.to_owned();
    let mut server = None;
    let mut random = None;
    let mut key_share = None;
    let mut timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);
    let mut force = false;

    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value = || {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("у параметра `{flag}` нет значения"))
        };
        match flag.as_str() {
            "--addr" => addr = Some(value()?),
            "--scenario" => {
                let name = value()?;
                scenario = Some(
                    Scenario::from_name(&name)
                        .ok_or_else(|| format!("неизвестный сценарий `{name}`"))?,
                );
            }
            "--out-dir" => out_dir = Some(PathBuf::from(value()?)),
            "--stand" => stand = value()?,
            "--server" => server = Some(value()?),
            "--random" => random = Some(parse_hex_array::<RANDOM_LEN>("--random", &value()?)?),
            "--key-share" => {
                key_share = Some(parse_hex_array::<X25519_KEY_LEN>("--key-share", &value()?)?);
            }
            "--timeout-ms" => timeout = parse_timeout(&value()?)?,
            "--force" => force = true,
            other => return Err(format!("неизвестный параметр `{other}`")),
        }
    }

    if !stand
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || stand.is_empty()
    {
        return Err(format!(
            "имя стенда `{stand}`: допустимы строчные латинские буквы, цифры и дефис"
        ));
    }

    let server = server.ok_or(
        "не задан обязательный параметр --server: продукт и версия сервера стенда, например вывод `openssl version` в окружении, где запущен стенд",
    )?;
    check_server(&server)?;

    Ok(Options {
        addr: addr.ok_or("не задан обязательный параметр --addr")?,
        scenario: scenario.ok_or("не задан обязательный параметр --scenario")?,
        out_dir,
        stand,
        server,
        random,
        key_share,
        timeout,
        force,
    })
}

/// Разбирает `--timeout-ms`: целое от 1 до [`MAX_TIMEOUT_MS`].
fn parse_timeout(text: &str) -> Result<Duration, String> {
    let millis: u64 = text.parse().map_err(|_| {
        format!("некорректный таймаут `{text}`: нужно целое число от 1 до {MAX_TIMEOUT_MS} мс")
    })?;
    if millis == 0 || millis > MAX_TIMEOUT_MS {
        return Err(format!(
            "таймаут `{text}` вне допустимого диапазона: от 1 до {MAX_TIMEOUT_MS} мс"
        ));
    }
    Ok(Duration::from_millis(millis))
}

/// Проверяет строку `--server`: она попадает в `.meta.toml` и в
/// `capture_command` в одинарных кавычках.
fn check_server(server: &str) -> Result<(), String> {
    if server.trim().is_empty() {
        return Err("параметр `--server`: пустая строка".to_owned());
    }
    if server
        .chars()
        .any(|character| character.is_control() || character == '\'')
    {
        return Err(
            "параметр `--server`: управляющие символы и одинарная кавычка не допускаются"
                .to_owned(),
        );
    }
    Ok(())
}

/// Проверяет, что адрес — IP-литерал loopback с портом. Имена не
/// разрешаются: DNS-запросов подкоманда не делает.
fn loopback_addr(text: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = text.parse().map_err(|_| {
        format!("адрес `{text}`: нужен IP-литерал с портом, например 127.0.0.1:4433; имена не разрешаются")
    })?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "адрес `{text}` не loopback: record-fixture работает только с 127.0.0.0/8 и ::1 (локальные стенды из tests/stands); соединение не выполнялось"
        ));
    }
    Ok(addr)
}

/// Команда записи для `.meta.toml`: аргументы, по которым запись
/// воспроизводится.
fn capture_command(
    options: &Options,
    random: &[u8; RANDOM_LEN],
    key_share: &[u8; X25519_KEY_LEN],
) -> String {
    let mut command = format!(
        "cargo xtask record-fixture --addr {} --scenario {} --stand {} --server '{}' --random {}",
        options.addr,
        options.scenario.name(),
        options.stand,
        options.server,
        hex_compact(random)
    );
    if options.scenario.uses_key_share() {
        let _ = write!(command, " --key-share {}", hex_compact(key_share));
    }
    command
}

/// Поля `[expected.fields]` фикстуры ClientHello.
fn client_fields(hello: &ClientHello) -> Vec<(&'static str, String)> {
    let suites = hello
        .cipher_suites()
        .iter()
        .map(|code| format!("{code:#06x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let extensions = hello
        .extensions()
        .iter()
        .map(|extension| format!("{:#06x}", extension.ext_type().0))
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        (
            "record_version",
            format!("{:#06x}", hello.record_version().0),
        ),
        (
            "legacy_version",
            format!("{:#06x}", hello.legacy_version().0),
        ),
        ("session_id_len", hello.session_id().len().to_string()),
        ("cipher_suites", suites),
        ("extensions", extensions),
    ]
}

/// Итог разбора для `[expected].outcome` при записи с `--force`.
fn forced_outcome(stop: &Stop) -> &'static str {
    if matches!(stop, Stop::Failed(_)) {
        "error"
    } else {
        "ok"
    }
}

fn record(root: &Path, options: &Options) -> Result<(), String> {
    // Проверка адреса — до любых других действий, включая чтение urandom.
    let addr = loopback_addr(&options.addr)?;
    let scenario = options.scenario;

    let random = match options.random {
        Some(random) => random,
        None => urandom_array()?,
    };
    let key_share = match options.key_share {
        Some(key_share) => key_share,
        None if scenario.uses_key_share() => urandom_array()?,
        None => [0_u8; X25519_KEY_LEN],
    };

    let hello = scenario
        .build(random, &key_share)
        .map_err(|error| format!("не удалось собрать ClientHello: {error}"))?;
    let request = hello
        .record_bytes()
        .map_err(|error| format!("не удалось закодировать ClientHello: {error}"))?;
    let retry = match scenario.retry_scenario() {
        Some(retry_scenario) => {
            let retry_hello = retry_scenario
                .build(random, &key_share)
                .map_err(|error| format!("не удалось собрать второй ClientHello: {error}"))?;
            let retry_request = retry_hello
                .record_bytes()
                .map_err(|error| format!("не удалось закодировать второй ClientHello: {error}"))?;
            Some((retry_hello, retry_request))
        }
        None => None,
    };
    let retry_request: Option<&[u8]> = match &retry {
        Some((_, bytes)) => Some(bytes),
        None => None,
    };

    let client_name = scenario.client_fixture(&options.stand);
    let server_name = scenario.server_fixture(&options.stand);
    let retry_names = scenario.retry_fixtures(&options.stand);
    let out_dir = options
        .out_dir
        .clone()
        .unwrap_or_else(|| root.join(DEFAULT_OUT_DIR));

    // Существующие фикстуры проверяются до соединения со стендом.
    if !options.force {
        let mut names = vec![client_name.as_str(), server_name.as_str()];
        if let Some((retry_client, retry_server)) = &retry_names {
            names.push(retry_client);
            names.push(retry_server);
        }
        refuse_existing(&out_dir, &names)?;
    }

    let capture = exchange(addr, &request, retry_request, options.timeout)?;

    eprintln!("xtask record-fixture: сценарий {}", scenario.name());
    eprintln!("  сервер: {}", options.server);
    eprintln!("  остановка: {}", capture.stop.describe());
    eprintln!("  разбор ответа (для сверки с [expected], в метаданные не пишется):");
    for line in &capture.observed {
        eprintln!("    {line}");
    }

    let verdict = check_outcome(scenario, &capture.stop)
        .and_then(|()| check_fragmentation(scenario, &capture.bytes));
    if let Err(mismatch) = &verdict
        && !options.force
    {
        return Err(format!(
            "{mismatch}; фикстуры не записаны (запись при несовпадении итога — только с --force)"
        ));
    }
    if let Err(mismatch) = &verdict {
        check_forced_layout(scenario, capture.retry_offset.is_some())
            .map_err(|refusal| format!("{mismatch}; {refusal}"))?;
    }
    if capture.bytes.is_empty() {
        return Err(format!(
            "ответ пуст ({}); фикстура не записана",
            capture.stop.describe()
        ));
    }

    let command = capture_command(options, &random, &key_share);
    let server_command = scenario.server_command(&options.stand);
    let source = Source {
        stand: &options.stand,
        server: &options.server,
        server_command: &server_command,
        capture_command: &command,
        date: today(),
    };
    let client_summary =
        "ClientHello в одной записи; собирается билдером tls-probe побайтно так же";
    let exchange_code = capture.stop.code();

    let fields = client_fields(&hello);
    let client_meta = Meta {
        description: scenario.client_description(),
        direction: "client",
        request: None,
        second_request: None,
        length: request.len(),
        outcome: "ok",
        exchange: None,
        summary: client_summary,
        fields: fields
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect(),
        conditions: &[],
    };
    let mut files = vec![fixture_file(&client_name, &request, &client_meta, &source)];

    // Второй ClientHello пишется, если он был отправлен.
    let second = match (&retry, &retry_names, capture.retry_offset) {
        (Some((retry_hello, retry_bytes)), Some((retry_client, retry_server)), Some(offset)) => {
            let fields = client_fields(retry_hello);
            let meta = Meta {
                description: "Второй ClientHello TLS 1.3, отправленный после HelloRetryRequest: те же random, session_id и шифры, key_share x25519",
                direction: "client",
                request: None,
                second_request: None,
                length: retry_bytes.len(),
                outcome: "ok",
                exchange: None,
                summary: client_summary,
                fields: fields
                    .iter()
                    .map(|(key, value)| (*key, value.as_str()))
                    .collect(),
                conditions: &[],
            };
            files.push(fixture_file(retry_client, retry_bytes, &meta, &source));
            Some((retry_client.as_str(), retry_server.as_str(), offset))
        }
        _ => None,
    };

    match (&verdict, second) {
        (Ok(()), Some((retry_client, retry_server, offset))) => {
            let first_leg = capture.bytes.get(..offset).ok_or_else(|| {
                format!("внутренняя ошибка: граница первой части обмена {offset} вне ответа")
            })?;
            let first_meta = Meta {
                description: scenario.server_description(),
                direction: "server",
                request: Some(&client_name),
                second_request: None,
                length: first_leg.len(),
                outcome: "ok",
                exchange: Some(exchange_code),
                summary: scenario.server_summary(),
                fields: scenario.server_fields().to_vec(),
                conditions: scenario.stand_conditions(),
            };
            files.push(fixture_file(&server_name, first_leg, &first_meta, &source));

            let full_meta = Meta {
                description: "Полный поток сервера в обмене с HelloRetryRequest: HRR, ChangeCipherSpec, второй ServerHello и первая зашифрованная запись",
                direction: "server",
                request: Some(&client_name),
                second_request: Some((retry_client, offset)),
                length: capture.bytes.len(),
                outcome: "ok",
                exchange: Some(exchange_code),
                summary: "HelloRetryRequest и ChangeCipherSpec, после второго ClientHello — ServerHello (не HelloRetryRequest) с supported_versions = TLS 1.3 и key_share x25519, затем одна зашифрованная запись application_data",
                fields: RETRY_EXCHANGE_FIELDS.to_vec(),
                conditions: &[],
            };
            files.push(fixture_file(
                retry_server,
                &capture.bytes,
                &full_meta,
                &source,
            ));
        }
        (Ok(()), None) => {
            if scenario.retry_scenario().is_some() {
                return Err(
                    "внутренняя ошибка: обмен с HelloRetryRequest завершён без второго ClientHello"
                        .to_owned(),
                );
            }
            let meta = Meta {
                description: scenario.server_description(),
                direction: "server",
                request: Some(&client_name),
                second_request: None,
                length: capture.bytes.len(),
                outcome: "ok",
                exchange: Some(exchange_code),
                summary: scenario.server_summary(),
                fields: scenario.server_fields().to_vec(),
                conditions: scenario.stand_conditions(),
            };
            files.push(fixture_file(&server_name, &capture.bytes, &meta, &source));
        }
        (Err(mismatch), second) => {
            // Запись с --force: фактический итог, без ожидаемых полей сценария
            // и условий стенда. Имена файлов отражают содержимое: если второй
            // ClientHello был отправлен, ответ делится так же, как при
            // совпавшем итоге, и перезаписываются обе серверные фикстуры.
            // Случай сценария с HRR без второго ClientHello отсеян выше,
            // в `check_forced_layout`.
            let summary = format!(
                "записано с --force при несовпадении итога обмена: {mismatch}; ожидаемые поля сценария не записаны"
            );
            let description = "Ответ сервера, записанный с --force: итог обмена не совпал с ожидаемым для сценария";
            match second {
                Some((retry_client, retry_server, offset)) => {
                    let first_leg = capture.bytes.get(..offset).ok_or_else(|| {
                        format!(
                            "внутренняя ошибка: граница первой части обмена {offset} вне ответа"
                        )
                    })?;
                    let first_meta = Meta {
                        description: "Первая часть ответа сервера (до второго ClientHello), записанная с --force: итог обмена не совпал с ожидаемым для сценария",
                        direction: "server",
                        request: Some(&client_name),
                        second_request: None,
                        length: first_leg.len(),
                        outcome: "ok",
                        exchange: Some(exchange_code),
                        summary: &summary,
                        fields: Vec::new(),
                        conditions: &[],
                    };
                    files.push(fixture_file(&server_name, first_leg, &first_meta, &source));

                    let full_meta = Meta {
                        description,
                        direction: "server",
                        request: Some(&client_name),
                        second_request: Some((retry_client, offset)),
                        length: capture.bytes.len(),
                        outcome: forced_outcome(&capture.stop),
                        exchange: Some(exchange_code),
                        summary: &summary,
                        fields: Vec::new(),
                        conditions: &[],
                    };
                    files.push(fixture_file(
                        retry_server,
                        &capture.bytes,
                        &full_meta,
                        &source,
                    ));
                }
                None => {
                    let meta = Meta {
                        description,
                        direction: "server",
                        request: Some(&client_name),
                        second_request: None,
                        length: capture.bytes.len(),
                        outcome: forced_outcome(&capture.stop),
                        exchange: Some(exchange_code),
                        summary: &summary,
                        fields: Vec::new(),
                        conditions: &[],
                    };
                    files.push(fixture_file(&server_name, &capture.bytes, &meta, &source));
                }
            }
        }
    }

    fs::create_dir_all(&out_dir)
        .map_err(|error| format!("не удалось создать {}: {error}", out_dir.display()))?;
    write_fixtures(&out_dir, &files, options.force)?;

    if let Err(mismatch) = &verdict {
        eprintln!("  ВНИМАНИЕ: записано с --force: {mismatch}");
    }
    for file in &files {
        eprintln!("  записано: {} ({} байт)", file.name, file.length);
    }
    eprintln!("  каталог: {}", out_dir.display());
    Ok(())
}

/// Что означает открытое событие декодера для хода обмена.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// ServerHello, не являющийся HelloRetryRequest.
    Hello,
    /// HelloRetryRequest: запрошенная группа и наличие `cookie`.
    Retry {
        group: Option<NamedGroup>,
        cookie: bool,
    },
    ChangeCipherSpec,
    Other,
}

/// Результат обработки одного события декодера, без заимствований.
#[derive(Debug)]
enum Step {
    NeedMore,
    Plain {
        line: String,
        stop: Option<Stop>,
        seen: Seen,
    },
    Encrypted(String),
    /// Декодер отказал по лимиту общего объёма потока.
    TooLarge,
    Failed(String),
}

/// Дедлайн всего обмена, считая соединение: [`EXCHANGE_TIMEOUTS`] таймаутов
/// от начала.
fn read_deadline(start: Instant, timeout: Duration) -> Result<Instant, String> {
    start
        .checked_add(timeout.saturating_mul(EXCHANGE_TIMEOUTS))
        .ok_or_else(|| {
            format!(
                "таймаут {} мс слишком велик: дедлайн чтения не представим",
                timeout.as_millis()
            )
        })
}

/// Таймаут очередной операции с сокетом: не больше `timeout` и не больше
/// остатка до дедлайна. `None` — дедлайн наступил.
fn remaining_timeout(deadline: Instant, now: Instant, timeout: Duration) -> Option<Duration> {
    let left = deadline.checked_duration_since(now)?;
    if left.is_zero() {
        return None;
    }
    Some(left.min(timeout))
}

/// Задаёт таймауты чтения и записи по остатку до дедлайна. `Ok(false)` —
/// дедлайн наступил, операцию начинать нельзя.
fn arm_timeouts(stream: &TcpStream, deadline: Instant, timeout: Duration) -> Result<bool, String> {
    let Some(limit) = remaining_timeout(deadline, Instant::now(), timeout) else {
        return Ok(false);
    };
    stream
        .set_read_timeout(Some(limit))
        .and_then(|()| stream.set_write_timeout(Some(limit)))
        .map_err(|error| format!("не удалось задать таймауты: {error}"))?;
    Ok(true)
}

/// Лимиты декодера: общий объём потока равен пределу подкоманды.
fn decoder_limits() -> ParseLimits {
    ParseLimits {
        max_total_bytes: MAX_RESPONSE_BYTES,
        ..ParseLimits::default()
    }
}

/// Истина, если декодер отказал по лимиту общего объёма потока.
fn is_total_bytes_limit(error: &ParseError) -> bool {
    matches!(error, ParseError::LimitExceeded { limit, .. } if *limit == TOTAL_BYTES_LIMIT)
}

/// Один вызов декодера. Ошибка по лимиту общего объёма даёт тот же итог,
/// что и проверка числа принятых байтов: [`Step::TooLarge`].
fn feed_step(decoder: &mut Decoder, input: &mut &[u8]) -> Step {
    match decoder.feed(input) {
        Ok(event) => inspect(&event),
        Err(error) if is_total_bytes_limit(&error) => Step::TooLarge,
        Err(error) => Step::Failed(error.to_string()),
    }
}

/// Запись с `--force` в сценарии с HelloRetryRequest возможна, только если
/// второй ClientHello был отправлен: иначе ответ не является обменом с HRR,
/// и под именами фикстур сценария его записывать нельзя. Существующие
/// фикстуры при отказе не изменяются и не удаляются.
fn check_forced_layout(scenario: Scenario, second_sent: bool) -> Result<(), String> {
    if scenario.retry_scenario().is_none() || second_sent {
        return Ok(());
    }
    Err(format!(
        "сценарий {}: второй ClientHello не отправлен, ответ не является обменом с HelloRetryRequest; под именами фикстур сценария он не записывается и с --force, существующие фикстуры не изменены",
        scenario.name()
    ))
}

/// Может ли подкоманда ответить на HelloRetryRequest вторым ClientHello.
fn retry_supported(group: Option<NamedGroup>, cookie: bool) -> Result<(), String> {
    if cookie {
        return Err(
            "HelloRetryRequest с расширением cookie: второй ClientHello с cookie не поддерживается"
                .to_owned(),
        );
    }
    match group {
        Some(group) if group == X25519 => Ok(()),
        Some(group) => Err(format!(
            "HelloRetryRequest запросил группу {:#06x}: второй ClientHello умеет только x25519 (0x001d)",
            group.0
        )),
        None => Err("HelloRetryRequest без корректного key_share".to_owned()),
    }
}

/// Отправляет ClientHello и читает ответ до условия остановки. Если задан
/// `retry_request`, он отправляется после HelloRetryRequest.
fn exchange(
    addr: SocketAddr,
    request: &[u8],
    retry_request: Option<&[u8]>,
    timeout: Duration,
) -> Result<Capture, String> {
    let deadline = read_deadline(Instant::now(), timeout)?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|error| format!("не удалось соединиться с {addr}: {error}"))?;
    if !arm_timeouts(&stream, deadline, timeout)? {
        return Err(format!(
            "общий дедлайн обмена истёк до отправки ClientHello на {addr}"
        ));
    }
    stream
        .write_all(request)
        .map_err(|error| format!("не удалось отправить ClientHello: {error}"))?;

    let mut decoder = Decoder::new(decoder_limits());
    let mut received = Vec::new();
    let mut keep = 0_usize;
    let mut observed = Vec::new();
    let mut saw_retry = false;
    let mut retry_sent = false;
    let mut second_hello = false;
    let mut first_leg_end = None;
    let mut buffer = [0_u8; 4096];

    let stop = 'read: loop {
        // Таймаут каждого чтения — не больше остатка до общего дедлайна.
        if !arm_timeouts(&stream, deadline, timeout)? {
            keep = received.len();
            break Stop::Timeout;
        }
        let count = match stream.read(&mut buffer) {
            Ok(0) => {
                keep = received.len();
                break Stop::Closed;
            }
            Ok(count) => count,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                keep = received.len();
                break Stop::Timeout;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => {
                if received.is_empty() {
                    return Err(format!("ошибка чтения ответа: {error}"));
                }
                keep = received.len();
                break Stop::Closed;
            }
        };
        let chunk = buffer.get(..count).unwrap_or(&[]);
        received.extend_from_slice(chunk);
        if received.len() > MAX_RESPONSE_BYTES {
            keep = MAX_RESPONSE_BYTES;
            break Stop::TooLarge;
        }

        let mut input = chunk;
        loop {
            let step = feed_step(&mut decoder, &mut input);
            match step {
                Step::NeedMore => break,
                Step::Plain { line, stop, seen } => {
                    observed.push(line);
                    let offset = decoder.stream_offset();
                    keep = offset;
                    if let Some(stop) = stop {
                        break 'read stop;
                    }
                    match seen {
                        Seen::Retry { group, cookie } => {
                            if saw_retry {
                                break 'read Stop::Failed(
                                    "второй HelloRetryRequest в одном соединении".to_owned(),
                                );
                            }
                            saw_retry = true;
                            first_leg_end = Some(offset);
                            if let Some(retry_request) = retry_request {
                                if let Err(reason) = retry_supported(group, cookie) {
                                    break 'read Stop::Failed(reason);
                                }
                                if !arm_timeouts(&stream, deadline, timeout)? {
                                    break 'read Stop::Timeout;
                                }
                                stream.write_all(retry_request).map_err(|error| {
                                    format!("не удалось отправить второй ClientHello: {error}")
                                })?;
                                retry_sent = true;
                            }
                        }
                        Seen::ChangeCipherSpec => {
                            // CCS сразу за HRR относится к первой части обмена.
                            if saw_retry && !second_hello {
                                first_leg_end = Some(offset);
                            }
                        }
                        Seen::Hello => {
                            if saw_retry {
                                second_hello = true;
                            }
                        }
                        Seen::Other => {}
                    }
                }
                Step::Encrypted(line) => {
                    observed.push(line);
                    if second_hello {
                        // Полный обмен с HRR: первая зашифрованная запись
                        // входит в фикстуру.
                        keep = decoder.stream_offset();
                        break 'read Stop::RetryComplete;
                    }
                    break 'read Stop::Encrypted;
                }
                Step::TooLarge => {
                    keep = received.len().min(MAX_RESPONSE_BYTES);
                    break 'read Stop::TooLarge;
                }
                Step::Failed(reason) => {
                    keep = received.len();
                    break 'read Stop::Failed(reason);
                }
            }
        }
    };

    received.truncate(keep);
    Ok(Capture {
        bytes: received,
        stop,
        observed,
        retry_offset: if retry_sent { first_leg_end } else { None },
    })
}

/// Описывает событие декодера и решает, останавливаться ли на нём.
fn inspect(event: &Event<'_>) -> Step {
    let plain = |line: String, stop: Option<Stop>| Step::Plain {
        line,
        stop,
        seen: Seen::Other,
    };
    match event {
        Event::NeedMore => Step::NeedMore,
        Event::Handshake(message) => match ServerMessage::from_message(message) {
            Ok(ServerMessage::ServerHello(hello)) => Step::Plain {
                line: describe_hello("ServerHello", &hello),
                stop: None,
                seen: Seen::Hello,
            },
            Ok(ServerMessage::HelloRetryRequest(hello)) => {
                let group = hello.extensions().find_map(|extension| match extension {
                    ServerExtension::KeyShare(share) => Some(share.group()),
                    _ => None,
                });
                let cookie = hello
                    .raw_extensions()
                    .filter_map(Result::ok)
                    .any(|raw| raw.ext_type.0 == COOKIE_EXTENSION);
                Step::Plain {
                    line: describe_hello("HelloRetryRequest", &hello),
                    stop: None,
                    seen: Seen::Retry { group, cookie },
                }
            }
            Ok(ServerMessage::ServerHelloDone) => {
                plain("ServerHelloDone".to_owned(), Some(Stop::ServerHelloDone))
            }
            Ok(other) => plain(
                format!(
                    "{} ({} байт тела)",
                    other.msg_type().name().unwrap_or("handshake"),
                    message.body.len()
                ),
                None,
            ),
            Err(error) => plain(
                format!("handshake типа {}: {error}", message.msg_type.0),
                Some(Stop::Failed(error.to_string())),
            ),
        },
        Event::Alert(body) => match Alert::parse(body) {
            Ok(alert) => plain(
                format!(
                    "alert: level {} ({}), description {} ({})",
                    alert.level.0,
                    alert.level.name().unwrap_or("?"),
                    alert.description.0,
                    alert.description.name().unwrap_or("?")
                ),
                Some(Stop::Alert {
                    level: alert.level.0,
                    description: alert.description.0,
                }),
            ),
            Err(error) => plain(
                format!("alert не разобран: {error}"),
                Some(Stop::Failed(error.to_string())),
            ),
        },
        Event::ChangeCipherSpec => Step::Plain {
            line: "ChangeCipherSpec".to_owned(),
            stop: None,
            seen: Seen::ChangeCipherSpec,
        },
        Event::ApplicationData(body) => Step::Encrypted(format!(
            "application_data, {} байт: зашифровано",
            body.len()
        )),
        Event::Opaque(record) => Step::Encrypted(format!(
            "запись типа {}, {} байт: не интерпретируется",
            record.content_type.0,
            record.fragment.len()
        )),
    }
}

fn describe_hello(label: &str, hello: &ServerHello<'_>) -> String {
    let extensions = hello
        .extensions()
        .map(|extension| format!("{extension:02x?}"))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "{label}: legacy_version {:#06x}, version {:#06x}, cipher_suite {:#06x}, compression {:#04x}, session_id {} байт, downgrade {:?}, аномалии {:?}, расширения: {extensions}",
        hello.legacy_version.0,
        hello.version().0,
        hello.cipher_suite.0,
        hello.compression_method,
        hello.session_id.len(),
        hello.downgrade_marker(),
        hello.anomalies(),
    )
}

/// Сведения об источнике для `.meta.toml`.
struct Source<'a> {
    stand: &'a str,
    server: &'a str,
    server_command: &'a str,
    capture_command: &'a str,
    date: String,
}

/// Содержимое `.meta.toml`, зависящее от фикстуры.
struct Meta<'a> {
    description: &'a str,
    direction: &'a str,
    request: Option<&'a str>,
    /// Имя фикстуры второго ClientHello и число байтов ответа до него.
    second_request: Option<(&'a str, usize)>,
    length: usize,
    outcome: &'a str,
    /// Код итога обмена; только у ответов сервера.
    exchange: Option<&'a str>,
    summary: &'a str,
    /// Ожидаемые поля; пустой список — секция `[expected.fields]` не пишется.
    fields: Vec<(&'a str, &'a str)>,
    /// Условия записи (параметры варианта стенда и проверенные свойства
    /// потока); пустой список — секция `[source.conditions]` не пишется.
    conditions: &'a [(&'a str, &'a str)],
}

/// Готовое содержимое пары файлов одной фикстуры.
#[derive(Debug)]
struct FixtureFile {
    name: String,
    length: usize,
    hex: String,
    meta: String,
}

fn fixture_file(name: &str, bytes: &[u8], meta: &Meta<'_>, source: &Source<'_>) -> FixtureFile {
    FixtureFile {
        name: name.to_owned(),
        length: bytes.len(),
        hex: hex_lines(bytes),
        meta: meta_toml(meta, source),
    }
}

/// Пути пары файлов фикстуры: `.hex` и `.meta.toml`.
fn fixture_paths(dir: &Path, name: &str) -> [PathBuf; 2] {
    [
        dir.join(format!("{name}.hex")),
        dir.join(format!("{name}.meta.toml")),
    ]
}

/// Ошибка, если хотя бы один файл перечисленных фикстур уже существует.
fn refuse_existing(dir: &Path, names: &[&str]) -> Result<(), String> {
    for name in names {
        for path in fixture_paths(dir, name) {
            if path.exists() {
                return Err(format!(
                    "{} уже существует; перезапись — только с --force",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Пишет все файлы записи: сначала под временными именами, затем
/// переименованием. Без `force` существующие файлы не перезаписываются.
///
/// Атомарно только переименование каждого отдельного файла. Группа файлов
/// (до четырёх фикстур по два файла) переименовывается по очереди: если
/// переименование прервётся посередине (ошибка ФС, остановка процесса),
/// часть файлов окажется новой, часть — прежней, а оставшиеся временные
/// файлы удаляются только при ошибке, о которой процесс успел узнать. Откат
/// не выполняется: каталог фикстур находится под контролем версий,
/// расхождение видно в `git status` и по несовпадению `length` в
/// `.meta.toml`, а запись повторяется той же командой с `--force`.
fn write_fixtures(dir: &Path, files: &[FixtureFile], force: bool) -> Result<(), String> {
    if !force {
        let names: Vec<&str> = files.iter().map(|file| file.name.as_str()).collect();
        refuse_existing(dir, &names)?;
    }

    let mut targets = Vec::new();
    for file in files {
        let contents = [file.hex.as_str(), file.meta.as_str()];
        for (path, content) in fixture_paths(dir, &file.name).into_iter().zip(contents) {
            let temp_name = match path.file_name() {
                Some(name) => format!(".{}.tmp-{}", name.to_string_lossy(), std::process::id()),
                None => return Err(format!("некорректный путь фикстуры {}", path.display())),
            };
            targets.push((dir.join(temp_name), path, content));
        }
    }

    let written = targets.iter().try_for_each(|(temp, _, content)| {
        fs::write(temp, content)
            .map_err(|error| format!("не удалось записать {}: {error}", temp.display()))
    });
    let renamed = written.and_then(|()| {
        targets.iter().try_for_each(|(temp, path, _)| {
            fs::rename(temp, path).map_err(|error| {
                format!(
                    "не удалось переименовать {} в {}: {error}",
                    temp.display(),
                    path.display()
                )
            })
        })
    });
    if renamed.is_err() {
        for (temp, _, _) in &targets {
            let _ = fs::remove_file(temp);
        }
    }
    renamed
}

/// Формат `.hex`: нижний регистр, 16 байт в строке, байты через пробел.
fn hex_lines(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(3));
    for line in bytes.chunks(16) {
        let mut first = true;
        for byte in line {
            if !first {
                text.push(' ');
            }
            first = false;
            let _ = write!(text, "{byte:02x}");
        }
        text.push('\n');
    }
    text
}

fn hex_compact(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn meta_toml(meta: &Meta<'_>, source: &Source<'_>) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "format = 1");
    let _ = writeln!(text, "description = {}", toml_string(meta.description));
    let _ = writeln!(text, "direction = {}", toml_string(meta.direction));
    if let Some(request) = meta.request {
        let _ = writeln!(text, "request = {}", toml_string(request));
    }
    if let Some((second_request, offset)) = meta.second_request {
        let _ = writeln!(text, "second_request = {}", toml_string(second_request));
        let _ = writeln!(text, "second_request_offset = {offset}");
    }
    let _ = writeln!(text, "length = {}", meta.length);
    let _ = writeln!(text);
    let _ = writeln!(text, "[source]");
    let _ = writeln!(text, "kind = \"stand\"");
    let _ = writeln!(text, "stand = {}", toml_string(source.stand));
    let _ = writeln!(text, "server = {}", toml_string(source.server));
    let _ = writeln!(
        text,
        "server_command = {}",
        toml_string(source.server_command)
    );
    let _ = writeln!(
        text,
        "capture_command = {}",
        toml_string(source.capture_command)
    );
    let _ = writeln!(text, "date = {}", toml_string(&source.date));
    if !meta.conditions.is_empty() {
        let _ = writeln!(text);
        let _ = writeln!(text, "[source.conditions]");
        for (key, value) in meta.conditions {
            let _ = writeln!(text, "{key} = {}", toml_string(value));
        }
    }
    let _ = writeln!(text);
    let _ = writeln!(text, "[expected]");
    let _ = writeln!(text, "outcome = {}", toml_string(meta.outcome));
    if let Some(exchange) = meta.exchange {
        let _ = writeln!(text, "exchange = {}", toml_string(exchange));
    }
    let _ = writeln!(text, "summary = {}", toml_string(meta.summary));
    if !meta.fields.is_empty() {
        let _ = writeln!(text);
        let _ = writeln!(text, "[expected.fields]");
        for (key, value) in &meta.fields {
            let _ = writeln!(text, "{key} = {}", toml_string(value));
        }
    }
    text
}

/// Базовая строка TOML в двойных кавычках.
fn toml_string(value: &str) -> String {
    let mut text = String::with_capacity(value.len().saturating_add(2));
    text.push('"');
    for character in value.chars() {
        match character {
            '"' => text.push_str("\\\""),
            '\\' => text.push_str("\\\\"),
            '\n' => text.push_str("\\n"),
            '\r' => text.push_str("\\r"),
            '\t' => text.push_str("\\t"),
            other if other.is_control() => {
                let _ = write!(text, "\\u{:04X}", u32::from(other));
            }
            other => text.push(other),
        }
    }
    text.push('"');
    text
}

/// Разбирает `N` байтов, записанных `2 * N` шестнадцатеричными цифрами.
fn parse_hex_array<const N: usize>(flag: &str, text: &str) -> Result<[u8; N], String> {
    let digits = N.saturating_mul(2);
    let error = || format!("параметр `{flag}`: нужно ровно {digits} шестнадцатеричных цифр");
    if text.len() != digits || !text.is_ascii() {
        return Err(error());
    }
    let mut bytes = [0_u8; N];
    for (slot, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| error())?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| error())?;
    }
    Ok(bytes)
}

/// Читает `N` случайных байтов из `/dev/urandom`.
fn urandom_array<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0_u8; N];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| {
            format!("не удалось прочитать /dev/urandom: {error}; задайте --random и --key-share")
        })?;
    Ok(bytes)
}

/// Сегодняшняя дата UTC в виде `ГГГГ-ММ-ДД`.
fn today() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    civil_date(seconds / 86_400)
}

/// Дата по числу дней от 1970-01-01 (алгоритм civil_from_days).
fn civil_date(days: u64) -> String {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_SCENARIOS: [Scenario; 6] = [
        Scenario::Tls12,
        Scenario::Tls12Fragmented,
        Scenario::Tls12DheRsa,
        Scenario::Tls13,
        Scenario::Tls13Hrr,
        Scenario::NoSharedCipher,
    ];

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    /// Пустой каталог для теста записи файлов.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("certscan-xtask-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_file(name: &str, byte: u8) -> FixtureFile {
        FixtureFile {
            name: name.to_owned(),
            length: 1,
            hex: hex_lines(&[byte]),
            meta: format!("length = 1\nmarker = {byte}\n"),
        }
    }

    #[test]
    fn accepts_only_loopback_literals() {
        assert!(loopback_addr("127.0.0.1:4433").is_ok());
        assert!(loopback_addr("127.255.255.254:1").is_ok());
        assert!(loopback_addr("[::1]:4433").is_ok());

        for addr in [
            "192.0.2.1:443",
            "10.0.0.1:4433",
            "0.0.0.0:4433",
            "[2001:db8::1]:443",
            "[::ffff:127.0.0.1]:4433",
        ] {
            let error = loopback_addr(addr).unwrap_err();
            assert!(error.contains("не loopback"), "{addr}: {error}");
        }
        for addr in ["localhost:4433", "127.0.0.1", "example.test:443", ""] {
            let error = loopback_addr(addr).unwrap_err();
            assert!(error.contains("IP-литерал"), "{addr}: {error}");
        }
    }

    #[test]
    fn parses_arguments() {
        let random = "ab".repeat(32);
        let list = args(&[
            "--addr",
            "127.0.0.1:4433",
            "--scenario",
            "tls13-hrr",
            "--server",
            "OpenSSL 4.1.0 23 Oct 2026",
            "--timeout-ms",
            "500",
            "--random",
            &random,
        ]);
        let options = parse_args(&list).unwrap();
        assert_eq!(options.addr, "127.0.0.1:4433");
        assert_eq!(options.scenario, Scenario::Tls13Hrr);
        assert_eq!(options.server, "OpenSSL 4.1.0 23 Oct 2026");
        assert_eq!(options.timeout, Duration::from_millis(500));
        assert_eq!(options.random, Some([0xAB; 32]));
        assert_eq!(options.stand, DEFAULT_STAND);
        assert!(!options.force);

        let mut forced = list.clone();
        forced.push("--force".to_owned());
        assert!(parse_args(&forced).unwrap().force);

        let missing = parse_args(&list[..2]).unwrap_err();
        assert!(missing.contains("--server"), "{missing}");
        let missing = parse_args(&args(&["--addr", "127.0.0.1:4433", "--server", "x"]));
        assert!(missing.unwrap_err().contains("--scenario"));
        let unknown = parse_args(&args(&["--nope"])).unwrap_err();
        assert!(unknown.contains("--nope"), "{unknown}");
        let no_value = parse_args(&args(&["--addr"])).unwrap_err();
        assert!(no_value.contains("нет значения"), "{no_value}");
    }

    #[test]
    fn server_is_required_and_validated() {
        let base = ["--addr", "127.0.0.1:4433", "--scenario", "tls12"];
        let error = parse_args(&args(&base)).unwrap_err();
        assert!(error.contains("--server"), "{error}");

        for bad in ["", "   ", "Open'SSL", "OpenSSL\n4"] {
            let mut list = args(&base);
            list.extend(args(&["--server", bad]));
            let error = parse_args(&list).unwrap_err();
            assert!(error.contains("--server"), "{bad:?}: {error}");
        }
        assert!(check_server("OpenSSL 4.1.0 23 Oct 2026").is_ok());
    }

    #[test]
    fn timeout_is_bounded() {
        assert_eq!(parse_timeout("1"), Ok(Duration::from_millis(1)));
        assert_eq!(parse_timeout("60000"), Ok(Duration::from_millis(60_000)));
        for bad in [
            "0",
            "60001",
            "18446744073709551615",
            "18446744073709551616",
            "-1",
            "abc",
            "",
        ] {
            let error = parse_timeout(bad).unwrap_err();
            assert!(error.contains("60000"), "{bad}: {error}");
        }

        let list = args(&[
            "--addr",
            "127.0.0.1:4433",
            "--scenario",
            "tls12",
            "--server",
            "x",
            "--timeout-ms",
            "18446744073709551615",
        ]);
        let error = parse_args(&list).unwrap_err();
        assert!(error.contains("диапазона"), "{error}");
    }

    #[test]
    fn deadline_uses_checked_arithmetic() {
        let start = Instant::now();
        let deadline = read_deadline(start, Duration::from_millis(MAX_TIMEOUT_MS)).unwrap();
        assert_eq!(
            deadline.duration_since(start),
            Duration::from_millis(3 * MAX_TIMEOUT_MS)
        );
        // Непредставимый дедлайн — ошибка, а не паника.
        let error = read_deadline(start, Duration::MAX).unwrap_err();
        assert!(error.contains("слишком велик"), "{error}");
    }

    #[test]
    fn hex_helpers() {
        let bytes: Vec<u8> = (0..18).collect();
        assert_eq!(
            hex_lines(&bytes),
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n10 11\n"
        );
        assert_eq!(hex_lines(&[]), "");
        assert_eq!(hex_compact(&[0xDE, 0xAD]), "dead");
        assert!(parse_hex_array::<RANDOM_LEN>("--random", "zz").is_err());
        assert!(parse_hex_array::<RANDOM_LEN>("--random", &"g".repeat(2 * RANDOM_LEN)).is_err());
        assert_eq!(
            parse_hex_array::<RANDOM_LEN>("--random", &"0F".repeat(RANDOM_LEN)),
            Ok([0x0F; RANDOM_LEN])
        );
        let error = parse_hex_array::<X25519_KEY_LEN>("--key-share", "00").unwrap_err();
        assert!(
            error.contains("--key-share") && error.contains("64"),
            "{error}"
        );
    }

    #[test]
    fn toml_strings_are_escaped() {
        assert_eq!(toml_string("a \"b\" \\ c"), "\"a \\\"b\\\" \\\\ c\"");
        assert_eq!(toml_string("x\ny"), "\"x\\ny\"");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(59), "1970-03-01");
        assert_eq!(civil_date(11_016), "2000-02-29");
        assert_eq!(civil_date(20_768), "2026-11-11");
    }

    #[test]
    fn scenarios_build_and_name_fixtures() {
        let random = [0x11_u8; 32];
        let key = [0x42_u8; 32];
        for scenario in ALL_SCENARIOS {
            assert_eq!(Scenario::from_name(scenario.name()), Some(scenario));
            let hello = scenario.build(random, &key).unwrap();
            assert!(hello.record_bytes().is_ok());
            assert_ne!(
                scenario.client_fixture("openssl-basic"),
                scenario.server_fixture("openssl-basic")
            );
            assert!(!scenario.server_fields().is_empty());
        }
        assert_eq!(Scenario::from_name("tls11"), None);
        assert_eq!(
            Scenario::NoSharedCipher.server_fixture("openssl-basic"),
            "tls12-alert-openssl-basic-no-shared-cipher"
        );
        assert_eq!(
            Scenario::Tls13Hrr.retry_fixtures("openssl-basic"),
            Some((
                "tls13-clienthello-openssl-basic-after-hrr".to_owned(),
                "tls13-serverhello-openssl-basic-after-hrr".to_owned(),
            ))
        );
        for scenario in [Scenario::Tls12, Scenario::Tls13, Scenario::NoSharedCipher] {
            assert_eq!(scenario.retry_fixtures("openssl-basic"), None);
            assert_eq!(scenario.retry_scenario(), None);
        }
    }

    #[test]
    fn retry_hello_repeats_first_hello_with_key_share() {
        let random = [0x11_u8; 32];
        let key = [0x42_u8; 32];
        let first = Scenario::Tls13Hrr.build(random, &key).unwrap();
        let retry_scenario = Scenario::Tls13Hrr.retry_scenario().unwrap();
        let second = retry_scenario.build(random, &key).unwrap();

        assert_eq!(first.random(), second.random());
        assert_eq!(first.session_id(), second.session_id());
        assert_eq!(first.cipher_suites(), second.cipher_suites());
        assert_eq!(first.legacy_version(), second.legacy_version());
        let types = |hello: &ClientHello| -> Vec<u16> {
            hello
                .extensions()
                .iter()
                .map(|extension| extension.ext_type().0)
                .collect()
        };
        assert_eq!(types(&first), types(&second));

        // Отличие — только key_share: 2 байта группы, 2 байта длины и ключ.
        let first_bytes = first.record_bytes().unwrap();
        let second_bytes = second.record_bytes().unwrap();
        assert_eq!(second_bytes.len(), first_bytes.len() + 4 + key.len());
        assert!(second_bytes.ends_with(&key));
        assert!(!first_bytes.ends_with(&key));
    }

    #[test]
    fn outcome_must_match_scenario() {
        let handshake_failure = Stop::Alert {
            level: 2,
            description: 40,
        };
        let stops = [
            Stop::ServerHelloDone,
            handshake_failure.clone(),
            Stop::Alert {
                level: 2,
                description: 70,
            },
            Stop::Alert {
                level: 1,
                description: 40,
            },
            Stop::Encrypted,
            Stop::RetryComplete,
            Stop::Timeout,
            Stop::Closed,
            Stop::TooLarge,
            Stop::Failed("x".to_owned()),
        ];
        let expected = [
            (Scenario::Tls12, Stop::ServerHelloDone),
            (Scenario::Tls12Fragmented, Stop::ServerHelloDone),
            (Scenario::Tls12DheRsa, Stop::ServerHelloDone),
            (Scenario::Tls13, Stop::Encrypted),
            (Scenario::Tls13Hrr, Stop::RetryComplete),
            (Scenario::NoSharedCipher, handshake_failure),
        ];
        for (scenario, good) in &expected {
            assert_eq!(scenario.expected_stop(), *good);
            for stop in &stops {
                let verdict = check_outcome(*scenario, stop);
                assert_eq!(verdict.is_ok(), stop == good, "{scenario:?}: {stop:?}");
                if let Err(message) = verdict {
                    assert!(message.contains(scenario.name()), "{message}");
                    assert!(message.contains(good.code()), "{message}");
                    assert!(message.contains(stop.code()), "{message}");
                }
            }
        }
        // Итоги, которые не являются ожидаемыми ни для одного сценария.
        for stop in [
            Stop::Timeout,
            Stop::Closed,
            Stop::TooLarge,
            Stop::Failed("x".to_owned()),
        ] {
            for scenario in ALL_SCENARIOS {
                assert!(check_outcome(scenario, &stop).is_err());
            }
        }
    }

    #[test]
    fn stop_codes_are_distinct() {
        let stops = [
            Stop::ServerHelloDone,
            Stop::Alert {
                level: 2,
                description: 40,
            },
            Stop::Encrypted,
            Stop::RetryComplete,
            Stop::Timeout,
            Stop::Closed,
            Stop::TooLarge,
            Stop::Failed("x".to_owned()),
        ];
        let mut codes: Vec<&str> = stops.iter().map(Stop::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), stops.len());
        assert!(stops.iter().all(|stop| !stop.describe().is_empty()));
        assert_eq!(forced_outcome(&Stop::Failed("x".to_owned())), "error");
        assert_eq!(forced_outcome(&Stop::Timeout), "ok");
    }

    #[test]
    fn retry_support() {
        assert_eq!(retry_supported(Some(X25519), false), Ok(()));
        let error = retry_supported(Some(NamedGroup(0x0017)), false).unwrap_err();
        assert!(error.contains("0x0017"), "{error}");
        assert!(retry_supported(None, false).is_err());
        let error = retry_supported(Some(X25519), true).unwrap_err();
        assert!(error.contains("cookie"), "{error}");
    }

    #[test]
    fn capture_command_names_stand_and_server() {
        let list = args(&[
            "--addr",
            "127.0.0.1:4433",
            "--scenario",
            "tls12",
            "--server",
            "OpenSSL 4.1.0 23 Oct 2026",
            "--stand",
            "openssl-basic",
            "--force",
            "--timeout-ms",
            "100",
        ]);
        let mut options = parse_args(&list).unwrap();
        let random = [0xAB_u8; 32];
        let key = [0xCD_u8; 32];
        assert_eq!(
            capture_command(&options, &random, &key),
            format!(
                "cargo xtask record-fixture --addr 127.0.0.1:4433 --scenario tls12 --stand openssl-basic --server 'OpenSSL 4.1.0 23 Oct 2026' --random {}",
                "ab".repeat(32)
            )
        );
        for scenario in [Scenario::Tls13, Scenario::Tls13Hrr] {
            options.scenario = scenario;
            let command = capture_command(&options, &random, &key);
            assert!(
                command.ends_with(&format!(" --key-share {}", "cd".repeat(32))),
                "{command}"
            );
        }
    }

    #[test]
    fn meta_for_matched_and_forced_outcome() {
        let source = Source {
            stand: "openssl-basic",
            server: "OpenSSL 4.1.0 23 Oct 2026",
            server_command: "STAND_PORT=4434 tests/stands/openssl-basic/run.sh",
            capture_command: "cargo xtask record-fixture",
            date: "2026-11-11".to_owned(),
        };
        let matched = Meta {
            description: "d",
            direction: "server",
            request: Some("client"),
            second_request: Some(("client-after-hrr", 99)),
            length: 7,
            outcome: "ok",
            exchange: Some("retry_complete"),
            summary: "s",
            fields: vec![("version", "0x0304")],
            conditions: &[
                ("max_send_frag", "512"),
                ("handshake_message_spans_records", "true"),
            ],
        };
        let text = meta_toml(&matched, &source);
        // Условия стенда — в секции источника, а не среди ожидаемых полей.
        assert!(
            text.contains(
                "date = \"2026-11-11\"\n\n[source.conditions]\nmax_send_frag = \"512\"\nhandshake_message_spans_records = \"true\"\n\n[expected]\n"
            ),
            "{text}"
        );
        assert!(text.contains("request = \"client\"\n"), "{text}");
        assert!(text.contains("second_request = \"client-after-hrr\"\n"));
        assert!(text.contains("second_request_offset = 99\n"));
        assert!(text.contains("length = 7\n"));
        assert!(text.contains("server = \"OpenSSL 4.1.0 23 Oct 2026\"\n"));
        assert!(
            text.contains(
                "server_command = \"STAND_PORT=4434 tests/stands/openssl-basic/run.sh\"\n"
            )
        );
        assert!(text.contains("outcome = \"ok\"\n"));
        assert!(text.contains("exchange = \"retry_complete\"\n"));
        assert!(text.ends_with("[expected.fields]\nversion = \"0x0304\"\n"));

        // С --force: фактический итог, секции ожидаемых полей нет.
        let forced = Meta {
            description: "d",
            direction: "server",
            request: Some("client"),
            second_request: None,
            length: 7,
            outcome: forced_outcome(&Stop::Timeout),
            exchange: Some(Stop::Timeout.code()),
            summary: "записано с --force",
            fields: Vec::new(),
            conditions: &[],
        };
        let text = meta_toml(&forced, &source);
        assert!(!text.contains("[source.conditions]"), "{text}");
        assert!(text.contains("exchange = \"timeout\"\n"), "{text}");
        assert!(!text.contains("[expected.fields]"), "{text}");
        assert!(!text.contains("second_request"), "{text}");
        assert!(text.ends_with("summary = \"записано с --force\"\n"));
    }

    #[test]
    fn existing_fixtures_are_not_overwritten_without_force() {
        let dir = scratch_dir("overwrite");
        let first = [sample_file("one", 1), sample_file("two", 2)];
        write_fixtures(&dir, &first, false).unwrap();
        assert_eq!(fs::read_to_string(dir.join("one.hex")).unwrap(), "01\n");
        assert_eq!(fs::read_to_string(dir.join("two.hex")).unwrap(), "02\n");
        assert!(dir.join("two.meta.toml").exists());

        // Без --force не пишется ни один файл записи, даже новый.
        let second = [sample_file("three", 3), sample_file("two", 9)];
        let error = write_fixtures(&dir, &second, false).unwrap_err();
        assert!(error.contains("--force"), "{error}");
        assert!(error.contains("two"), "{error}");
        assert!(!dir.join("three.hex").exists());
        assert_eq!(fs::read_to_string(dir.join("two.hex")).unwrap(), "02\n");
        assert!(refuse_existing(&dir, &["three"]).is_ok());
        assert!(refuse_existing(&dir, &["three", "one"]).is_err());

        write_fixtures(&dir, &second, true).unwrap();
        assert_eq!(fs::read_to_string(dir.join("two.hex")).unwrap(), "09\n");
        assert_eq!(fs::read_to_string(dir.join("three.hex")).unwrap(), "03\n");

        // Временных файлов не осталось.
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "one.hex",
                "one.meta.toml",
                "three.hex",
                "three.meta.toml",
                "two.hex",
                "two.meta.toml",
            ]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Запись TLS с телом короче 256 байт.
    fn raw_record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            content_type,
            0x03,
            0x03,
            0x00,
            u8::try_from(body.len()).unwrap(),
        ];
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn detects_handshake_message_spanning_records() {
        let done = [0x0E, 0x00, 0x00, 0x00];
        let certificate = [0x0B, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];

        // Каждое сообщение целиком в своей записи.
        let mut whole = raw_record(22, &certificate);
        whole.extend(raw_record(22, &done));
        assert!(!handshake_spans_records(&whole));

        // Два сообщения в одной записи.
        let both = [certificate.as_slice(), done.as_slice()].concat();
        assert!(!handshake_spans_records(&raw_record(22, &both)));

        // Тело разбито между записями; заголовок разбит между записями.
        for cut in [5_usize, 2] {
            let mut split = raw_record(22, &certificate[..cut]);
            split.extend(raw_record(22, &certificate[cut..]));
            split.extend(raw_record(22, &done));
            assert!(handshake_spans_records(&split), "разрез {cut}");
            assert!(check_fragmentation(Scenario::Tls12Fragmented, &split).is_ok());
        }

        // Недособранное сообщение без продолжения, обрезанный и пустой поток.
        let mut dangling = raw_record(22, &certificate[..5]);
        dangling.extend(raw_record(21, &[0x02, 0x28]));
        assert!(!handshake_spans_records(&dangling));
        assert!(!handshake_spans_records(&whole[..whole.len() - 1]));
        assert!(!handshake_spans_records(&[0x16, 0x03]));
        assert!(!handshake_spans_records(&[]));

        // Проверка применяется только к сценарию с фрагментацией.
        for scenario in ALL_SCENARIOS {
            let verdict = check_fragmentation(scenario, &whole);
            assert_eq!(
                verdict.is_ok(),
                scenario != Scenario::Tls12Fragmented,
                "{scenario:?}"
            );
        }
        let error = check_fragmentation(Scenario::Tls12Fragmented, &whole).unwrap_err();
        assert!(error.contains("tls12-fragmented"), "{error}");
    }

    #[test]
    fn fragmented_scenario_reuses_tls12_hello_and_names_stand_variant() {
        let random = [0x11_u8; 32];
        let key = [0x42_u8; 32];
        let plain = Scenario::Tls12.build(random, &key).unwrap();
        let fragmented = Scenario::Tls12Fragmented.build(random, &key).unwrap();
        assert_eq!(
            plain.record_bytes().unwrap(),
            fragmented.record_bytes().unwrap()
        );

        assert_eq!(
            Scenario::Tls12.server_command("openssl-basic"),
            "tests/stands/openssl-basic/run.sh"
        );
        let command = Scenario::Tls12Fragmented.server_command("openssl-basic");
        assert!(
            command.starts_with(
                "STAND_PORT=4434 STAND_MAX_SEND_FRAG=512 STAND_EXTRA_SAN=DNS:fragment-padding-01.stand.localhost,"
            ),
            "{command}"
        );
        assert!(
            command.ends_with(
                "DNS:fragment-padding-08.stand.localhost tests/stands/openssl-basic/run.sh"
            ),
            "{command}"
        );
        assert_eq!(
            Scenario::Tls12Fragmented.server_fixture("openssl-basic"),
            "tls12-serverhello-openssl-basic-max-send-frag"
        );
        assert_eq!(
            Scenario::Tls12Fragmented.client_fixture("openssl-basic"),
            "tls12-clienthello-openssl-basic-max-send-frag"
        );
    }

    #[test]
    fn failed_write_leaves_no_temporary_files() {
        let dir = scratch_dir("missing").join("absent");
        let error = write_fixtures(&dir, &[sample_file("one", 1)], false).unwrap_err();
        assert!(error.contains("не удалось записать"), "{error}");
        assert!(!dir.exists());
        fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn operation_timeout_is_capped_by_deadline() {
        let start = Instant::now();
        let timeout = Duration::from_millis(100);
        let deadline = read_deadline(start, timeout).unwrap();
        assert_eq!(deadline.duration_since(start), timeout * EXCHANGE_TIMEOUTS);

        // Пока до дедлайна далеко — полный таймаут, затем остаток.
        assert_eq!(remaining_timeout(deadline, start, timeout), Some(timeout));
        let late = start + Duration::from_millis(250);
        assert_eq!(
            remaining_timeout(deadline, late, timeout),
            Some(Duration::from_millis(50))
        );
        // Дедлайн наступил или пройден: операцию начинать нельзя.
        assert_eq!(remaining_timeout(deadline, deadline, timeout), None);
        assert_eq!(
            remaining_timeout(deadline, deadline + timeout, timeout),
            None
        );
    }

    /// Первый результат декодера, отличный от `NeedMore`.
    fn first_step(decoder: &mut Decoder, bytes: &[u8]) -> Step {
        let mut input = bytes;
        let mut step = Step::NeedMore;
        for _ in 0..4 {
            step = feed_step(decoder, &mut input);
            if !matches!(step, Step::NeedMore) {
                break;
            }
        }
        step
    }

    #[test]
    fn response_volume_has_single_outcome() {
        assert_eq!(decoder_limits().max_total_bytes, MAX_RESPONSE_BYTES);
        assert_eq!(
            ParseLimits {
                max_total_bytes: ParseLimits::default().max_total_bytes,
                ..decoder_limits()
            },
            ParseLimits::default()
        );

        // Название лимита сверяется с ошибкой, которую выдаёт сам tls-probe.
        let total = ParseLimits::default()
            .check_total_bytes(usize::MAX, 0)
            .unwrap_err();
        assert!(is_total_bytes_limit(&total), "{total}");
        let record = ParseLimits::default()
            .check_record_len(usize::MAX, 0)
            .unwrap_err();
        assert!(!is_total_bytes_limit(&record), "{record}");

        // Лимит общего объёма в декодере — итог too_large, а не parse_error.
        let limits = ParseLimits {
            max_total_bytes: 8,
            ..decoder_limits()
        };
        let mut decoder = Decoder::new(limits);
        let bytes = raw_record(22, &[0x0E, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00]);
        let step = first_step(&mut decoder, &bytes);
        assert!(matches!(step, Step::TooLarge), "{step:?}");
        assert_eq!(Stop::TooLarge.code(), "too_large");

        // Другие лимиты остаются ошибкой разбора: запись длиной 18433 байта.
        let mut decoder = Decoder::new(decoder_limits());
        let step = first_step(&mut decoder, &[0x16, 0x03, 0x03, 0x48, 0x01]);
        assert!(
            matches!(&step, Step::Failed(reason) if reason.contains("max_record_len")),
            "{step:?}"
        );
    }

    #[test]
    fn forced_write_needs_second_hello_in_retry_scenario() {
        // Сценарий с HRR без отправленного второго ClientHello: отказ.
        let error = check_forced_layout(Scenario::Tls13Hrr, false).unwrap_err();
        assert!(error.contains("tls13-hrr"), "{error}");
        assert!(error.contains("--force"), "{error}");
        assert_eq!(check_forced_layout(Scenario::Tls13Hrr, true), Ok(()));
        // Остальные сценарии пишут одну серверную фикстуру.
        for scenario in [
            Scenario::Tls12,
            Scenario::Tls12Fragmented,
            Scenario::Tls12DheRsa,
            Scenario::Tls13,
            Scenario::NoSharedCipher,
        ] {
            assert_eq!(check_forced_layout(scenario, false), Ok(()));
        }
    }

    #[test]
    fn stand_conditions_are_not_expected_fields() {
        assert_eq!(
            Scenario::Tls12Fragmented.stand_conditions(),
            [
                ("max_send_frag", "512"),
                ("handshake_message_spans_records", "true"),
            ]
        );
        assert_eq!(
            Scenario::Tls12DheRsa.stand_conditions(),
            [("key_type", "rsa"), ("cipher", "DHE-RSA-AES256-GCM-SHA384")]
        );
        // Условия из метаданных совпадают с переменными команды запуска.
        let command = Scenario::Tls12DheRsa.server_command("openssl-basic");
        assert_eq!(
            command,
            "STAND_PORT=4435 STAND_KEY_TYPE=rsa STAND_CIPHER=DHE-RSA-AES256-GCM-SHA384 tests/stands/openssl-basic/run.sh"
        );
        for scenario in ALL_SCENARIOS {
            for (condition, _) in scenario.stand_conditions() {
                assert!(
                    scenario
                        .server_fields()
                        .iter()
                        .all(|(key, _)| key != condition),
                    "{scenario:?}: {condition}"
                );
            }
            let has_conditions =
                matches!(scenario, Scenario::Tls12Fragmented | Scenario::Tls12DheRsa);
            assert_eq!(
                !scenario.stand_conditions().is_empty(),
                has_conditions,
                "{scenario:?}"
            );
        }
    }
}
