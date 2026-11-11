//! Тесты на фикстурах крейта: `crates/tls-probe/tests/fixtures/*.hex` и
//! `*.meta.toml`, записанные подкомандой `cargo xtask record-fixture` со
//! стенда `openssl-basic`. Формат — `tests/fixtures/README.md` в корне
//! репозитория.
//!
//! Ожидаемые значения в `assert` совпадают с `[expected]` в `.meta.toml` и
//! сверены независимо от парсера: шифр и версия — по выводу
//! `openssl s_client` к тому же стенду, HelloRetryRequest — ручным разбором
//! hex. Из `.meta.toml` тесты читают отдельные ключи (`length`, `request`,
//! сведения об источнике) упрощённым разбором, см. [`Fixture::meta_value`];
//! TOML-парсер в зависимостях не нужен.

use tls_data::{AlertDescription, CipherSuite, NamedGroup, SignatureScheme};

use crate::alert::{Alert, AlertLevel};
use crate::client_hello::{ClientHello, ClientHelloView};
use crate::codec::Reader;
use crate::decoder::{Decoder, Event};
use crate::ext::{Extension, KeyShareEntry, kind};
use crate::handshake::ServerMessage;
use crate::limits::ParseLimits;
use crate::record::{ContentType, HandshakeType, ProtocolVersion, Record};
use crate::server_hello::{
    DowngradeMarker, HELLO_RETRY_REQUEST_RANDOM, RANDOM_LEN, ServerExtension, ServerHello,
    ServerKeyShare,
};
use crate::server_kx::{EcCurveType, KeyExchangeKind, ServerKeyExchange};

/// Пара «hex, метаданные» одной фикстуры.
struct Fixture {
    name: &'static str,
    hex: &'static str,
    meta: &'static str,
}

macro_rules! fixture {
    ($name:literal) => {
        Fixture {
            name: $name,
            hex: include_str!(concat!("../tests/fixtures/", $name, ".hex")),
            meta: include_str!(concat!("../tests/fixtures/", $name, ".meta.toml")),
        }
    };
}

const TLS12_CLIENT: Fixture = fixture!("tls12-clienthello-openssl-basic");
const TLS12_SERVER: Fixture = fixture!("tls12-serverhello-openssl-basic");
const TLS13_CLIENT: Fixture = fixture!("tls13-clienthello-openssl-basic");
const TLS13_SERVER: Fixture = fixture!("tls13-serverhello-openssl-basic");
const HRR_CLIENT: Fixture = fixture!("tls13-clienthello-openssl-basic-no-key-share");
const HRR_SERVER: Fixture = fixture!("tls13-hrr-openssl-basic");
const HRR_SECOND_CLIENT: Fixture = fixture!("tls13-clienthello-openssl-basic-after-hrr");
const HRR_EXCHANGE: Fixture = fixture!("tls13-serverhello-openssl-basic-after-hrr");
const ALERT_CLIENT: Fixture = fixture!("tls12-clienthello-openssl-basic-rsa-only");
const ALERT_SERVER: Fixture = fixture!("tls12-alert-openssl-basic-no-shared-cipher");
const FRAGMENTED_CLIENT: Fixture = fixture!("tls12-clienthello-openssl-basic-max-send-frag");
const FRAGMENTED_SERVER: Fixture = fixture!("tls12-serverhello-openssl-basic-max-send-frag");
const DHE_RSA_CLIENT: Fixture = fixture!("tls12-clienthello-openssl-basic-dhe-rsa");
const DHE_RSA_SERVER: Fixture = fixture!("tls12-serverhello-openssl-basic-dhe-rsa");

const ALL: [&Fixture; 12] = [
    &TLS12_CLIENT,
    &TLS12_SERVER,
    &TLS13_CLIENT,
    &TLS13_SERVER,
    &HRR_CLIENT,
    &HRR_SERVER,
    &HRR_SECOND_CLIENT,
    &HRR_EXCHANGE,
    &ALERT_CLIENT,
    &ALERT_SERVER,
    &FRAGMENTED_CLIENT,
    &FRAGMENTED_SERVER,
];

/// Порции, которыми фикстуры подаются в декодер.
const CHUNKS: [usize; 7] = [1_usize, 2, 3, 5, 7, 64, 100];

impl Fixture {
    /// Строки `.hex` с данными: строки-комментарии, начинающиеся с `#`,
    /// пропускаются (формат их разрешает).
    fn data_lines(&self) -> impl Iterator<Item = &'static str> {
        self.hex.lines().filter(|line| !line.starts_with('#'))
    }

    /// Байты фикстуры: комментарии и пробелы пропускаются.
    fn bytes(&self) -> Vec<u8> {
        self.data_lines()
            .flat_map(str::split_whitespace)
            .map(|pair| u8::from_str_radix(pair, 16).unwrap())
            .collect()
    }

    /// Значение ключа из секции метаданных; `section` — имя секции без
    /// скобок (`"source"`, `"source.conditions"`, `"expected"`,
    /// `"expected.fields"`) или пустая строка для ключей до первой секции.
    ///
    /// Это не TOML-парсер, а разбор подмножества, которое пишет
    /// `cargo xtask record-fixture`: одна пара `ключ = значение` в строке,
    /// заголовок секции отдельной строкой, значение — целое число или
    /// строка в двойных кавычках. Кавычки снимаются, escape-
    /// последовательности не раскрываются; многострочные строки, массивы и
    /// встроенные таблицы не поддерживаются.
    fn meta_value(&self, section: &str, key: &str) -> Option<&'static str> {
        let prefix = format!("{key} = ");
        let mut current = "";
        for line in self.meta.lines() {
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                current = name;
            } else if current == section
                && let Some(value) = line.strip_prefix(prefix.as_str())
            {
                return Some(value.trim().trim_matches('"'));
            }
        }
        None
    }
}

/// Событие декодера с владеющими копиями данных. Записи, которые декодер не
/// разбирает, различаются по варианту события: `ApplicationData` (запись
/// `application_data` до ChangeCipherSpec) и `Opaque` (любая запись после
/// ChangeCipherSpec, `heartbeat`, неизвестный тип) — см. `docs/DECISIONS.md`,
/// D-14.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Handshake(HandshakeType, Vec<u8>),
    Alert(Vec<u8>),
    ChangeCipherSpec,
    /// Событие `ApplicationData`: длина тела записи.
    ApplicationData(usize),
    /// Событие `Opaque`: тип содержимого и длина тела записи.
    Opaque(ContentType, usize),
}

impl Seen {
    /// Истина для записи, которую декодер отдал без разбора.
    fn is_uninterpreted(&self) -> bool {
        matches!(self, Self::ApplicationData(_) | Self::Opaque(..))
    }
}

/// Пропускает байты через декодер порциями по `chunk` байтов. Ручных
/// вызовов `resume_plaintext` нет.
fn decode(bytes: &[u8], chunk: usize) -> (Vec<Seen>, Decoder) {
    let mut decoder = Decoder::default();
    let mut seen = Vec::new();
    for part in bytes.chunks(chunk) {
        let mut input = part;
        loop {
            match decoder.feed(&mut input).unwrap() {
                Event::NeedMore => break,
                Event::Handshake(message) => {
                    seen.push(Seen::Handshake(message.msg_type, message.body.to_vec()));
                }
                Event::Alert(body) => seen.push(Seen::Alert(body.to_vec())),
                Event::ChangeCipherSpec => seen.push(Seen::ChangeCipherSpec),
                Event::ApplicationData(body) => seen.push(Seen::ApplicationData(body.len())),
                Event::Opaque(record) => {
                    seen.push(Seen::Opaque(record.content_type, record.fragment.len()));
                }
            }
        }
    }
    (seen, decoder)
}

fn handshake_body(seen: &[Seen], index: usize) -> (HandshakeType, &[u8]) {
    match seen.get(index) {
        Some(Seen::Handshake(msg_type, body)) => (*msg_type, body.as_slice()),
        other => panic!("событие {index}: ожидалось handshake-сообщение, получено {other:?}"),
    }
}

/// Записи потока: тип содержимого и длина тела.
fn records(bytes: &[u8]) -> Vec<(ContentType, usize)> {
    let limits = ParseLimits::default();
    let mut reader = Reader::new(bytes);
    let mut list = Vec::new();
    while !reader.is_empty() {
        let record = Record::parse(&mut reader, &limits).unwrap();
        list.push((record.content_type, record.fragment.len()));
    }
    list
}

/// Смещение `random` в записанном ClientHello: после заголовков записи
/// (5 байтов) и сообщения (4 байта) и поля версии (2 байта).
const CLIENT_RANDOM_OFFSET: usize = 5 + 4 + 2;

/// `random` из записанного ClientHello.
fn client_random(bytes: &[u8]) -> [u8; RANDOM_LEN] {
    bytes
        .get(CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + RANDOM_LEN)
        .unwrap()
        .try_into()
        .unwrap()
}

fn groups() -> [NamedGroup; 3] {
    [NamedGroup(0x001D), NamedGroup(0x0017), NamedGroup(0x0018)]
}

fn schemes() -> [SignatureScheme; 6] {
    [
        SignatureScheme(0x0403),
        SignatureScheme(0x0503),
        SignatureScheme(0x0804),
        SignatureScheme(0x0805),
        SignatureScheme(0x0401),
        SignatureScheme(0x0501),
    ]
}

/// ClientHello TLS 1.2 из сценариев `tls12` и `tls12-fragmented`.
fn tls12_hello(random: [u8; RANDOM_LEN]) -> ClientHello {
    ClientHello::new(random)
        .with_cipher_suites([0xC02C_u16, 0xC02B, 0xCCA9, 0x00FF])
        .with_extensions([
            Extension::server_name(b"localhost").unwrap(),
            Extension::supported_groups(&groups()).unwrap(),
            Extension::ec_point_formats(&[0x00]).unwrap(),
            Extension::signature_algorithms(&schemes()).unwrap(),
            Extension::extended_master_secret(),
            Extension::session_ticket(&[]),
        ])
}

/// ClientHello TLS 1.3 из сценариев записи; `key_share` — список записей.
fn tls13_hello(random: [u8; RANDOM_LEN], shares: &[KeyShareEntry<'_>]) -> ClientHello {
    let session_id: Vec<u8> = random.iter().map(|byte| !byte).collect();
    ClientHello::new(random)
        .with_session_id(&session_id)
        .with_cipher_suites([0x1302_u16, 0x1301, 0x1303])
        .with_extensions([
            Extension::server_name(b"localhost").unwrap(),
            Extension::supported_versions(&[ProtocolVersion::TLS1_3]).unwrap(),
            Extension::supported_groups(&groups()).unwrap(),
            Extension::signature_algorithms(&schemes()).unwrap(),
            Extension::psk_key_exchange_modes(&[0x01]).unwrap(),
            Extension::key_share(shares).unwrap(),
        ])
}

/// Разбирает ServerHello TLS 1.2 стенда и проверяет поля, общие для обычного
/// и фрагментированного ответа.
fn assert_tls12_server_hello(body: &[u8]) {
    let hello = ServerHello::parse(body).unwrap();
    assert_eq!(hello.legacy_version, ProtocolVersion::TLS1_2);
    assert_eq!(hello.version(), ProtocolVersion::TLS1_2);
    assert_eq!(hello.cipher_suite, CipherSuite(0xC02C));
    // Тот же шифр показывает `openssl s_client -tls1_2` к стенду.
    assert_eq!(
        hello.cipher_suite.openssl_name(),
        Some("ECDHE-ECDSA-AES256-GCM-SHA384")
    );
    assert_eq!(hello.compression_method, 0);
    assert!(hello.session_id.is_empty());
    assert!(!hello.is_hello_retry_request());
    // Стенд умеет TLS 1.3 и помечает согласование TLS 1.2.
    assert_eq!(hello.downgrade_marker(), Some(DowngradeMarker::Tls12));
    assert_eq!(hello.anomalies(), Vec::new());

    let extensions: Vec<_> = hello.extensions().collect();
    assert_eq!(
        extensions,
        vec![
            ServerExtension::RenegotiationInfo(&[]),
            ServerExtension::EcPointFormats(&[0x00]),
            ServerExtension::SessionTicket,
            ServerExtension::ExtendedMasterSecret,
        ]
    );
    assert_eq!(hello.extension(kind::SUPPORTED_VERSIONS), None);
}

#[test]
fn meta_value_respects_sections() {
    let fixture = Fixture {
        name: "synthetic",
        hex: "",
        meta: "length = 7\nversion = \"top\"\n\n[source]\nkind = \"stand\"\n\n[source.conditions]\nmax_send_frag = \"512\"\n\n[expected]\noutcome = \"ok\"\n\n[expected.fields]\nversion = \"0x0304\"\nlength = \"field\"\n",
    };
    // Условия стенда — отдельная секция: ни в `source`, ни в ожидаемых полях
    // их нет.
    assert_eq!(
        fixture.meta_value("source.conditions", "max_send_frag"),
        Some("512")
    );
    assert_eq!(fixture.meta_value("source", "max_send_frag"), None);
    assert_eq!(fixture.meta_value("expected.fields", "max_send_frag"), None);
    assert_eq!(fixture.meta_value("source.conditions", "kind"), None);
    assert_eq!(fixture.meta_value("", "length"), Some("7"));
    assert_eq!(fixture.meta_value("", "version"), Some("top"));
    assert_eq!(fixture.meta_value("source", "kind"), Some("stand"));
    assert_eq!(fixture.meta_value("expected", "outcome"), Some("ok"));
    assert_eq!(
        fixture.meta_value("expected.fields", "version"),
        Some("0x0304")
    );
    assert_eq!(
        fixture.meta_value("expected.fields", "length"),
        Some("field")
    );
    // Ключ из другой секции не находится.
    assert_eq!(fixture.meta_value("", "kind"), None);
    assert_eq!(fixture.meta_value("source", "outcome"), None);
    assert_eq!(fixture.meta_value("expected", "version"), None);
    assert_eq!(fixture.meta_value("missing", "length"), None);
}

#[test]
fn hex_comments_are_skipped() {
    let fixture = Fixture {
        name: "synthetic",
        hex: "# SYNTHETIC: составлено вручную, не запись сервера\n16 03 03\n# ещё комментарий\n00 01\n",
        meta: "",
    };
    assert_eq!(fixture.bytes(), vec![0x16, 0x03, 0x03, 0x00, 0x01]);
    assert_eq!(fixture.data_lines().count(), 2);
}

#[test]
fn fixtures_follow_the_format() {
    for fixture in ALL {
        let bytes = fixture.bytes();
        let length: usize = fixture.meta_value("", "length").unwrap().parse().unwrap();
        assert_eq!(bytes.len(), length, "{}: length", fixture.name);
        assert_eq!(
            fixture.meta_value("", "format"),
            Some("1"),
            "{}",
            fixture.name
        );
        assert_eq!(
            fixture.meta_value("source", "kind"),
            Some("stand"),
            "{}",
            fixture.name
        );
        assert_eq!(
            fixture.meta_value("source", "stand"),
            Some("openssl-basic"),
            "{}",
            fixture.name
        );
        assert!(
            fixture
                .meta_value("source", "server")
                .unwrap()
                .starts_with("OpenSSL "),
            "{}",
            fixture.name
        );
        assert!(
            fixture
                .meta_value("source", "server_command")
                .unwrap()
                .ends_with("tests/stands/openssl-basic/run.sh"),
            "{}",
            fixture.name
        );
        let command = fixture.meta_value("source", "capture_command").unwrap();
        assert!(
            command.starts_with("cargo xtask record-fixture --addr 127.0.0.1:"),
            "{}",
            fixture.name
        );
        // Стенд и версию сервера задаёт тот, кто запускает запись.
        assert!(
            command.contains(" --stand openssl-basic --server 'OpenSSL "),
            "{}",
            fixture.name
        );
        assert_eq!(
            fixture.meta_value("expected", "outcome"),
            Some("ok"),
            "{}",
            fixture.name
        );
        assert!(
            fixture.meta_value("expected", "summary").is_some(),
            "{}",
            fixture.name
        );

        // Строки данных: нижний регистр, не более 16 байтов в строке.
        // Строки-комментарии формат разрешает; в записанных фикстурах их нет.
        for line in fixture.data_lines() {
            assert!(line.split_whitespace().count() <= 16, "{}", fixture.name);
            assert!(
                line.bytes().all(|byte| byte == b' '
                    || byte.is_ascii_digit()
                    || (b'a'..=b'f').contains(&byte)),
                "{}: {line}",
                fixture.name
            );
        }
    }

    // Ответы ссылаются на свои запросы и хранят итог обмена.
    for (server, client, exchange) in [
        (&TLS12_SERVER, &TLS12_CLIENT, "server_hello_done"),
        (&TLS13_SERVER, &TLS13_CLIENT, "encrypted"),
        (&HRR_SERVER, &HRR_CLIENT, "retry_complete"),
        (&HRR_EXCHANGE, &HRR_CLIENT, "retry_complete"),
        (&ALERT_SERVER, &ALERT_CLIENT, "alert"),
        (&FRAGMENTED_SERVER, &FRAGMENTED_CLIENT, "server_hello_done"),
    ] {
        assert_eq!(server.meta_value("", "direction"), Some("server"));
        assert_eq!(client.meta_value("", "direction"), Some("client"));
        assert_eq!(server.meta_value("", "request"), Some(client.name));
        assert_eq!(client.meta_value("", "request"), None);
        assert_eq!(
            server.meta_value("expected", "exchange"),
            Some(exchange),
            "{}",
            server.name
        );
        assert_eq!(client.meta_value("expected", "exchange"), None);
    }

    // Второй запрос есть только у полного обмена с HelloRetryRequest.
    assert_eq!(
        HRR_SECOND_CLIENT.meta_value("", "direction"),
        Some("client")
    );
    for fixture in ALL {
        let expected = (fixture.name == HRR_EXCHANGE.name).then_some(HRR_SECOND_CLIENT.name);
        assert_eq!(
            fixture.meta_value("", "second_request"),
            expected,
            "{}",
            fixture.name
        );
        assert_eq!(
            fixture.meta_value("", "second_request_offset").is_some(),
            expected.is_some(),
            "{}",
            fixture.name
        );
    }
}

#[test]
fn builder_reproduces_tls12_client_hello() {
    let bytes = TLS12_CLIENT.bytes();
    let hello = tls12_hello(client_random(&bytes));
    assert_eq!(hello.record_bytes().unwrap(), bytes);

    let (seen, decoder) = decode(&bytes, bytes.len());
    assert!(decoder.is_idle());
    let (msg_type, body) = handshake_body(&seen, 0);
    assert_eq!(msg_type, HandshakeType::CLIENT_HELLO);
    let view = ClientHelloView::parse(body).unwrap();
    assert_eq!(view.legacy_version, ProtocolVersion::TLS1_2);
    assert!(view.session_id.is_empty());
    assert_eq!(
        view.cipher_suites().map(u16::from).collect::<Vec<_>>(),
        vec![0xC02C, 0xC02B, 0xCCA9, 0x00FF]
    );
    let extension_types: Vec<u16> = view
        .extensions()
        .map(|extension| extension.unwrap().ext_type.0)
        .collect();
    assert_eq!(
        extension_types,
        vec![0x0000, 0x000A, 0x000B, 0x000D, 0x0017, 0x0023]
    );

    // Вариант стенда с фрагментацией получает тот же ClientHello.
    assert_eq!(FRAGMENTED_CLIENT.bytes(), bytes);
}

#[test]
fn builder_reproduces_tls13_client_hello() {
    let bytes = TLS13_CLIENT.bytes();
    // key_share — последнее расширение, публичное значение — последние 32 байта.
    let public = bytes.last_chunk::<32>().unwrap();
    let hello = tls13_hello(
        client_random(&bytes),
        &[KeyShareEntry {
            group: NamedGroup(0x001D),
            key_exchange: public,
        }],
    );
    assert_eq!(hello.record_bytes().unwrap(), bytes);

    let body = hello.body_bytes().unwrap();
    let view = ClientHelloView::parse(&body).unwrap();
    assert_eq!(view.session_id.len(), 32);
    assert_eq!(view.extensions().count(), 6);
}

#[test]
fn builder_reproduces_client_hello_without_key_share() {
    let bytes = HRR_CLIENT.bytes();
    let hello = tls13_hello(client_random(&bytes), &[]);
    assert_eq!(hello.record_bytes().unwrap(), bytes);
    // Пустой список key_share: тип, длина 2, пустой вектор.
    assert!(bytes.ends_with(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x00]));
}

#[test]
fn builder_reproduces_second_client_hello_after_retry() {
    let first = HRR_CLIENT.bytes();
    let bytes = HRR_SECOND_CLIENT.bytes();
    // Тот же random, что в первом ClientHello.
    assert_eq!(client_random(&bytes), client_random(&first));

    let public = bytes.last_chunk::<32>().unwrap();
    let hello = tls13_hello(
        client_random(&bytes),
        &[KeyShareEntry {
            group: NamedGroup(0x001D),
            key_exchange: public,
        }],
    );
    assert_eq!(hello.record_bytes().unwrap(), bytes);

    // Те же session_id, шифры и типы расширений; отличие — только key_share.
    let (first_seen, _) = decode(&first, first.len());
    let (second_seen, _) = decode(&bytes, bytes.len());
    let (_, first_body) = handshake_body(&first_seen, 0);
    let (_, second_body) = handshake_body(&second_seen, 0);
    let first_view = ClientHelloView::parse(first_body).unwrap();
    let second_view = ClientHelloView::parse(second_body).unwrap();
    assert_eq!(first_view.session_id, second_view.session_id);
    assert_eq!(
        first_view
            .cipher_suites()
            .map(u16::from)
            .collect::<Vec<_>>(),
        second_view
            .cipher_suites()
            .map(u16::from)
            .collect::<Vec<_>>()
    );
    let types = |view: &ClientHelloView<'_>| -> Vec<u16> {
        view.extensions()
            .map(|extension| extension.unwrap().ext_type.0)
            .collect()
    };
    assert_eq!(types(&first_view), types(&second_view));
    assert_eq!(bytes.len(), first.len() + 4 + public.len());
}

#[test]
fn builder_reproduces_rsa_only_client_hello() {
    let bytes = ALERT_CLIENT.bytes();
    let hello = ClientHello::new(client_random(&bytes))
        .with_cipher_suites([0x009D_u16, 0x009C, 0x003D, 0x002F])
        .with_extensions([
            Extension::server_name(b"localhost").unwrap(),
            Extension::signature_algorithms(&schemes()).unwrap(),
            Extension::extended_master_secret(),
        ]);
    assert_eq!(hello.record_bytes().unwrap(), bytes);
}

#[test]
fn tls12_server_hello() {
    let bytes = TLS12_SERVER.bytes();
    let (seen, decoder) = decode(&bytes, bytes.len());
    assert!(decoder.is_idle());
    assert!(!decoder.is_opaque());
    assert_eq!(decoder.stream_offset(), bytes.len());
    assert_eq!(seen.len(), 4);

    let (msg_type, body) = handshake_body(&seen, 0);
    assert_eq!(msg_type, HandshakeType::SERVER_HELLO);
    assert_tls12_server_hello(body);

    // Certificate и ServerKeyExchange диспетчер по-прежнему отдаёт как тип и
    // тело; разбор — отдельным вызовом (P1-07).
    //
    // Ожидаемые значения относятся к этой записи и получены независимо от
    // парсера, из байтов фикстуры: границы сообщений и полей — разбором hex
    // по смещениям, сертификат — `openssl x509 -inform DER -noout -text` и
    // `openssl asn1parse` над DER, извлечённым во временный файл. Сертификат
    // стенда создаётся заново при каждом запуске, а длина DER-подписи ECDSA
    // меняется от записи к записи (70 – 72 байта), поэтому после перезаписи
    // фикстуры длины ниже нужно сверить заново.
    let (msg_type, body) = handshake_body(&seen, 1);
    let message = ServerMessage::parse(msg_type, body).unwrap();
    assert!(matches!(message, ServerMessage::Certificate(raw) if raw == body));
    let certificates = message
        .certificates(&ParseLimits::default())
        .unwrap()
        .unwrap();
    // Один сертификат: CN=localhost, ключ id-ecPublicKey P-256, подпись
    // ecdsa-with-SHA256 (самоподписанный).
    assert_eq!(certificates.len(), 1);
    assert_eq!(certificates.iter().count(), 1);
    let der = certificates.first().unwrap();
    assert_eq!(der.len(), 380);
    // DER начинается с SEQUENCE, длина которой записана двумя байтами и
    // покрывает весь срез: парсер не захватил лишнего и не обрезал.
    assert!(der.starts_with(&[0x30, 0x82]));
    let declared = der.get(2..4).map(|len| {
        len.iter()
            .fold(0_usize, |acc, byte| (acc << 8) | usize::from(*byte))
    });
    assert_eq!(declared, Some(der.len() - 4));

    let (msg_type, body) = handshake_body(&seen, 2);
    let message = ServerMessage::parse(msg_type, body).unwrap();
    assert!(matches!(message, ServerMessage::ServerKeyExchange(raw) if raw == body));
    // Вид key exchange выводится из шифра ServerHello так же, как это
    // делает вызывающий код: ECDHE-ECDSA-AES256-GCM-SHA384, Kx=ECDH, Au=ECDSA.
    let kind = KeyExchangeKind::from_optional_info(CipherSuite(0xC02C).info());
    assert_eq!(kind, KeyExchangeKind::Ecdhe { signed: true });
    let exchange = message
        .server_key_exchange(ProtocolVersion::TLS1_2, kind)
        .unwrap()
        .unwrap();
    let ServerKeyExchange::Ecdhe {
        params,
        signed_params,
        signature,
    } = exchange
    else {
        panic!("ожидался ECDHE, получено {exchange:?}");
    };
    assert_eq!(params.curve_type, EcCurveType::NAMED_CURVE);
    // x25519 (0x001d), точка 32 байта.
    assert_eq!(params.named_curve, NamedGroup(0x001D));
    assert_eq!(params.point.len(), 32);
    // curve_type, named_curve, длина точки и сама точка.
    assert_eq!(signed_params.len(), 1 + 2 + 1 + 32);
    let signature = signature.unwrap();
    // ecdsa_secp256r1_sha256 (0x0403); подпись — DER SEQUENCE из 70 байт.
    assert_eq!(signature.scheme, Some(SignatureScheme(0x0403)));
    assert_eq!(signature.signature.len(), 72);
    assert!(signature.signature.starts_with(&[0x30, 0x46]));
    // Сообщения других типов этими методами не разбираются.
    assert!(message.certificates(&ParseLimits::default()).is_none());

    let (msg_type, body) = handshake_body(&seen, 3);
    assert!(matches!(
        ServerMessage::parse(msg_type, body).unwrap(),
        ServerMessage::ServerHelloDone
    ));

    // Без ограничения фрагмента каждое сообщение пришло в своей записи.
    let layout = records(&bytes);
    assert_eq!(layout.len(), 4);
    assert!(
        layout
            .iter()
            .all(|(content_type, _)| *content_type == ContentType::HANDSHAKE)
    );
}

#[test]
fn builder_reproduces_dhe_rsa_client_hello() {
    let bytes = DHE_RSA_CLIENT.bytes();
    let hello = ClientHello::new(client_random(&bytes))
        .with_cipher_suites([0x009F_u16, 0x009E, 0x00FF])
        .with_extensions([
            Extension::server_name(b"localhost").unwrap(),
            Extension::supported_groups(&groups()).unwrap(),
            Extension::signature_algorithms(&schemes()).unwrap(),
            Extension::extended_master_secret(),
            Extension::session_ticket(&[]),
        ]);
    assert_eq!(hello.record_bytes().unwrap(), bytes);
}

#[test]
fn tls12_dhe_rsa_server_key_exchange() {
    // Вариант стенда с RSA-сертификатом и шифром DHE-RSA: условия записи
    // лежат в `[source.conditions]`, а не в ожидаемых полях.
    assert_eq!(
        DHE_RSA_SERVER.meta_value("source.conditions", "key_type"),
        Some("rsa")
    );
    assert_eq!(
        DHE_RSA_SERVER.meta_value("source.conditions", "cipher"),
        Some("DHE-RSA-AES256-GCM-SHA384")
    );
    assert_eq!(
        DHE_RSA_SERVER.meta_value("expected", "exchange"),
        Some("server_hello_done")
    );

    let bytes = DHE_RSA_SERVER.bytes();
    let (seen, decoder) = decode(&bytes, bytes.len());
    assert!(decoder.is_idle());
    assert_eq!(decoder.stream_offset(), bytes.len());
    assert_eq!(seen.len(), 4);

    let (msg_type, body) = handshake_body(&seen, 0);
    assert_eq!(msg_type, HandshakeType::SERVER_HELLO);
    let hello = ServerHello::parse(body).unwrap();
    assert_eq!(hello.version(), ProtocolVersion::TLS1_2);
    assert_eq!(hello.cipher_suite, CipherSuite(0x009F));
    // Тот же шифр показал `openssl s_client -tls1_2` к этому варианту
    // стенда (строка «Cipher is»).
    assert_eq!(
        hello.cipher_suite.openssl_name(),
        Some("DHE-RSA-AES256-GCM-SHA384")
    );
    assert!(hello.session_id.is_empty());
    assert_eq!(hello.downgrade_marker(), Some(DowngradeMarker::Tls12));
    // Шифр без эллиптических кривых: ec_point_formats сервер не отправил.
    let extensions: Vec<_> = hello.extensions().collect();
    assert_eq!(
        extensions,
        vec![
            ServerExtension::RenegotiationInfo(&[]),
            ServerExtension::SessionTicket,
            ServerExtension::ExtendedMasterSecret,
        ]
    );

    // Ожидаемые значения ниже получены независимо от парсера из байтов этой
    // фикстуры: границы сообщений и полей — разбором hex по смещениям
    // (скрипт на Python), сертификат — `openssl x509 -inform DER -noout
    // -text` над DER, извлечённым во временный файл. Сертификат стенда
    // создаётся заново при каждом запуске, но длины здесь от записи к записи
    // меняться не должны: подпись RSA 2048 всегда занимает 256 байт.
    let (msg_type, body) = handshake_body(&seen, 1);
    let message = ServerMessage::parse(msg_type, body).unwrap();
    let certificates = message
        .certificates(&ParseLimits::default())
        .unwrap()
        .unwrap();
    // Один сертификат: CN=localhost, ключ rsaEncryption 2048 бит, подпись
    // sha256WithRSAEncryption (самоподписанный).
    assert_eq!(certificates.len(), 1);
    let der = certificates.first().unwrap();
    assert_eq!(der.len(), 776);
    assert!(der.starts_with(&[0x30, 0x82, 0x03, 0x04]));

    let (msg_type, body) = handshake_body(&seen, 2);
    let message = ServerMessage::parse(msg_type, body).unwrap();
    assert!(matches!(message, ServerMessage::ServerKeyExchange(raw) if raw == body));
    assert_eq!(body.len(), 779);
    // DHE-RSA-AES256-GCM-SHA384: Kx=DH, Au=RSA.
    let kind = KeyExchangeKind::from_optional_info(hello.cipher_suite.info());
    assert_eq!(kind, KeyExchangeKind::Dhe { signed: true });
    let exchange = message
        .server_key_exchange(ProtocolVersion::TLS1_2, kind)
        .unwrap()
        .unwrap();
    let ServerKeyExchange::Dhe {
        params,
        signed_params,
        signature,
    } = exchange
    else {
        panic!("ожидался DHE, получено {exchange:?}");
    };
    // `openssl s_client`: «Peer Temp Key: DH, 2048 bits». Параметры сервер
    // выбрал сам («Using default temp DH parameters» в журнале s_server).
    assert_eq!(params.p.len(), 256);
    assert_eq!(params.p_bits(), 2048);
    assert!(params.p.starts_with(&[0xFF; 8]));
    assert!(params.p.ends_with(&[0xFF; 8]));
    assert_eq!(params.g, &[0x02][..]);
    // Ys меняется от соединения к соединению; длина поля — как у p.
    assert_eq!(params.ys.len(), 256);
    // Три поля с двухбайтовыми длинами.
    assert_eq!(signed_params.len(), 2 + 256 + 2 + 1 + 2 + 256);
    assert_eq!(body.get(..signed_params.len()), Some(signed_params));
    let signature = signature.unwrap();
    // `openssl s_client`: «Peer signature type: rsa_pss_rsae_sha256» (0x0804),
    // «Server public key is 2048 bit» — подпись 256 байт.
    assert_eq!(signature.scheme, Some(SignatureScheme(0x0804)));
    assert_eq!(signature.signature.len(), 256);

    let (msg_type, body) = handshake_body(&seen, 3);
    assert!(matches!(
        ServerMessage::parse(msg_type, body).unwrap(),
        ServerMessage::ServerHelloDone
    ));
}

#[test]
fn certificate_split_across_records() {
    // Стенд с -max_send_frag 512 и сертификатом крупнее одного фрагмента.
    // Это условия записи (`[source.conditions]`), а не ожидаемый результат
    // разбора: в `[expected.fields]` их нет.
    assert_eq!(
        FRAGMENTED_SERVER.meta_value("source.conditions", "max_send_frag"),
        Some("512")
    );
    assert_eq!(
        FRAGMENTED_SERVER.meta_value("source.conditions", "handshake_message_spans_records"),
        Some("true")
    );
    assert_eq!(
        FRAGMENTED_SERVER.meta_value("expected.fields", "max_send_frag"),
        None
    );
    assert_eq!(
        FRAGMENTED_SERVER.meta_value("expected.fields", "handshake_message_spans_records"),
        None
    );
    let bytes = FRAGMENTED_SERVER.bytes();

    // Записей больше, чем сообщений; ни одна не длиннее 512 байтов, и хотя
    // бы одна заполнена до предела.
    let layout = records(&bytes);
    assert!(
        layout
            .iter()
            .all(|(content_type, _)| *content_type == ContentType::HANDSHAKE)
    );
    assert!(layout.iter().all(|(_, length)| *length <= 512));
    assert!(layout.iter().any(|(_, length)| *length == 512));

    let (seen, decoder) = decode(&bytes, bytes.len());
    assert!(decoder.is_idle());
    assert!(!decoder.is_opaque());
    assert_eq!(decoder.stream_offset(), bytes.len());
    assert_eq!(seen.len(), 4);
    assert!(layout.len() > seen.len());

    let (msg_type, body) = handshake_body(&seen, 0);
    assert_eq!(msg_type, HandshakeType::SERVER_HELLO);
    assert_tls12_server_hello(body);

    // Certificate не помещается в одну запись и собран из нескольких.
    let (msg_type, body) = handshake_body(&seen, 1);
    assert_eq!(msg_type, HandshakeType::CERTIFICATE);
    assert!(body.len() > 512);
    assert!(matches!(
        ServerMessage::parse(msg_type, body).unwrap(),
        ServerMessage::Certificate(certificate) if certificate.len() == body.len()
    ));
    // Тело — список сертификатов: трёхбайтовая длина списка покрывает всё
    // остальное, внутри один сертификат в DER (SEQUENCE, 0x30).
    let mut reader = Reader::new(body);
    let mut list = reader.sub_u24().unwrap();
    reader.finish().unwrap();
    let certificate = list.vec_u24().unwrap();
    list.finish().unwrap();
    assert_eq!(certificate.first(), Some(&0x30));

    let (msg_type, body) = handshake_body(&seen, 2);
    assert!(matches!(
        ServerMessage::parse(msg_type, body).unwrap(),
        ServerMessage::ServerKeyExchange(exchange) if !exchange.is_empty()
    ));
    let (msg_type, body) = handshake_body(&seen, 3);
    assert!(matches!(
        ServerMessage::parse(msg_type, body).unwrap(),
        ServerMessage::ServerHelloDone
    ));

    // Сумма сообщений с заголовками равна сумме тел записей.
    let messages: usize = seen
        .iter()
        .map(|event| match event {
            Seen::Handshake(_, body) => body.len() + 4,
            _ => 0,
        })
        .sum();
    let fragments: usize = layout.iter().map(|(_, length)| *length).sum();
    assert_eq!(messages, fragments);
}

#[test]
fn tls13_server_hello() {
    let bytes = TLS13_SERVER.bytes();
    let (seen, decoder) = decode(&bytes, bytes.len());
    assert!(decoder.is_idle());
    assert!(decoder.is_opaque());
    assert!(!decoder.awaits_second_hello());
    assert_eq!(seen.len(), 2);
    assert_eq!(seen.get(1), Some(&Seen::ChangeCipherSpec));

    let (msg_type, body) = handshake_body(&seen, 0);
    let ServerMessage::ServerHello(hello) = ServerMessage::parse(msg_type, body).unwrap() else {
        panic!("ожидался ServerHello");
    };
    assert_eq!(hello.legacy_version, ProtocolVersion::TLS1_2);
    assert_eq!(hello.version(), ProtocolVersion::TLS1_3);
    assert_eq!(hello.cipher_suite, CipherSuite(0x1302));
    // Тот же шифр показывает `openssl s_client -tls1_3` к стенду.
    assert_eq!(
        hello.cipher_suite.openssl_name(),
        Some("TLS_AES_256_GCM_SHA384")
    );
    assert_eq!(hello.compression_method, 0);
    assert!(!hello.is_hello_retry_request());
    assert_eq!(hello.downgrade_marker(), None);
    assert_eq!(hello.anomalies(), Vec::new());

    // Сервер возвращает session_id клиента.
    let client = TLS13_CLIENT.bytes();
    let client_session_id: Vec<u8> = client_random(&client).iter().map(|byte| !byte).collect();
    assert_eq!(hello.session_id, client_session_id.as_slice());

    assert_eq!(
        hello.extension(kind::SUPPORTED_VERSIONS),
        Some(ServerExtension::SupportedVersions(ProtocolVersion::TLS1_3))
    );
    match hello.extension(kind::KEY_SHARE) {
        Some(ServerExtension::KeyShare(ServerKeyShare::Entry {
            group,
            key_exchange,
        })) => {
            assert_eq!(group, NamedGroup(0x001D));
            assert_eq!(group.name(), Some("x25519"));
            assert_eq!(key_exchange.len(), 32);
        }
        other => panic!("ожидался key_share с ключом, получено {other:?}"),
    }
    assert_eq!(hello.extensions().count(), 2);
}

#[test]
fn hello_retry_request() {
    let bytes = HRR_SERVER.bytes();
    let (seen, decoder) = decode(&bytes, bytes.len());
    assert!(decoder.is_idle());
    assert_eq!(seen.len(), 2);
    assert_eq!(seen.get(1), Some(&Seen::ChangeCipherSpec));

    let (msg_type, body) = handshake_body(&seen, 0);
    assert_eq!(msg_type, HandshakeType::SERVER_HELLO);
    let ServerMessage::HelloRetryRequest(hello) = ServerMessage::parse(msg_type, body).unwrap()
    else {
        panic!("ожидался HelloRetryRequest");
    };
    assert!(hello.is_hello_retry_request());
    // Все 32 байта константы совпадают с записанным ответом сервера.
    assert_eq!(hello.random, HELLO_RETRY_REQUEST_RANDOM);
    assert_eq!(hello.legacy_version, ProtocolVersion::TLS1_2);
    assert_eq!(hello.version(), ProtocolVersion::TLS1_3);
    assert_eq!(hello.cipher_suite, CipherSuite(0x1302));
    assert_eq!(hello.downgrade_marker(), None);
    assert_eq!(hello.anomalies(), Vec::new());

    let client = HRR_CLIENT.bytes();
    let client_session_id: Vec<u8> = client_random(&client).iter().map(|byte| !byte).collect();
    assert_eq!(hello.session_id, client_session_id.as_slice());

    assert_eq!(
        hello.extensions().collect::<Vec<_>>(),
        vec![
            ServerExtension::SupportedVersions(ProtocolVersion::TLS1_3),
            ServerExtension::KeyShare(ServerKeyShare::RetryGroup(NamedGroup(0x001D))),
        ]
    );

    // После HRR второй ServerHello идёт открытым текстом: декодер распознал
    // HRR сам, CCS режим Opaque не включил, resume_plaintext не нужен.
    assert!(decoder.awaits_second_hello());
    assert!(!decoder.is_opaque());
}

#[test]
fn hello_retry_exchange_without_manual_resume() {
    // Полный поток сервера: HRR, CCS, второй ServerHello, зашифрованная
    // запись. `decode` ни разу не вызывает resume_plaintext.
    let bytes = HRR_EXCHANGE.bytes();
    let (seen, decoder) = decode(&bytes, bytes.len());
    assert!(decoder.is_idle());
    assert_eq!(decoder.stream_offset(), bytes.len());
    assert_eq!(seen.len(), 4);

    // Первая часть потока — фикстура ответа на первый ClientHello.
    let offset: usize = HRR_EXCHANGE
        .meta_value("", "second_request_offset")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(bytes.get(..offset).unwrap(), HRR_SERVER.bytes());

    let (msg_type, body) = handshake_body(&seen, 0);
    let ServerMessage::HelloRetryRequest(retry) = ServerMessage::parse(msg_type, body).unwrap()
    else {
        panic!("ожидался HelloRetryRequest");
    };
    let retry_group = match retry.extension(kind::KEY_SHARE) {
        Some(ServerExtension::KeyShare(ServerKeyShare::RetryGroup(group))) => group,
        other => panic!("ожидался key_share с группой, получено {other:?}"),
    };
    assert_eq!(retry_group, NamedGroup(0x001D));

    assert_eq!(seen.get(1), Some(&Seen::ChangeCipherSpec));

    let (msg_type, body) = handshake_body(&seen, 2);
    assert_eq!(msg_type, HandshakeType::SERVER_HELLO);
    let ServerMessage::ServerHello(hello) = ServerMessage::parse(msg_type, body).unwrap() else {
        panic!("ожидался ServerHello, не HelloRetryRequest");
    };
    assert!(!hello.is_hello_retry_request());
    assert_eq!(hello.legacy_version, ProtocolVersion::TLS1_2);
    assert_eq!(hello.version(), ProtocolVersion::TLS1_3);
    assert_eq!(hello.cipher_suite, CipherSuite(0x1302));
    assert_eq!(hello.cipher_suite, retry.cipher_suite);
    assert_eq!(hello.session_id, retry.session_id);
    assert_eq!(hello.downgrade_marker(), None);
    assert_eq!(hello.anomalies(), Vec::new());
    assert_eq!(
        hello.extension(kind::SUPPORTED_VERSIONS),
        Some(ServerExtension::SupportedVersions(ProtocolVersion::TLS1_3))
    );
    match hello.extension(kind::KEY_SHARE) {
        Some(ServerExtension::KeyShare(ServerKeyShare::Entry {
            group,
            key_exchange,
        })) => {
            // Группа — та, что сервер запросил в HRR.
            assert_eq!(group, retry_group);
            assert_eq!(key_exchange.len(), 32);
        }
        other => panic!("ожидался key_share с ключом, получено {other:?}"),
    }

    // Дальше — зашифрованная запись. OpenSSL шлёт CCS один раз, сразу за
    // HRR. После второго ServerHello CCS нет, поэтому режим Opaque не
    // включён и зашифрованная запись типа application_data приходит именно
    // событием ApplicationData, а не Opaque (docs/DECISIONS.md, D-14).
    // Сравнивается точный вариант события и длина тела записи.
    assert_eq!(
        records(&bytes).last(),
        Some(&(ContentType::APPLICATION_DATA, 51))
    );
    assert_eq!(seen.get(3), Some(&Seen::ApplicationData(51)));
    assert_ne!(
        seen.get(3),
        Some(&Seen::Opaque(ContentType::APPLICATION_DATA, 51))
    );
    assert!(!decoder.awaits_second_hello());
    assert!(!decoder.is_opaque());

    for chunk in CHUNKS {
        let (chunked, decoder) = decode(&bytes, chunk);
        assert_eq!(chunked, seen, "порции по {chunk}");
        assert!(decoder.is_idle());
    }
}

#[test]
fn no_shared_cipher_alert() {
    let bytes = ALERT_SERVER.bytes();
    let (seen, decoder) = decode(&bytes, bytes.len());
    assert!(decoder.is_idle());
    let [Seen::Alert(body)] = seen.as_slice() else {
        panic!("ожидался один alert, получено {seen:?}");
    };
    let alert = Alert::parse(body).unwrap();
    assert_eq!(alert.level, AlertLevel::FATAL);
    assert!(alert.is_fatal());
    // Тот же номер показывает `openssl s_client`: SSL alert number 40.
    assert_eq!(alert.description, AlertDescription(40));
    assert_eq!(alert.description.name(), Some("handshake_failure"));
}

#[test]
fn server_fixtures_decode_the_same_in_any_chunking() {
    for fixture in [
        &TLS12_SERVER,
        &TLS13_SERVER,
        &HRR_SERVER,
        &ALERT_SERVER,
        &FRAGMENTED_SERVER,
    ] {
        let bytes = fixture.bytes();
        let (whole, _) = decode(&bytes, bytes.len());
        for chunk in CHUNKS {
            let (seen, decoder) = decode(&bytes, chunk);
            assert_eq!(seen, whole, "{}: порции по {chunk}", fixture.name);
            assert!(decoder.is_idle(), "{}", fixture.name);
        }
        assert!(
            !whole.iter().any(Seen::is_uninterpreted),
            "{}",
            fixture.name
        );
    }
}

#[test]
fn truncated_server_fixture_is_never_a_panic_or_error() {
    for fixture in [&TLS12_SERVER, &HRR_EXCHANGE, &FRAGMENTED_SERVER] {
        let bytes = fixture.bytes();
        for len in 0..bytes.len() {
            let mut decoder = Decoder::default();
            let mut input = bytes.get(..len).unwrap();
            loop {
                match decoder.feed(&mut input) {
                    Ok(Event::NeedMore) => break,
                    Ok(_) => {}
                    Err(error) => panic!("{}: длина {len}: {error}", fixture.name),
                }
            }
        }
    }
}
