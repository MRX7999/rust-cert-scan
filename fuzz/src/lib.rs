//! Тела фаззинг-целей certscan.
//!
//! Каждая цель из `fuzz_targets/` — обёртка над одноимённой функцией этого
//! модуля. Так тела целей собираются и на stable и прогоняются обычным
//! тестом на seed-файлах (`cargo test --manifest-path fuzz/Cargo.toml`), без
//! nightly и cargo-fuzz. Сам модуль `libfuzzer-sys` не использует.
//!
//! Цели проверяют не только отсутствие паник, но и инварианты; нарушение
//! оформлено через `assert!`. Workspace-линты на этот крейт не действуют.
//!
//! Входы целей — «сырые» байты (поток записей либо тело сообщения), без
//! управляющих префиксов: seed-файлы из фикстур используются как есть.
//! Размеры порций для инкрементальных декодеров выводятся из хеша входа.

use std::num::NonZeroUsize;

use tls_data::sslv2::Sslv2CipherKind;
use tls_probe::client_hello::RANDOM_LEN;
use tls_probe::sslv2::parse_message;
use tls_probe::{
    Alert, CertificateList, ClientHello, ClientHelloView, Decoder, EcCurveType,
    Event, HandshakeType, KeyExchangeKind, ParseError, ParseLimits, ProtocolVersion, Reader,
    ServerHello, ServerKeyExchange, ServerMessage, Sslv2ClientHello, Sslv2ClientHelloView,
    Sslv2Decoder, Sslv2Event, Sslv2RecordHeader, UnparsedReason, Writer,
};

/// Длина заголовка TLS-записи.
const RECORD_HEADER_LEN: usize = 5;
/// Длина заголовка handshake-сообщения.
const HANDSHAKE_HEADER_LEN: usize = 4;
/// Длина сообщения alert.
const ALERT_LEN: usize = 2;
/// Длина двухбайтового заголовка записи SSLv2.
const SSLV2_HEADER_LEN: usize = 2;

/// Версии, для которых перебирается разбор ServerKeyExchange: четыре, где
/// формат определён, TLS 1.3 и заведомо неизвестная.
const KX_VERSIONS: [ProtocolVersion; 6] = [
    ProtocolVersion::SSL3_0,
    ProtocolVersion::TLS1_0,
    ProtocolVersion::TLS1_1,
    ProtocolVersion::TLS1_2,
    ProtocolVersion(0x0304),
    ProtocolVersion(0x7F1C),
];

/// Все виды key exchange, включая каждую причину отказа от разбора.
const KX_KINDS: [KeyExchangeKind; 12] = [
    KeyExchangeKind::Dhe { signed: true },
    KeyExchangeKind::Dhe { signed: false },
    KeyExchangeKind::Ecdhe { signed: true },
    KeyExchangeKind::Ecdhe { signed: false },
    KeyExchangeKind::RsaExport,
    KeyExchangeKind::Unsupported(UnparsedReason::Psk),
    KeyExchangeKind::Unsupported(UnparsedReason::NoServerKeyExchange),
    KeyExchangeKind::Unsupported(UnparsedReason::UnsupportedKeyExchange),
    KeyExchangeKind::Unsupported(UnparsedReason::Tls13),
    KeyExchangeKind::Unsupported(UnparsedReason::UnknownKeyExchange),
    KeyExchangeKind::Unsupported(UnparsedReason::UnsupportedVersion),
    KeyExchangeKind::Unsupported(UnparsedReason::ExplicitCurve),
];

/// Генератор размеров порций, детерминированно выведенный из входа.
struct Chunks {
    state: u64,
    max: usize,
}

impl Chunks {
    fn from_input(data: &[u8]) -> Self {
        // FNV-1a по всему входу.
        let mut state = 0xCBF2_9CE4_8422_2325_u64;
        for byte in data {
            state ^= u64::from(*byte);
            state = state.wrapping_mul(0x0000_0100_0000_01B3);
        }
        let max = match state % 7 {
            0 => 1,
            1 => 2,
            2 => 5,
            3 => 16,
            4 => 64,
            5 => 1024,
            _ => 20_000,
        };
        Self {
            state: state | 1,
            max,
        }
    }

    fn next_size(&mut self) -> usize {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        let bound = u64::try_from(self.max).unwrap_or(1);
        usize::try_from(self.state % bound).unwrap_or(0) + 1
    }
}

/// Событие основного декодера без заимствований.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnedEvent {
    Handshake(u8, Vec<u8>),
    Alert(Vec<u8>),
    ChangeCipherSpec,
    ApplicationData(Vec<u8>),
    Opaque(u8, u16, Vec<u8>),
}

impl OwnedEvent {
    /// Нижняя оценка числа байтов потока, которые относятся только к этому
    /// событию. Всегда больше нуля, поэтому число событий ограничено длиной
    /// потока.
    fn stream_bytes(&self) -> usize {
        match self {
            Self::Handshake(_, body) => HANDSHAKE_HEADER_LEN + body.len(),
            Self::Alert(_) => ALERT_LEN,
            Self::ChangeCipherSpec => RECORD_HEADER_LEN + 1,
            Self::ApplicationData(fragment) | Self::Opaque(_, _, fragment) => {
                RECORD_HEADER_LEN + fragment.len()
            }
        }
    }
}

/// Проверяет событие и снимает с него копию; `None` для `NeedMore`.
fn own_event(event: Event<'_>, limits: &ParseLimits) -> Option<OwnedEvent> {
    Some(match event {
        Event::NeedMore => return None,
        Event::Handshake(message) => {
            assert_eq!(message.raw.len(), HANDSHAKE_HEADER_LEN + message.body.len());
            assert!(message.body.len() <= limits.max_handshake_len);
            let mut header = Reader::new(message.raw);
            assert_eq!(header.u8(), Ok(message.msg_type.0));
            assert_eq!(
                header.u24().map(|len| usize::try_from(len).unwrap_or(usize::MAX)),
                Ok(message.body.len())
            );
            assert_eq!(header.rest(), message.body);
            OwnedEvent::Handshake(message.msg_type.0, message.body.to_vec())
        }
        Event::Alert(bytes) => {
            assert_eq!(bytes.len(), ALERT_LEN);
            assert!(Alert::parse(bytes).is_ok());
            OwnedEvent::Alert(bytes.to_vec())
        }
        Event::ChangeCipherSpec => OwnedEvent::ChangeCipherSpec,
        Event::ApplicationData(fragment) => {
            assert!(fragment.len() <= limits.max_record_len);
            OwnedEvent::ApplicationData(fragment.to_vec())
        }
        Event::Opaque(record) => {
            assert!(record.fragment.len() <= limits.max_record_len);
            OwnedEvent::Opaque(
                record.content_type.0,
                record.version.0,
                record.fragment.to_vec(),
            )
        }
    })
}

/// Прогоняет поток через [`Decoder`] порциями и проверяет инварианты:
///
/// - `NeedMore` возвращается, только когда порция исчерпана;
/// - `stream_offset()` равен числу байтов, забранных из входа;
/// - сумма байтов, отнесённых к событиям, не превышает забранного, а число
///   вызовов `feed` ограничено длиной потока (нет событий «из ничего»);
/// - после ошибки повторный `feed` возвращает её же и вход не забирает.
fn decode_stream(
    stream: &[u8],
    mut next_size: impl FnMut() -> usize,
) -> (Vec<OwnedEvent>, Option<ParseError>) {
    let limits = ParseLimits::default();
    let mut decoder = Decoder::new(limits.clone());
    let mut events = Vec::new();
    let mut rest = stream;
    let mut fed = 0_usize;
    let mut emitted = 0_usize;
    let mut calls = 0_usize;
    let budget = stream.len().saturating_mul(2).saturating_add(2);

    while !rest.is_empty() {
        let size = next_size().clamp(1, rest.len());
        let (chunk, tail) = rest.split_at(size);
        rest = tail;
        fed += size;
        let mut input = chunk;
        loop {
            calls += 1;
            assert!(calls <= budget, "feed вызван {calls} раз на {} байтов", stream.len());
            let step = decoder
                .feed(&mut input)
                .map(|event| own_event(event, &limits));
            match step {
                Err(error) => {
                    let mut again = input;
                    assert_eq!(decoder.feed(&mut again).map(|_| ()), Err(error));
                    assert_eq!(again.len(), input.len());
                    let mut empty: &[u8] = &[];
                    assert_eq!(decoder.feed(&mut empty).map(|_| ()), Err(error));
                    return (events, Some(error));
                }
                Ok(None) => {
                    assert!(input.is_empty(), "NeedMore при непустом входе");
                    assert_eq!(decoder.stream_offset(), fed);
                    break;
                }
                Ok(Some(event)) => {
                    let consumed = fed - input.len();
                    assert_eq!(decoder.stream_offset(), consumed);
                    emitted += event.stream_bytes();
                    assert!(emitted <= consumed, "выдано {emitted}, забрано {consumed}");
                    events.push(event);
                }
            }
        }
    }
    (events, None)
}

/// Сравнивает итоги разбора одного потока при разной нарезке. `NotTls`
/// сравнивается только по факту: в ошибку попадают байты, доступные в
/// момент проверки, а их число зависит от порции.
fn assert_same_error(whole: Option<ParseError>, chunked: Option<ParseError>) {
    match (whole, chunked) {
        (Some(ParseError::NotTls { .. }), Some(ParseError::NotTls { .. })) => {}
        (whole, chunked) => assert_eq!(whole, chunked),
    }
}

/// Цель `record_layer`: произвольный поток в [`Decoder`].
///
/// Поток разбирается дважды — одним куском и порциями, размеры которых
/// выведены из входа; последовательность событий и ошибка должны совпасть.
/// Каждое handshake-сообщение дополнительно проходит через диспетчер.
pub fn record_layer(data: &[u8]) {
    let (whole_events, whole_error) = decode_stream(data, || usize::MAX);
    let mut chunks = Chunks::from_input(data);
    let (chunked_events, chunked_error) = decode_stream(data, || chunks.next_size());
    assert_eq!(whole_events, chunked_events);
    assert_same_error(whole_error, chunked_error);

    for event in &whole_events {
        if let OwnedEvent::Handshake(msg_type, body) = event {
            dispatch(HandshakeType(*msg_type), body);
        }
    }
}

/// Цель `alert`: [`Alert::parse`] принимает ровно два байта.
pub fn alert(data: &[u8]) {
    match Alert::parse(data) {
        Ok(alert) => {
            assert_eq!(data.len(), ALERT_LEN);
            let _ = alert.is_fatal();
        }
        Err(_) => assert_ne!(data.len(), ALERT_LEN),
    }
}

/// Цель `server_hello`: тело ServerHello или HelloRetryRequest.
pub fn server_hello(data: &[u8]) {
    let direct = ServerHello::parse(data);
    let dispatched = ServerMessage::parse(HandshakeType::SERVER_HELLO, data);
    match (direct, dispatched) {
        (Ok(hello), Ok(message)) => {
            let retry = hello.is_hello_retry_request();
            match message {
                ServerMessage::HelloRetryRequest(_) => assert!(retry),
                ServerMessage::ServerHello(_) => assert!(!retry),
                other => panic!("server_hello разобран как {:?}", other.msg_type()),
            }
            let _ = hello.version();
            let _ = hello.downgrade_marker();
            let _ = hello.anomalies();
            let typed = hello.extensions().count();
            let mut raw = 0_usize;
            for extension in hello.raw_extensions() {
                assert!(extension.is_ok(), "расширение разобранного hello с ошибкой");
                raw += 1;
            }
            assert!(typed <= raw);
            if !hello.has_extensions_block() {
                assert_eq!(raw, 0);
            }
        }
        (Err(direct), Err(dispatched)) => assert_eq!(direct, dispatched),
        (direct, dispatched) => panic!(
            "ServerHello::parse и диспетчер расходятся: {:?} и {:?}",
            direct.map(|_| ()),
            dispatched.map(|_| ())
        ),
    }
}

/// Цель `certificate`: тело Certificate в формате TLS до 1.2.
pub fn certificate(data: &[u8]) {
    let limits = ParseLimits::default();
    let Ok(list) = CertificateList::parse(data, &limits) else {
        return;
    };
    let mut count = 0_usize;
    let mut total = 3_usize;
    for der in list.iter() {
        assert!(!der.is_empty(), "пустой сертификат в разобранном списке");
        count += 1;
        total += 3 + der.len();
    }
    assert_eq!(count, list.len());
    assert_eq!(list.iter().len(), list.len());
    assert_eq!(list.is_empty(), count == 0);
    assert_eq!(list.first(), list.iter().next());
    assert_eq!(total, data.len(), "срезы сертификатов не покрывают тело");

    let again = ServerMessage::parse(HandshakeType::CERTIFICATE, data)
        .ok()
        .and_then(|message| message.certificates(&limits))
        .and_then(Result::ok)
        .map(|list| list.len());
    assert_eq!(again, Some(count));
}

/// Проверяет разбор ServerKeyExchange для одной пары «версия — вид».
fn check_server_kx(data: &[u8], version: ProtocolVersion, kind: KeyExchangeKind) {
    let result = ServerKeyExchange::parse(data, version, kind);

    let dispatched = ServerMessage::parse(HandshakeType::SERVER_KEY_EXCHANGE, data)
        .ok()
        .and_then(|message| message.server_key_exchange(version, kind));
    assert_eq!(dispatched, Some(result));

    if let KeyExchangeKind::Unsupported(reason) = kind {
        assert_eq!(
            result,
            Ok(ServerKeyExchange::Unparsed { reason, body: data })
        );
        return;
    }
    let version_supported = matches!(
        version,
        ProtocolVersion::SSL3_0
            | ProtocolVersion::TLS1_0
            | ProtocolVersion::TLS1_1
            | ProtocolVersion::TLS1_2
    );
    if !version_supported {
        assert_eq!(
            result,
            Ok(ServerKeyExchange::Unparsed {
                reason: UnparsedReason::UnsupportedVersion,
                body: data,
            })
        );
        return;
    }
    let Ok(message) = result else {
        return;
    };

    let signed = !matches!(
        kind,
        KeyExchangeKind::Dhe { signed: false } | KeyExchangeKind::Ecdhe { signed: false }
    );
    let with_scheme = version == ProtocolVersion::TLS1_2;

    let (params_len, signed_params, signature) = match message {
        ServerKeyExchange::Dhe {
            params,
            signed_params,
            signature,
        } => {
            assert!(matches!(kind, KeyExchangeKind::Dhe { .. }));
            assert!(!params.p.is_empty() && !params.g.is_empty() && !params.ys.is_empty());
            assert!(params.p_bits() <= params.p.len() * 8);
            (
                6 + params.p.len() + params.g.len() + params.ys.len(),
                signed_params,
                signature,
            )
        }
        ServerKeyExchange::Ecdhe {
            params,
            signed_params,
            signature,
        } => {
            assert!(matches!(kind, KeyExchangeKind::Ecdhe { .. }));
            assert_eq!(params.curve_type, EcCurveType::NAMED_CURVE);
            assert!(!params.point.is_empty());
            (4 + params.point.len(), signed_params, signature)
        }
        ServerKeyExchange::RsaExport {
            params,
            signed_params,
            signature,
        } => {
            assert_eq!(kind, KeyExchangeKind::RsaExport);
            assert!(!params.modulus.is_empty() && !params.exponent.is_empty());
            assert!(params.modulus_bits() <= params.modulus.len() * 8);
            (
                4 + params.modulus.len() + params.exponent.len(),
                signed_params,
                Some(signature),
            )
        }
        ServerKeyExchange::Unparsed { reason, body } => {
            assert_eq!(reason, UnparsedReason::ExplicitCurve);
            assert!(matches!(kind, KeyExchangeKind::Ecdhe { .. }));
            assert_eq!(body, data);
            return;
        }
    };

    assert_eq!(Some(signed_params), data.get(..params_len));
    assert_eq!(signature.is_some(), signed);
    assert_eq!(message.signature().copied(), signature);
    let signature_len = signature.map_or(0, |signature| {
        assert_eq!(signature.scheme.is_some(), with_scheme);
        2 + signature.signature.len() + if with_scheme { 2 } else { 0 }
    });
    assert_eq!(
        params_len + signature_len,
        data.len(),
        "поля не покрывают тело"
    );
}

/// Цель `server_kx`: тело ServerKeyExchange разбирается для каждого вида
/// key exchange и каждой версии из [`KX_KINDS`] и [`KX_VERSIONS`].
pub fn server_kx(data: &[u8]) {
    for version in KX_VERSIONS {
        for kind in KX_KINDS {
            check_server_kx(data, version, kind);
        }
    }
}

/// Диспетчер и все типизированные методы разбора для одного сообщения.
fn dispatch(msg_type: HandshakeType, body: &[u8]) {
    let limits = ParseLimits::default();
    let message = match ServerMessage::parse(msg_type, body) {
        Ok(message) => message,
        Err(_) => {
            assert!(
                msg_type == HandshakeType::SERVER_HELLO
                    || msg_type == HandshakeType::SERVER_HELLO_DONE,
                "диспетчер вернул ошибку для типа {}",
                msg_type.0
            );
            return;
        }
    };
    assert_eq!(message.msg_type(), msg_type);

    assert_eq!(
        message.certificates(&limits).is_some(),
        msg_type == HandshakeType::CERTIFICATE
    );
    assert_eq!(
        message.certificate_status().is_some(),
        msg_type == HandshakeType::CERTIFICATE_STATUS
    );
    assert_eq!(
        message.new_session_ticket().is_some(),
        msg_type == HandshakeType::NEW_SESSION_TICKET
    );
    for version in KX_VERSIONS {
        for kind in KX_KINDS {
            assert_eq!(
                message.server_key_exchange(version, kind).is_some(),
                msg_type == HandshakeType::SERVER_KEY_EXCHANGE
            );
        }
    }

    match msg_type {
        HandshakeType::SERVER_HELLO => server_hello(body),
        HandshakeType::CERTIFICATE => certificate(body),
        HandshakeType::SERVER_KEY_EXCHANGE => server_kx(body),
        _ => {}
    }
}

/// Цель `server_message`: первый байт входа — тип handshake-сообщения,
/// остальное — тело.
pub fn server_message(data: &[u8]) {
    let Some((msg_type, body)) = data.split_first() else {
        return;
    };
    dispatch(HandshakeType(*msg_type), body);
}

/// Цель `client_hello`: [`ClientHelloView`] и пара «билдер — парсер» в обе
/// стороны.
pub fn client_hello(data: &[u8]) {
    client_hello_parse_then_build(data);
    client_hello_build_then_parse(data);
}

/// Разобранное тело без расширений, собранное билдером заново, совпадает
/// с входом побайтно.
fn client_hello_parse_then_build(data: &[u8]) {
    let Ok(view) = ClientHelloView::parse(data) else {
        return;
    };
    assert_eq!(view.cipher_suites_raw.len() % 2, 0);
    let mut extensions = 0_usize;
    for extension in view.extensions() {
        assert!(extension.is_ok(), "расширение разобранного hello с ошибкой");
        extensions += 1;
    }
    if !view.has_extensions_block() {
        assert_eq!(extensions, 0);
    }
    let suites: Vec<u16> = view
        .cipher_suites_raw
        .chunks_exact(2)
        .map(|pair| pair.iter().fold(0_u16, |code, byte| (code << 8) | u16::from(*byte)))
        .collect();
    assert_eq!(view.cipher_suites().count(), suites.len());
    if extensions != 0 {
        return;
    }
    let rebuilt = ClientHello::new(view.random)
        .with_legacy_version(view.legacy_version)
        .with_session_id(view.session_id)
        .with_cipher_suites(suites)
        .with_compression_methods(view.compression_methods)
        .with_empty_extensions_block(view.has_extensions_block())
        .body_bytes();
    assert_eq!(rebuilt.as_deref(), Ok(data));
}

/// Hello, собранный из полей, выведенных из входа, разбирается обратно в
/// те же поля; записи с фрагментацией декодер собирает в то же сообщение.
fn client_hello_build_then_parse(data: &[u8]) {
    let mut reader = Reader::new(data);
    let (Ok(version), Ok(random), Ok(session_len), Ok(fragment_len)) = (
        reader.u16(),
        reader.array::<RANDOM_LEN>(),
        reader.u8(),
        reader.u8(),
    ) else {
        return;
    };
    let rest = reader.rest();
    let session_len = usize::from(session_len % 33).min(rest.len());
    let (session_id, suites_raw) = rest.split_at(session_len);
    let suites: Vec<u16> = suites_raw
        .chunks_exact(2)
        .map(|pair| pair.iter().fold(0_u16, |code, byte| (code << 8) | u16::from(*byte)))
        .collect();

    let hello = ClientHello::new(random)
        .with_legacy_version(ProtocolVersion(version))
        .with_session_id(session_id)
        .with_cipher_suites(suites.iter().copied())
        .with_empty_extensions_block(fragment_len % 2 == 1)
        .with_max_fragment_len(NonZeroUsize::new(usize::from(fragment_len)));

    let Ok(body) = hello.body_bytes() else {
        panic!("hello с полями в пределах префиксов не собран");
    };
    let Ok(view) = ClientHelloView::parse(&body) else {
        panic!("собранный hello не разобран");
    };
    assert_eq!(view.legacy_version, ProtocolVersion(version));
    assert_eq!(view.random, random);
    assert_eq!(view.session_id, session_id);
    assert_eq!(
        view.cipher_suites_raw,
        suites_raw.get(..suites.len() * 2).unwrap_or(&[])
    );
    assert_eq!(view.compression_methods, hello.compression_methods());
    assert_eq!(view.has_extensions_block(), fragment_len % 2 == 1);
    assert_eq!(view.extensions().count(), 0);

    let Ok(records) = hello.record_bytes() else {
        panic!("записи hello не собраны");
    };
    let (events, error) = decode_stream(&records, || usize::MAX);
    assert_eq!(error, None);
    assert_eq!(
        events,
        vec![OwnedEvent::Handshake(HandshakeType::CLIENT_HELLO.0, body)]
    );
}

/// Событие декодера SSLv2 без заимствований.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnedSslv2Event {
    ServerHello {
        session_id_hit: bool,
        certificate_type: u8,
        version: u16,
        certificate: Vec<u8>,
        cipher_specs: Vec<u8>,
        connection_id: Vec<u8>,
    },
    Error(u16),
    Other(u8, Vec<u8>),
    TlsReply(Vec<u8>),
}

fn own_sslv2_event(event: Sslv2Event<'_>) -> Option<OwnedSslv2Event> {
    Some(match event {
        Sslv2Event::NeedMore => return None,
        Sslv2Event::ServerHello(hello) => {
            assert_eq!(hello.cipher_specs.len() % 3, 0);
            assert_eq!(hello.cipher_kinds().count(), hello.cipher_specs.len() / 3);
            OwnedSslv2Event::ServerHello {
                session_id_hit: hello.session_id_hit,
                certificate_type: hello.certificate_type.0,
                version: hello.version.0,
                certificate: hello.certificate.to_vec(),
                cipher_specs: hello.cipher_specs.to_vec(),
                connection_id: hello.connection_id.to_vec(),
            }
        }
        Sslv2Event::Error(code) => OwnedSslv2Event::Error(code.0),
        Sslv2Event::Other { msg_type, body } => OwnedSslv2Event::Other(msg_type, body.to_vec()),
        Sslv2Event::TlsReply { prefix } => {
            assert_eq!(prefix.len(), SSLV2_HEADER_LEN);
            OwnedSslv2Event::TlsReply(prefix.to_vec())
        }
    })
}

/// Прогоняет поток через [`Sslv2Decoder`] порциями. Инварианты:
///
/// - `NeedMore` — только при исчерпанной порции;
/// - каждое событие-запись соответствует хотя бы трём забранным байтам,
///   число вызовов `feed` ограничено длиной потока;
/// - ошибка и `TlsReply` окончательны: повторный вызов возвращает то же и
///   вход не забирает.
fn decode_sslv2(
    stream: &[u8],
    mut next_size: impl FnMut() -> usize,
) -> (Vec<OwnedSslv2Event>, Option<ParseError>) {
    let mut decoder = Sslv2Decoder::default();
    let mut events = Vec::new();
    let mut rest = stream;
    let mut fed = 0_usize;
    let mut emitted = 0_usize;
    let mut calls = 0_usize;
    let budget = stream.len().saturating_mul(2).saturating_add(2);

    while !rest.is_empty() {
        let size = next_size().clamp(1, rest.len());
        let (chunk, tail) = rest.split_at(size);
        rest = tail;
        fed += size;
        let mut input = chunk;
        loop {
            calls += 1;
            assert!(calls <= budget, "feed вызван {calls} раз на {} байтов", stream.len());
            let step = decoder.feed(&mut input).map(own_sslv2_event);
            match step {
                Err(error) => {
                    let mut again = input;
                    assert_eq!(decoder.feed(&mut again).map(|_| ()), Err(error));
                    assert_eq!(again.len(), input.len());
                    return (events, Some(error));
                }
                Ok(None) => {
                    assert!(input.is_empty(), "NeedMore при непустом входе");
                    break;
                }
                Ok(Some(event)) => {
                    if matches!(event, OwnedSslv2Event::TlsReply(_)) {
                        let mut again = input;
                        let repeated = decoder.feed(&mut again).map(own_sslv2_event);
                        assert_eq!(repeated, Ok(Some(event.clone())));
                        assert_eq!(again.len(), input.len());
                        events.push(event);
                        return (events, None);
                    }
                    emitted += SSLV2_HEADER_LEN + 1;
                    assert!(emitted <= fed - input.len());
                    events.push(event);
                }
            }
        }
    }
    (events, None)
}

/// Цель `sslv2`: ответ на SSLv2 CLIENT-HELLO в [`Sslv2Decoder`], отдельные
/// парсеры сообщений и пара «билдер — парсер» для CLIENT-HELLO.
pub fn sslv2(data: &[u8]) {
    let (whole_events, whole_error) = decode_sslv2(data, || usize::MAX);
    let mut chunks = Chunks::from_input(data);
    let (chunked_events, chunked_error) = decode_sslv2(data, || chunks.next_size());
    assert_eq!(whole_events, chunked_events);
    assert_same_error(whole_error, chunked_error);

    // Ответ TLS: забранный префикс вместе с остатком — исходный поток, и
    // его принимает основной декодер со своими инвариантами.
    if let Some(OwnedSslv2Event::TlsReply(prefix)) = whole_events.last() {
        let skipped: usize = whole_events.len() - 1;
        if skipped == 0 {
            assert_eq!(Some(prefix.as_slice()), data.get(..SSLV2_HEADER_LEN));
            let _ = decode_stream(data, || usize::MAX);
        }
    }

    let limits = ParseLimits::default();
    let _ = parse_message(data, &limits);
    let mut reader = Reader::new(data);
    if let Ok(header) = Sslv2RecordHeader::parse(&mut reader) {
        assert_eq!(reader.position(), header.header_len);
        assert!(header.header_len == 2 || header.header_len == 3);
    } else {
        assert_eq!(reader.position(), 0);
    }
    if let Ok(view) = Sslv2ClientHelloView::parse(data) {
        assert_eq!(view.cipher_specs.len() % 3, 0);
        assert_eq!(
            10 + view.cipher_specs.len() + view.session_id.len() + view.challenge.len(),
            data.len() + 1
        );
    }
    let _ = Sslv2ClientHelloView::parse_record(data);

    sslv2_build_then_parse(data);
}

/// CLIENT-HELLO, собранный из полей, выведенных из входа, разбирается
/// обратно в те же поля.
fn sslv2_build_then_parse(data: &[u8]) {
    let mut reader = Reader::new(data);
    let (Ok(version), Ok(kinds_count), Ok(session_len)) =
        (reader.u16(), reader.u8(), reader.u8())
    else {
        return;
    };
    let rest = reader.rest();
    let kinds_len = (usize::from(kinds_count % 16) * 3).min(rest.len() / 3 * 3);
    let (specs, rest) = rest.split_at(kinds_len);
    let session_len = usize::from(session_len % 33).min(rest.len());
    let (session_id, challenge) = rest.split_at(session_len);
    let kinds: Vec<Sslv2CipherKind> = specs
        .chunks_exact(3)
        .filter_map(|chunk| <[u8; 3]>::try_from(chunk).ok()).map(Sslv2CipherKind::from_bytes)
        .collect();

    let hello = Sslv2ClientHello {
        version: ProtocolVersion(version),
        cipher_kinds: &kinds,
        session_id,
        challenge,
    };
    let mut writer = Writer::new();
    if hello.encode(&mut writer).is_err() {
        assert!(writer.is_empty(), "ошибка сборки оставила байты в буфере");
        assert!(9 + data.len() > 0x7FFF);
        return;
    }
    let record = writer.as_slice();
    assert_eq!(
        record.len(),
        SSLV2_HEADER_LEN + 9 + specs.len() + session_id.len() + challenge.len()
    );
    let Ok(view) = Sslv2ClientHelloView::parse_record(record) else {
        panic!("собранный SSLv2 CLIENT-HELLO не разобран");
    };
    assert_eq!(view.version, ProtocolVersion(version));
    assert_eq!(view.cipher_specs, specs);
    assert_eq!(view.session_id, session_id);
    assert_eq!(view.challenge, challenge);
    assert!(
        view.cipher_kinds()
            .map(Sslv2CipherKind::to_bytes)
            .eq(kinds.iter().map(|kind| kind.to_bytes()))
    );

    // Собственный hello — запись SSLv2 с типом CLIENT-HELLO: декодер ответа
    // отдаёт её как `Other`, основной декодер — как `NotTls`.
    let (events, error) = decode_sslv2(record, || usize::MAX);
    assert_eq!(error, None);
    assert_eq!(
        events,
        vec![OwnedSslv2Event::Other(
            tls_probe::sslv2::MSG_CLIENT_HELLO,
            record.get(SSLV2_HEADER_LEN + 1..).unwrap_or(&[]).to_vec()
        )]
    );
    let (_, error) = decode_stream(record, || usize::MAX);
    assert!(matches!(error, Some(ParseError::NotTls { .. })));
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::*;

    /// Цели, для которых в `seeds/` есть файлы, и их тела.
    const SEEDED: [(&str, fn(&[u8])); 7] = [
        ("record_layer", record_layer),
        ("sslv2", sslv2),
        ("server_message", server_message),
        ("server_hello", server_hello),
        ("certificate", certificate),
        ("server_kx", server_kx),
        ("client_hello", client_hello),
    ];

    fn seeds(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("seeds")
            .join(target);
        let mut files: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "bin"))
            .collect();
        files.sort();
        files
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }

    /// Каждая цель проходит на своих seed-файлах целиком.
    #[test]
    fn targets_pass_on_their_seeds() {
        for (target, body) in SEEDED {
            let seeds = seeds(target);
            assert!(!seeds.is_empty(), "нет seed-файлов для цели {target}");
            for (_, bytes) in &seeds {
                body(bytes);
            }
        }
    }

    /// Каждая цель проходит на каждом префиксе каждого seed-файла: обрыв в
    /// любом месте не нарушает инварианты.
    #[test]
    fn targets_pass_on_every_seed_prefix() {
        for (target, body) in SEEDED {
            for (_, bytes) in seeds(target) {
                for end in 0..bytes.len() {
                    body(&bytes[..end]);
                }
            }
        }
    }

    /// Каждая цель принимает seed-файлы всех остальных целей: вход «не
    /// своего» формата — обычный случай для фаззера.
    #[test]
    fn targets_pass_on_foreign_seeds() {
        for (source, _) in SEEDED {
            for (_, bytes) in seeds(source) {
                for (_, body) in SEEDED {
                    body(&bytes);
                }
                alert(&bytes);
            }
        }
    }

    /// Вырожденные входы и однобайтовые искажения первого seed-файла.
    #[test]
    fn targets_pass_on_degenerate_inputs() {
        let inputs: [&[u8]; 6] = [
            &[],
            &[0x00],
            &[0xFF; 64],
            &[0x00; 64],
            &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28],
            &[0x80, 0x03, 0x00, 0x00, 0x01],
        ];
        for input in inputs {
            for (_, body) in SEEDED {
                body(input);
            }
            alert(input);
        }
        for (target, body) in SEEDED {
            let Some((_, bytes)) = seeds(target).into_iter().next() else {
                continue;
            };
            for index in 0..bytes.len().min(96) {
                for flip in [0x01_u8, 0x80, 0xFF] {
                    let mut mutated = bytes.clone();
                    mutated[index] ^= flip;
                    body(&mutated);
                }
            }
        }
    }

    #[test]
    fn alert_accepts_exactly_two_bytes() {
        alert(&[]);
        alert(&[0x02]);
        alert(&[0x02, 0x28]);
        alert(&[0x02, 0x28, 0x00]);
    }

    #[test]
    fn chunk_sizes_are_deterministic_and_positive() {
        let mut first = Chunks::from_input(b"certscan");
        let mut second = Chunks::from_input(b"certscan");
        for _ in 0..1000 {
            let size = first.next_size();
            assert_eq!(size, second.next_size());
            assert!(size >= 1 && size <= first.max);
        }
    }
}
