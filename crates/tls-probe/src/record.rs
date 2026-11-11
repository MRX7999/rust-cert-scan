//! TLS record layer: разбор и сборка записей.
//!
//! Запись — заголовок из пяти байтов (тип содержимого, версия, длина тела)
//! и тело. Модуль разбирает одну запись из уже полученных байтов и собирает
//! записи для отправки, в том числе с фрагментацией по заданному размеру.
//! Накопление байтов из сети и склейка handshake-сообщений — задача
//! [`crate::decoder`].
//!
//! Значения полей не проверяются на допустимость: неизвестный тип
//! содержимого и произвольная версия сохраняются как числа. Проверяется
//! только длина тела по [`ParseLimits::max_record_len`], причём до чтения
//! тела. Расшифровка не выполняется: тело зашифрованной записи возвращается
//! как непрозрачный срез.

use std::num::NonZeroUsize;

use crate::codec::{Reader, Writer};
use crate::error::{EncodeError, ParseError};
use crate::limits::ParseLimits;

/// Длина заголовка записи в байтах.
pub const RECORD_HEADER_LEN: usize = 5;

/// Длина заголовка handshake-сообщения в байтах: тип и 24-битная длина.
pub const HANDSHAKE_HEADER_LEN: usize = 4;

/// Наибольшая длина тела, представимая 16-битным полем длины записи.
const MAX_ENCODABLE_FRAGMENT_LEN: usize = 0xFFFF;

/// Тип содержимого записи (`ContentType`).
///
/// Неизвестное значение — не ошибка: оно сохраняется как есть.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentType(pub u8);

impl ContentType {
    /// `change_cipher_spec` (20).
    pub const CHANGE_CIPHER_SPEC: Self = Self(20);
    /// `alert` (21).
    pub const ALERT: Self = Self(21);
    /// `handshake` (22).
    pub const HANDSHAKE: Self = Self(22);
    /// `application_data` (23).
    pub const APPLICATION_DATA: Self = Self(23);
    /// `heartbeat` (24).
    pub const HEARTBEAT: Self = Self(24);

    /// Имя типа; `None` для неизвестного значения.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::CHANGE_CIPHER_SPEC => Some("change_cipher_spec"),
            Self::ALERT => Some("alert"),
            Self::HANDSHAKE => Some("handshake"),
            Self::APPLICATION_DATA => Some("application_data"),
            Self::HEARTBEAT => Some("heartbeat"),
            _ => None,
        }
    }

    /// Истина, если значение — один из пяти известных типов.
    #[must_use]
    pub fn is_known(self) -> bool {
        self.name().is_some()
    }
}

impl From<u8> for ContentType {
    fn from(code: u8) -> Self {
        Self(code)
    }
}

impl From<ContentType> for u8 {
    fn from(code: ContentType) -> Self {
        code.0
    }
}

/// Версия протокола в том виде, в каком она передаётся в записи и в hello:
/// старший байт — major, младший — minor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// SSL 3.0 (`0x0300`).
    pub const SSL3_0: Self = Self(0x0300);
    /// TLS 1.0 (`0x0301`).
    pub const TLS1_0: Self = Self(0x0301);
    /// TLS 1.1 (`0x0302`).
    pub const TLS1_1: Self = Self(0x0302);
    /// TLS 1.2 (`0x0303`).
    pub const TLS1_2: Self = Self(0x0303);
    /// TLS 1.3 (`0x0304`).
    pub const TLS1_3: Self = Self(0x0304);

    /// Старший байт версии.
    #[must_use]
    pub fn major(self) -> u8 {
        let [major, _] = self.0.to_be_bytes();
        major
    }

    /// Младший байт версии.
    #[must_use]
    pub fn minor(self) -> u8 {
        let [_, minor] = self.0.to_be_bytes();
        minor
    }

    /// Имя версии; `None` для значения вне SSL 3.0 – TLS 1.3.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::SSL3_0 => Some("SSLv3"),
            Self::TLS1_0 => Some("TLSv1.0"),
            Self::TLS1_1 => Some("TLSv1.1"),
            Self::TLS1_2 => Some("TLSv1.2"),
            Self::TLS1_3 => Some("TLSv1.3"),
            _ => None,
        }
    }
}

impl From<u16> for ProtocolVersion {
    fn from(code: u16) -> Self {
        Self(code)
    }
}

impl From<ProtocolVersion> for u16 {
    fn from(code: ProtocolVersion) -> Self {
        code.0
    }
}

/// Тип handshake-сообщения (`HandshakeType`).
///
/// Неизвестное значение сохраняется как есть.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HandshakeType(pub u8);

impl HandshakeType {
    /// `hello_request` (0).
    pub const HELLO_REQUEST: Self = Self(0);
    /// `client_hello` (1).
    pub const CLIENT_HELLO: Self = Self(1);
    /// `server_hello` (2); в TLS 1.3 так же передаётся HelloRetryRequest.
    pub const SERVER_HELLO: Self = Self(2);
    /// `new_session_ticket` (4).
    pub const NEW_SESSION_TICKET: Self = Self(4);
    /// `encrypted_extensions` (8).
    pub const ENCRYPTED_EXTENSIONS: Self = Self(8);
    /// `certificate` (11).
    pub const CERTIFICATE: Self = Self(11);
    /// `server_key_exchange` (12).
    pub const SERVER_KEY_EXCHANGE: Self = Self(12);
    /// `certificate_request` (13).
    pub const CERTIFICATE_REQUEST: Self = Self(13);
    /// `server_hello_done` (14).
    pub const SERVER_HELLO_DONE: Self = Self(14);
    /// `certificate_verify` (15).
    pub const CERTIFICATE_VERIFY: Self = Self(15);
    /// `client_key_exchange` (16).
    pub const CLIENT_KEY_EXCHANGE: Self = Self(16);
    /// `finished` (20).
    pub const FINISHED: Self = Self(20);
    /// `certificate_status` (22).
    pub const CERTIFICATE_STATUS: Self = Self(22);

    /// Имя типа; `None` для значения, которого нет среди констант.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::HELLO_REQUEST => Some("hello_request"),
            Self::CLIENT_HELLO => Some("client_hello"),
            Self::SERVER_HELLO => Some("server_hello"),
            Self::NEW_SESSION_TICKET => Some("new_session_ticket"),
            Self::ENCRYPTED_EXTENSIONS => Some("encrypted_extensions"),
            Self::CERTIFICATE => Some("certificate"),
            Self::SERVER_KEY_EXCHANGE => Some("server_key_exchange"),
            Self::CERTIFICATE_REQUEST => Some("certificate_request"),
            Self::SERVER_HELLO_DONE => Some("server_hello_done"),
            Self::CERTIFICATE_VERIFY => Some("certificate_verify"),
            Self::CLIENT_KEY_EXCHANGE => Some("client_key_exchange"),
            Self::FINISHED => Some("finished"),
            Self::CERTIFICATE_STATUS => Some("certificate_status"),
            _ => None,
        }
    }
}

impl From<u8> for HandshakeType {
    fn from(code: u8) -> Self {
        Self(code)
    }
}

impl From<HandshakeType> for u8 {
    fn from(code: HandshakeType) -> Self {
        code.0
    }
}

/// Заголовок записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// Тип содержимого.
    pub content_type: ContentType,
    /// Версия record layer.
    pub version: ProtocolVersion,
    /// Заявленная длина тела.
    pub length: u16,
}

impl RecordHeader {
    /// Читает заголовок и проверяет длину тела по лимиту; тело не читается.
    ///
    /// При ошибке позиция читателя не меняется.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если байтов меньше пяти;
    /// [`ParseError::LimitExceeded`], если длина тела больше
    /// [`ParseLimits::max_record_len`].
    pub fn parse(reader: &mut Reader<'_>, limits: &ParseLimits) -> Result<Self, ParseError> {
        let mut probe = reader.clone();
        let content_type = ContentType(probe.u8()?);
        let version = ProtocolVersion(probe.u16()?);
        let length_position = probe.position();
        let length = probe.u16()?;
        limits.check_record_len(usize::from(length), length_position)?;
        *reader = probe;
        Ok(Self {
            content_type,
            version,
            length,
        })
    }

    /// Пишет заголовок.
    pub fn encode(&self, writer: &mut Writer) {
        writer.put_u8(self.content_type.0);
        writer.put_u16(self.version.0);
        writer.put_u16(self.length);
    }
}

/// Запись: заголовок и тело, заимствованное из входного буфера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// Тип содержимого.
    pub content_type: ContentType,
    /// Версия record layer.
    pub version: ProtocolVersion,
    /// Тело записи; для зашифрованной записи — непрозрачные байты.
    pub fragment: &'a [u8],
}

impl<'a> Record<'a> {
    /// Читает одну запись целиком.
    ///
    /// При ошибке позиция читателя не меняется, поэтому вызов можно
    /// повторить, когда придут недостающие байты.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если заголовок или тело получены не
    /// полностью; [`ParseError::LimitExceeded`], если длина тела больше
    /// [`ParseLimits::max_record_len`].
    pub fn parse(reader: &mut Reader<'a>, limits: &ParseLimits) -> Result<Self, ParseError> {
        let mut probe = reader.clone();
        let header = RecordHeader::parse(&mut probe, limits)?;
        let fragment = probe.take(usize::from(header.length))?;
        *reader = probe;
        Ok(Self {
            content_type: header.content_type,
            version: header.version,
            fragment,
        })
    }
}

/// Пишет одну запись с заданным телом.
///
/// # Errors
///
/// [`EncodeError::LengthOverflow`], если тело длиннее 65535 байтов; буфер
/// при этом не меняется.
pub fn write_record(
    writer: &mut Writer,
    content_type: ContentType,
    version: ProtocolVersion,
    fragment: &[u8],
) -> Result<(), EncodeError> {
    let length = u16::try_from(fragment.len()).map_err(|_| EncodeError::LengthOverflow {
        prefix_bytes: 2,
        max: 0xFFFF,
        actual: fragment.len(),
    })?;
    RecordHeader {
        content_type,
        version,
        length,
    }
    .encode(writer);
    writer.put_slice(fragment);
    Ok(())
}

/// Упаковывает данные в одну или несколько записей.
///
/// Без `max_fragment_len` данные уходят одной записью. С ним данные режутся
/// на части не длиннее заданного размера (и не длиннее 65535 байтов), каждая
/// часть — отдельная запись с теми же типом и версией. Пустые данные дают
/// одну запись с пустым телом. Соответствие размера части ограничениям RFC
/// не проверяется: сканеру нужны и нестандартные записи.
///
/// # Errors
///
/// [`EncodeError::LengthOverflow`], если фрагментация не задана, а данные
/// длиннее 65535 байтов; буфер при этом не меняется.
pub fn write_records(
    writer: &mut Writer,
    content_type: ContentType,
    version: ProtocolVersion,
    payload: &[u8],
    max_fragment_len: Option<NonZeroUsize>,
) -> Result<(), EncodeError> {
    let Some(max_fragment_len) = max_fragment_len else {
        return write_record(writer, content_type, version, payload);
    };
    if payload.is_empty() {
        return write_record(writer, content_type, version, payload);
    }
    let chunk_len = max_fragment_len.get().min(MAX_ENCODABLE_FRAGMENT_LEN);
    for chunk in payload.chunks(chunk_len) {
        write_record(writer, content_type, version, chunk)?;
    }
    Ok(())
}

/// Пишет handshake-сообщение без record layer: тип, 24-битную длину и тело.
///
/// # Errors
///
/// [`EncodeError::LengthOverflow`], если тело длиннее 16777215 байтов.
pub fn write_handshake_message(
    writer: &mut Writer,
    msg_type: HandshakeType,
    body: &[u8],
) -> Result<(), EncodeError> {
    let length = u32::try_from(body.len())
        .ok()
        .filter(|length| *length <= 0x00FF_FFFF)
        .ok_or(EncodeError::LengthOverflow {
            prefix_bytes: 3,
            max: 0x00FF_FFFF,
            actual: body.len(),
        })?;
    writer.put_u8(msg_type.0);
    writer.put_u24(length)?;
    writer.put_slice(body);
    Ok(())
}

/// Упаковывает готовое handshake-сообщение (с заголовком) в записи типа
/// `handshake` с заданной версией record layer.
///
/// Правила фрагментации — как у [`write_records`].
///
/// # Errors
///
/// [`EncodeError::LengthOverflow`], если фрагментация не задана, а сообщение
/// длиннее 65535 байтов.
pub fn write_handshake_records(
    writer: &mut Writer,
    version: ProtocolVersion,
    message: &[u8],
    max_fragment_len: Option<NonZeroUsize>,
) -> Result<(), EncodeError> {
    write_records(
        writer,
        ContentType::HANDSHAKE,
        version,
        message,
        max_fragment_len,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ParseLimits {
        ParseLimits::default()
    }

    #[test]
    fn content_type_names_and_unknown() {
        let known = [
            (20_u8, "change_cipher_spec"),
            (21, "alert"),
            (22, "handshake"),
            (23, "application_data"),
            (24, "heartbeat"),
        ];
        for (code, name) in known {
            let content_type = ContentType::from(code);
            assert_eq!(content_type.name(), Some(name));
            assert!(content_type.is_known());
            assert_eq!(u8::from(content_type), code);
        }
        for code in [0_u8, 19, 25, 0x48, 0x80, 0xFF] {
            assert_eq!(ContentType(code).name(), None);
            assert!(!ContentType(code).is_known());
        }
    }

    #[test]
    fn protocol_version_parts_and_names() {
        assert_eq!(ProtocolVersion::TLS1_2.major(), 3);
        assert_eq!(ProtocolVersion::TLS1_2.minor(), 3);
        assert_eq!(ProtocolVersion::SSL3_0.name(), Some("SSLv3"));
        assert_eq!(ProtocolVersion::TLS1_0.name(), Some("TLSv1.0"));
        assert_eq!(ProtocolVersion::TLS1_1.name(), Some("TLSv1.1"));
        assert_eq!(ProtocolVersion::TLS1_2.name(), Some("TLSv1.2"));
        assert_eq!(ProtocolVersion::TLS1_3.name(), Some("TLSv1.3"));
        assert_eq!(ProtocolVersion(0x0305).name(), None);
        assert_eq!(ProtocolVersion::from(0x5454).major(), 0x54);
        assert_eq!(u16::from(ProtocolVersion::TLS1_3), 0x0304);
        assert!(ProtocolVersion::TLS1_0 < ProtocolVersion::TLS1_3);
    }

    #[test]
    fn handshake_type_names_and_unknown() {
        assert_eq!(HandshakeType::SERVER_HELLO.name(), Some("server_hello"));
        assert_eq!(
            HandshakeType::SERVER_HELLO_DONE.name(),
            Some("server_hello_done")
        );
        assert_eq!(HandshakeType::from(2), HandshakeType::SERVER_HELLO);
        assert_eq!(u8::from(HandshakeType::CERTIFICATE), 11);
        assert_eq!(HandshakeType(0xEE).name(), None);
    }

    #[test]
    fn parses_header() {
        let data = [0x16, 0x03, 0x01, 0x00, 0x05, 0xAA];
        let mut reader = Reader::new(&data);
        let header = RecordHeader::parse(&mut reader, &limits()).unwrap();
        assert_eq!(
            header,
            RecordHeader {
                content_type: ContentType::HANDSHAKE,
                version: ProtocolVersion::TLS1_0,
                length: 5,
            }
        );
        assert_eq!(reader.position(), RECORD_HEADER_LEN);
    }

    #[test]
    fn truncated_header_does_not_advance() {
        for len in 0..RECORD_HEADER_LEN {
            let data = [0x16, 0x03, 0x03, 0x00, 0x01];
            let mut reader = Reader::new(&data[..len]);
            let error = RecordHeader::parse(&mut reader, &limits()).unwrap_err();
            assert!(
                matches!(error, ParseError::UnexpectedEof { .. }),
                "{error:?}"
            );
            assert_eq!(reader.position(), 0);
        }
    }

    #[test]
    fn header_length_over_limit() {
        // 18433 = 0x4801: на единицу больше лимита по умолчанию.
        let data = [0x17, 0x03, 0x03, 0x48, 0x01];
        let mut reader = Reader::new(&data);
        assert_eq!(
            RecordHeader::parse(&mut reader, &limits()),
            Err(ParseError::LimitExceeded {
                position: 3,
                limit: "max_record_len",
                max: 18_432,
                actual: 18_433,
            })
        );
        assert_eq!(reader.position(), 0);

        // Ровно на границе заголовок принимается.
        let data = [0x17, 0x03, 0x03, 0x48, 0x00];
        let mut reader = Reader::new(&data);
        let header = RecordHeader::parse(&mut reader, &limits()).unwrap();
        assert_eq!(header.length, 18_432);
    }

    #[test]
    fn parses_record_and_keeps_unknown_type() {
        let data = [0x63, 0x7F, 0x12, 0x00, 0x02, 0xAA, 0xBB, 0xCC];
        let mut reader = Reader::new(&data);
        let record = Record::parse(&mut reader, &limits()).unwrap();
        assert_eq!(record.content_type, ContentType(0x63));
        assert_eq!(record.version, ProtocolVersion(0x7F12));
        assert_eq!(record.fragment, &[0xAA, 0xBB][..]);
        assert_eq!(reader.remaining(), 1);
    }

    #[test]
    fn parses_empty_record() {
        let data = [0x17, 0x03, 0x03, 0x00, 0x00];
        let mut reader = Reader::new(&data);
        let record = Record::parse(&mut reader, &limits()).unwrap();
        assert!(record.fragment.is_empty());
        assert!(reader.is_empty());
    }

    #[test]
    fn truncated_body_does_not_advance() {
        let data = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02];
        let mut reader = Reader::new(&data);
        assert_eq!(
            Record::parse(&mut reader, &limits()),
            Err(ParseError::UnexpectedEof {
                position: 5,
                needed: 2,
                available: 1,
            })
        );
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn record_over_custom_limit() {
        let custom = ParseLimits {
            max_record_len: 2,
            max_handshake_len: 16,
            ..ParseLimits::default()
        };
        let data = [0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];
        let mut reader = Reader::new(&data);
        let error = Record::parse(&mut reader, &custom).unwrap_err();
        assert_eq!(
            error,
            ParseError::LimitExceeded {
                position: 3,
                limit: "max_record_len",
                max: 2,
                actual: 3,
            }
        );
    }

    #[test]
    fn writes_single_record() {
        let mut writer = Writer::new();
        write_record(
            &mut writer,
            ContentType::ALERT,
            ProtocolVersion::TLS1_2,
            &[0x02, 0x28],
        )
        .unwrap();
        assert_eq!(
            writer.as_slice(),
            &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28][..]
        );
    }

    #[test]
    fn single_record_overflow_leaves_buffer_untouched() {
        let mut writer = Writer::new();
        writer.put_u8(0x77);
        let payload = vec![0_u8; 0x1_0000];
        for result in [
            write_record(
                &mut writer,
                ContentType::HANDSHAKE,
                ProtocolVersion::TLS1_0,
                &payload,
            ),
            write_records(
                &mut writer,
                ContentType::HANDSHAKE,
                ProtocolVersion::TLS1_0,
                &payload,
                None,
            ),
        ] {
            assert_eq!(
                result,
                Err(EncodeError::LengthOverflow {
                    prefix_bytes: 2,
                    max: 0xFFFF,
                    actual: 0x1_0000,
                })
            );
        }
        assert_eq!(writer.as_slice(), &[0x77_u8][..]);
    }

    #[test]
    fn fragments_payload() {
        let payload = [1_u8, 2, 3, 4, 5, 6, 7];
        let mut writer = Writer::new();
        write_records(
            &mut writer,
            ContentType::HANDSHAKE,
            ProtocolVersion::TLS1_0,
            &payload,
            NonZeroUsize::new(3),
        )
        .unwrap();
        assert_eq!(
            writer.as_slice(),
            &[
                0x16, 0x03, 0x01, 0x00, 0x03, 1, 2, 3, 0x16, 0x03, 0x01, 0x00, 0x03, 4, 5, 6, 0x16,
                0x03, 0x01, 0x00, 0x01, 7
            ][..]
        );
    }

    #[test]
    fn fragmentation_edge_cases() {
        // Пустые данные — одна пустая запись.
        let mut writer = Writer::new();
        write_records(
            &mut writer,
            ContentType::APPLICATION_DATA,
            ProtocolVersion::TLS1_2,
            &[],
            NonZeroUsize::new(4),
        )
        .unwrap();
        assert_eq!(writer.as_slice(), &[0x17, 0x03, 0x03, 0x00, 0x00][..]);

        // Размер части больше данных — одна запись.
        let mut writer = Writer::new();
        write_records(
            &mut writer,
            ContentType::HANDSHAKE,
            ProtocolVersion::TLS1_2,
            &[8_u8, 9],
            NonZeroUsize::new(100),
        )
        .unwrap();
        assert_eq!(writer.len(), RECORD_HEADER_LEN + 2);

        // Размер части больше 65535 ограничивается полем длины записи.
        let payload = vec![0xAB_u8; 0x1_0000];
        let mut writer = Writer::new();
        write_records(
            &mut writer,
            ContentType::HANDSHAKE,
            ProtocolVersion::TLS1_2,
            &payload,
            NonZeroUsize::new(usize::MAX),
        )
        .unwrap();
        assert_eq!(writer.len(), payload.len() + 2 * RECORD_HEADER_LEN);
    }

    #[test]
    fn writes_handshake_message_and_records() {
        let mut message = Writer::new();
        write_handshake_message(&mut message, HandshakeType::SERVER_HELLO_DONE, &[]).unwrap();
        assert_eq!(message.as_slice(), &[0x0E, 0x00, 0x00, 0x00][..]);

        let mut message = Writer::new();
        write_handshake_message(&mut message, HandshakeType::CLIENT_HELLO, &[0xAA, 0xBB]).unwrap();
        assert_eq!(
            message.as_slice(),
            &[0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB][..]
        );
        assert_eq!(message.len(), HANDSHAKE_HEADER_LEN + 2);

        let mut writer = Writer::new();
        write_handshake_records(
            &mut writer,
            ProtocolVersion::TLS1_0,
            message.as_slice(),
            None,
        )
        .unwrap();
        assert_eq!(
            writer.as_slice(),
            &[
                0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB
            ][..]
        );
    }

    #[test]
    fn handshake_message_body_overflow() {
        let body = vec![0_u8; 0x0100_0000];
        let mut writer = Writer::new();
        assert_eq!(
            write_handshake_message(&mut writer, HandshakeType::CLIENT_HELLO, &body),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 3,
                max: 0x00FF_FFFF,
                actual: 0x0100_0000,
            })
        );
        assert!(writer.is_empty());
    }

    #[test]
    fn round_trip_fragmented_records() {
        let payload: Vec<u8> = (0..=255).collect();
        for chunk in [1_usize, 2, 7, 64, 255, 256, 1000] {
            let mut writer = Writer::new();
            write_records(
                &mut writer,
                ContentType::HANDSHAKE,
                ProtocolVersion::TLS1_2,
                &payload,
                NonZeroUsize::new(chunk),
            )
            .unwrap();

            let bytes = writer.into_inner();
            let mut reader = Reader::new(&bytes);
            let mut joined = Vec::new();
            let mut count = 0_usize;
            while !reader.is_empty() {
                let record = Record::parse(&mut reader, &limits()).unwrap();
                assert_eq!(record.content_type, ContentType::HANDSHAKE);
                assert_eq!(record.version, ProtocolVersion::TLS1_2);
                assert!(record.fragment.len() <= chunk);
                joined.extend_from_slice(record.fragment);
                count += 1;
            }
            assert_eq!(joined, payload, "размер части {chunk}");
            assert_eq!(count, payload.len().div_ceil(chunk));
        }
    }
}
