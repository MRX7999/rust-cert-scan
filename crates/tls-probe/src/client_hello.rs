//! Сборка и разбор ClientHello.
//!
//! [`ClientHello`] — билдер с полным контролем над полями: версия record
//! layer, `legacy_version`, `random`, `session_id`, список cipher suites,
//! методы сжатия и упорядоченный список расширений. Результат — байты тела
//! сообщения, handshake-сообщения или готовых записей.
//!
//! Билдер ничего не проверяет на соответствие RFC: сканеру нужны и
//! намеренно нестандартные hello. Допустимы произвольные коды suites
//! (неизвестные таблицам, SCSV, GREASE), пустые списки, повторяющиеся
//! расширения и любые их сочетания; порядок расширений сохраняется в
//! точности как задан. Ошибка возвращается, только если данные нельзя
//! закодировать: поле не помещается в свой префикс длины.
//!
//! Без расширений поле `extensions` не пишется вовсе — так выглядят hello
//! для SSLv3 и старых серверов. Пустой блок расширений (два нулевых байта)
//! включается явно через [`ClientHello::with_empty_extensions_block`].
//!
//! Генерации случайных чисел здесь нет: `random` задаёт вызывающий код.
//!
//! [`ClientHelloView`] — обратный разбор с заимствованием из входного
//! буфера; используется тестами round-trip и пригоден для разбора чужих
//! ClientHello.

use std::num::NonZeroUsize;

use tls_data::CipherSuite;

use crate::codec::{Reader, Writer};
use crate::error::{EncodeError, ParseError};
use crate::ext::{Extension, RawExtensions};
use crate::record::{HandshakeType, ProtocolVersion, write_handshake_records};

/// Длина поля `random` в байтах; объявлена в
/// [`server_hello`](crate::server_hello) и реэкспортируется здесь.
pub use crate::server_hello::RANDOM_LEN;

/// Билдер ClientHello; описание — в документации модуля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    record_version: ProtocolVersion,
    legacy_version: ProtocolVersion,
    random: [u8; RANDOM_LEN],
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    extensions: Vec<Extension>,
    empty_extensions_block: bool,
    max_fragment_len: Option<NonZeroUsize>,
}

impl ClientHello {
    /// Hello с заданным `random` и значениями по умолчанию: версия record
    /// layer TLS 1.0 (`0x0301`), `legacy_version` TLS 1.2 (`0x0303`), пустой
    /// `session_id`, пустой список suites, один метод сжатия `null`, без
    /// расширений, без фрагментации.
    #[must_use]
    pub fn new(random: [u8; RANDOM_LEN]) -> Self {
        Self {
            record_version: ProtocolVersion::TLS1_0,
            legacy_version: ProtocolVersion::TLS1_2,
            random,
            session_id: Vec::new(),
            cipher_suites: Vec::new(),
            compression_methods: vec![0x00],
            extensions: Vec::new(),
            empty_extensions_block: false,
            max_fragment_len: None,
        }
    }

    /// Задаёт версию в заголовках записей.
    #[must_use]
    pub fn with_record_version(mut self, version: ProtocolVersion) -> Self {
        self.record_version = version;
        self
    }

    /// Задаёт `legacy_version` (в TLS 1.2 и ниже — `client_version`).
    #[must_use]
    pub fn with_legacy_version(mut self, version: ProtocolVersion) -> Self {
        self.legacy_version = version;
        self
    }

    /// Заменяет `random`.
    #[must_use]
    pub fn with_random(mut self, random: [u8; RANDOM_LEN]) -> Self {
        self.random = random;
        self
    }

    /// Задаёт `session_id`; длина проверяется при кодировании.
    #[must_use]
    pub fn with_session_id(mut self, session_id: &[u8]) -> Self {
        self.session_id = session_id.to_vec();
        self
    }

    /// Заменяет список cipher suites. Принимает `u16` и
    /// [`CipherSuite`]; коды не проверяются.
    #[must_use]
    pub fn with_cipher_suites<I>(mut self, cipher_suites: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<u16>,
    {
        self.cipher_suites = cipher_suites.into_iter().map(Into::into).collect();
        self
    }

    /// Заменяет список методов сжатия.
    #[must_use]
    pub fn with_compression_methods(mut self, methods: &[u8]) -> Self {
        self.compression_methods = methods.to_vec();
        self
    }

    /// Добавляет расширение в конец списка.
    #[must_use]
    pub fn with_extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Заменяет список расширений.
    #[must_use]
    pub fn with_extensions<I>(mut self, extensions: I) -> Self
    where
        I: IntoIterator<Item = Extension>,
    {
        self.extensions = extensions.into_iter().collect();
        self
    }

    /// При пустом списке расширений писать пустой блок (два нулевых байта)
    /// вместо отсутствующего поля.
    #[must_use]
    pub fn with_empty_extensions_block(mut self, enabled: bool) -> Self {
        self.empty_extensions_block = enabled;
        self
    }

    /// Задаёт фрагментацию сообщения по записям: `None` — одна запись.
    #[must_use]
    pub fn with_max_fragment_len(mut self, max_fragment_len: Option<NonZeroUsize>) -> Self {
        self.max_fragment_len = max_fragment_len;
        self
    }

    /// Версия в заголовках записей.
    #[must_use]
    pub fn record_version(&self) -> ProtocolVersion {
        self.record_version
    }

    /// Значение `legacy_version`.
    #[must_use]
    pub fn legacy_version(&self) -> ProtocolVersion {
        self.legacy_version
    }

    /// Значение `random`.
    #[must_use]
    pub fn random(&self) -> &[u8; RANDOM_LEN] {
        &self.random
    }

    /// Значение `session_id`.
    #[must_use]
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Коды cipher suites в заданном порядке.
    #[must_use]
    pub fn cipher_suites(&self) -> &[u16] {
        &self.cipher_suites
    }

    /// Методы сжатия.
    #[must_use]
    pub fn compression_methods(&self) -> &[u8] {
        &self.compression_methods
    }

    /// Расширения в заданном порядке.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// Тело ClientHello без заголовка handshake-сообщения.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если `session_id` или список методов
    /// сжатия длиннее 255 байтов, список suites, тело расширения или блок
    /// расширений длиннее 65535 байтов.
    pub fn body_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut writer = Writer::new();
        self.write_body(&mut writer)?;
        Ok(writer.as_slice().to_vec())
    }

    /// Handshake-сообщение: тип `client_hello`, 24-битная длина и тело.
    ///
    /// # Errors
    ///
    /// Как у [`ClientHello::body_bytes`].
    pub fn handshake_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut writer = Writer::new();
        writer.put_u8(HandshakeType::CLIENT_HELLO.0);
        writer.nested_u24(|body| self.write_body(body))?;
        Ok(writer.as_slice().to_vec())
    }

    /// Готовые байты для отправки: сообщение в одной записи либо в
    /// нескольких, если задана фрагментация.
    ///
    /// # Errors
    ///
    /// Как у [`ClientHello::body_bytes`], а также
    /// [`EncodeError::LengthOverflow`], если фрагментация не задана и
    /// сообщение длиннее 65535 байтов.
    pub fn record_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let message = self.handshake_bytes()?;
        let mut writer = Writer::with_capacity(message.len().saturating_add(16));
        write_handshake_records(
            &mut writer,
            self.record_version,
            &message,
            self.max_fragment_len,
        )?;
        Ok(writer.as_slice().to_vec())
    }

    fn write_body(&self, writer: &mut Writer) -> Result<(), EncodeError> {
        writer.put_u16(self.legacy_version.0);
        writer.put_slice(&self.random);
        writer.put_vec_u8(&self.session_id)?;
        writer.nested_u16(|list| {
            for suite in &self.cipher_suites {
                list.put_u16(*suite);
            }
            Ok(())
        })?;
        writer.put_vec_u8(&self.compression_methods)?;
        if !self.extensions.is_empty() || self.empty_extensions_block {
            writer.nested_u16(|block| {
                for extension in &self.extensions {
                    extension.encode(block)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }
}

/// Разобранный ClientHello; срезы заимствуют входной буфер.
#[derive(Debug, Clone)]
pub struct ClientHelloView<'a> {
    /// Значение `legacy_version`.
    pub legacy_version: ProtocolVersion,
    /// Значение `random`.
    pub random: [u8; RANDOM_LEN],
    /// Значение `session_id`.
    pub session_id: &'a [u8],
    /// Список suites как байты: по два байта на код, длина чётная.
    pub cipher_suites_raw: &'a [u8],
    /// Методы сжатия.
    pub compression_methods: &'a [u8],
    /// Содержимое блока расширений; `None`, если поля нет.
    extensions: Option<Reader<'a>>,
}

impl<'a> ClientHelloView<'a> {
    /// Разбирает тело ClientHello (без заголовка handshake-сообщения).
    ///
    /// Формат списка расширений проверяется сразу, тела расширений не
    /// интерпретируются.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если тело обрезано;
    /// [`ParseError::InvalidValue`], если длина списка suites нечётная;
    /// [`ParseError::TrailingBytes`], если после блока расширений остались
    /// байты.
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(body);
        let legacy_version = ProtocolVersion(reader.u16()?);
        let random = reader.array::<RANDOM_LEN>()?;
        let session_id = reader.vec_u8()?;
        let suites_position = reader.position();
        let cipher_suites_raw = reader.vec_u16()?;
        if cipher_suites_raw.len() % 2 != 0 {
            return Err(ParseError::InvalidValue {
                position: suites_position,
                what: "нечётная длина списка cipher suites",
            });
        }
        let compression_methods = reader.vec_u8()?;
        let extensions = if reader.is_empty() {
            None
        } else {
            let block = reader.sub_u16()?;
            reader.finish()?;
            for extension in RawExtensions::new(block.clone()) {
                extension?;
            }
            Some(block)
        };
        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suites_raw,
            compression_methods,
            extensions,
        })
    }

    /// Коды cipher suites в порядке следования.
    pub fn cipher_suites(&self) -> impl Iterator<Item = CipherSuite> + 'a {
        self.cipher_suites_raw
            .chunks_exact(2)
            .filter_map(|pair| match *pair {
                [high, low] => Some(CipherSuite(u16::from_be_bytes([high, low]))),
                _ => None,
            })
    }

    /// Истина, если поле расширений присутствует (в том числе пустое).
    #[must_use]
    pub fn has_extensions_block(&self) -> bool {
        self.extensions.is_some()
    }

    /// Расширения в порядке следования; пусто, если поля нет.
    #[must_use]
    pub fn extensions(&self) -> RawExtensions<'a> {
        RawExtensions::new(self.extensions.clone().unwrap_or_else(|| Reader::new(&[])))
    }
}

#[cfg(test)]
mod tests {
    use tls_data::{NamedGroup, SignatureScheme};

    use super::*;
    use crate::decoder::{Decoder, Event};
    use crate::ext::{KeyShareEntry, RawExtension, kind};
    use crate::limits::ParseLimits;

    const RANDOM: [u8; RANDOM_LEN] = [0x11; RANDOM_LEN];

    /// Пропускает записи через декодер и возвращает тело единственного
    /// handshake-сообщения.
    fn decode_body(records: &[u8], limits: ParseLimits) -> Vec<u8> {
        let mut decoder = Decoder::new(limits);
        let mut input = records;
        let mut bodies = Vec::new();
        loop {
            match decoder.feed(&mut input).unwrap() {
                Event::NeedMore => break,
                Event::Handshake(message) => {
                    assert_eq!(message.msg_type, HandshakeType::CLIENT_HELLO);
                    bodies.push(message.body.to_vec());
                }
                other => panic!("неожиданное событие {other:?}"),
            }
        }
        assert!(decoder.is_idle());
        assert_eq!(bodies.len(), 1);
        bodies.remove(0)
    }

    fn collect_extensions<'a>(view: &ClientHelloView<'a>) -> Vec<RawExtension<'a>> {
        view.extensions().collect::<Result<_, _>>().unwrap()
    }

    fn tls13_hello() -> ClientHello {
        let public = [0x42_u8; 32];
        ClientHello::new(RANDOM)
            .with_session_id(&[0xAB; 32])
            .with_cipher_suites([0x1301_u16, 0x1302, 0x1303])
            .with_extension(Extension::server_name(b"localhost").unwrap())
            .with_extension(Extension::supported_versions(&[ProtocolVersion::TLS1_3]).unwrap())
            .with_extension(Extension::supported_groups(&[NamedGroup(0x001D)]).unwrap())
            .with_extension(Extension::signature_algorithms(&[SignatureScheme(0x0403)]).unwrap())
            .with_extension(
                Extension::key_share(&[KeyShareEntry {
                    group: NamedGroup(0x001D),
                    key_exchange: &public,
                }])
                .unwrap(),
            )
    }

    #[test]
    fn defaults() {
        let hello = ClientHello::new(RANDOM);
        assert_eq!(hello.record_version(), ProtocolVersion::TLS1_0);
        assert_eq!(hello.legacy_version(), ProtocolVersion::TLS1_2);
        assert_eq!(hello.random(), &RANDOM);
        assert!(hello.session_id().is_empty());
        assert!(hello.cipher_suites().is_empty());
        assert_eq!(hello.compression_methods(), &[0x00_u8][..]);
        assert!(hello.extensions().is_empty());
    }

    #[test]
    fn hello_without_extensions_has_no_extensions_field() {
        // Синтетический эталон: hello в стиле SSLv3, составлен по RFC 6101.
        let hello = ClientHello::new(RANDOM)
            .with_record_version(ProtocolVersion::SSL3_0)
            .with_legacy_version(ProtocolVersion::SSL3_0)
            .with_cipher_suites([0x000A_u16, 0x002F]);

        let mut expected = vec![
            0x16, 0x03, 0x00, 0x00, 0x2F, 0x01, 0x00, 0x00, 0x2B, 0x03, 0x00,
        ];
        expected.extend([0x11_u8; RANDOM_LEN]);
        expected.extend([0x00, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x2F, 0x01, 0x00]);
        assert_eq!(hello.record_bytes().unwrap(), expected);

        let body = hello.body_bytes().unwrap();
        assert_eq!(body.as_slice(), &expected[9..]);
        assert_eq!(hello.handshake_bytes().unwrap().as_slice(), &expected[5..]);

        let view = ClientHelloView::parse(&body).unwrap();
        assert!(!view.has_extensions_block());
        assert_eq!(view.extensions().count(), 0);
        assert_eq!(view.legacy_version, ProtocolVersion::SSL3_0);
    }

    #[test]
    fn empty_extensions_block_on_request() {
        let plain = ClientHello::new(RANDOM).body_bytes().unwrap();
        let hello = ClientHello::new(RANDOM).with_empty_extensions_block(true);
        let body = hello.body_bytes().unwrap();
        assert_eq!(body.len(), plain.len() + 2);
        assert!(body.ends_with(&[0x01, 0x00, 0x00, 0x00]));

        let view = ClientHelloView::parse(&body).unwrap();
        assert!(view.has_extensions_block());
        assert_eq!(view.extensions().count(), 0);
    }

    #[test]
    fn round_trip_with_extensions() {
        let hello = tls13_hello();
        let records = hello.record_bytes().unwrap();
        assert_eq!(records.get(..3), Some(&[0x16, 0x03, 0x01][..]));

        let body = decode_body(&records, ParseLimits::default());
        assert_eq!(body, hello.body_bytes().unwrap());

        let view = ClientHelloView::parse(&body).unwrap();
        assert_eq!(view.legacy_version, ProtocolVersion::TLS1_2);
        assert_eq!(view.random, RANDOM);
        assert_eq!(view.session_id, &[0xAB; 32][..]);
        assert_eq!(
            view.cipher_suites().map(u16::from).collect::<Vec<_>>(),
            hello.cipher_suites()
        );
        assert_eq!(view.compression_methods, &[0x00_u8][..]);

        let parsed = collect_extensions(&view);
        assert_eq!(parsed.len(), hello.extensions().len());
        for (parsed, built) in parsed.iter().zip(hello.extensions()) {
            assert_eq!(parsed.ext_type, built.ext_type());
            assert_eq!(parsed.data, built.data());
        }
        assert_eq!(
            parsed.iter().map(|item| item.ext_type).collect::<Vec<_>>(),
            vec![
                kind::SERVER_NAME,
                kind::SUPPORTED_VERSIONS,
                kind::SUPPORTED_GROUPS,
                kind::SIGNATURE_ALGORITHMS,
                kind::KEY_SHARE,
            ]
        );
    }

    #[test]
    fn extension_order_and_duplicates_are_preserved() {
        let hello = ClientHello::new(RANDOM)
            .with_cipher_suites([0xC02F_u16])
            .with_extensions([
                Extension::raw(0xFAFA, &[0x01]),
                Extension::extended_master_secret(),
                Extension::raw(0xFAFA, &[0x02]),
                Extension::extended_master_secret(),
                Extension::server_name(b"a").unwrap(),
                Extension::server_name(b"b").unwrap(),
                Extension::raw(kind::KEY_SHARE.0, &[0xFF]),
            ]);
        let body = hello.body_bytes().unwrap();
        let view = ClientHelloView::parse(&body).unwrap();
        let codes: Vec<u16> = collect_extensions(&view)
            .iter()
            .map(|item| item.ext_type.0)
            .collect();
        assert_eq!(
            codes,
            vec![0xFAFA, 0x0017, 0xFAFA, 0x0017, 0x0000, 0x0000, 0x0033]
        );
    }

    #[test]
    fn arbitrary_cipher_suite_codes() {
        // Неизвестный код, SCSV (0x00FF, 0x5600), GREASE и повтор.
        let codes = [0xFFFF_u16, 0x00FF, 0x5600, 0x0A0A, 0x1301, 0x1301, 0x0000];
        let hello = ClientHello::new(RANDOM).with_cipher_suites(codes);
        let body = hello.body_bytes().unwrap();
        let view = ClientHelloView::parse(&body).unwrap();
        assert_eq!(
            view.cipher_suites().map(u16::from).collect::<Vec<_>>(),
            codes
        );

        // Те же коды через тип tls-data.
        let typed = ClientHello::new(RANDOM).with_cipher_suites(codes.map(CipherSuite));
        assert_eq!(typed.body_bytes().unwrap(), body);
    }

    #[test]
    fn every_field_is_configurable() {
        let hello = ClientHello::new(RANDOM)
            .with_random([0x22; RANDOM_LEN])
            .with_record_version(ProtocolVersion(0x0305))
            .with_legacy_version(ProtocolVersion(0x0302))
            .with_session_id(&[0x01, 0x02])
            .with_cipher_suites([0x002F_u16])
            .with_compression_methods(&[0x01, 0x00]);
        let records = hello.record_bytes().unwrap();
        assert_eq!(records.get(..3), Some(&[0x16, 0x03, 0x05][..]));

        let view_body = hello.body_bytes().unwrap();
        let view = ClientHelloView::parse(&view_body).unwrap();
        assert_eq!(view.legacy_version, ProtocolVersion::TLS1_1);
        assert_eq!(view.random, [0x22; RANDOM_LEN]);
        assert_eq!(view.session_id, &[0x01, 0x02][..]);
        assert_eq!(view.compression_methods, &[0x01, 0x00][..]);

        // Пустые списки suites и методов сжатия тоже кодируются.
        let empty = ClientHello::new(RANDOM).with_compression_methods(&[]);
        let body = empty.body_bytes().unwrap();
        assert!(body.ends_with(&[0x00, 0x00, 0x00, 0x00]));
        let view = ClientHelloView::parse(&body).unwrap();
        assert_eq!(view.cipher_suites().count(), 0);
        assert!(view.compression_methods.is_empty());
    }

    #[test]
    fn fragmented_hello_is_reassembled() {
        let hello = tls13_hello()
            .with_extension(Extension::padding(500))
            .with_max_fragment_len(NonZeroUsize::new(100));
        let records = hello.record_bytes().unwrap();
        let message_len = hello.handshake_bytes().unwrap().len();
        assert_eq!(records.len(), message_len + 5 * message_len.div_ceil(100));

        let body = decode_body(&records, ParseLimits::default());
        assert_eq!(body, hello.body_bytes().unwrap());
    }

    #[test]
    fn field_prefix_overflows() {
        let base = ClientHello::new(RANDOM);
        assert!(
            base.clone()
                .with_session_id(&[0_u8; 255])
                .body_bytes()
                .is_ok()
        );
        assert_eq!(
            base.clone().with_session_id(&[0_u8; 256]).body_bytes(),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 1,
                max: 0xFF,
                actual: 256,
            })
        );
        assert!(
            base.clone()
                .with_compression_methods(&[0_u8; 256])
                .body_bytes()
                .is_err()
        );

        let suites = vec![0x1301_u16; 0x7FFF];
        assert!(base.clone().with_cipher_suites(suites).body_bytes().is_ok());
        let suites = vec![0x1301_u16; 0x8000];
        assert_eq!(
            base.clone().with_cipher_suites(suites).handshake_bytes(),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                max: 0xFFFF,
                actual: 0x1_0000,
            })
        );

        // Каждое расширение помещается, блок целиком — нет.
        let hello = base
            .clone()
            .with_extension(Extension::padding(40_000))
            .with_extension(Extension::padding(40_000));
        assert!(matches!(
            hello.record_bytes(),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                ..
            })
        ));

        // Тело одного расширения не помещается в свой префикс.
        let hello = base.with_extension(Extension::padding(0x1_0000));
        assert!(hello.body_bytes().is_err());
    }

    #[test]
    fn oversized_message_needs_fragmentation() {
        // Блок расширений ровно 65535 байтов: сообщение длиннее записи.
        let hello = ClientHello::new(RANDOM).with_extension(Extension::padding(0xFFFF - 4));
        let message_len = hello.handshake_bytes().unwrap().len();
        assert!(message_len > 0xFFFF);
        assert_eq!(
            hello.record_bytes(),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                max: 0xFFFF,
                actual: message_len,
            })
        );

        let fragmented = hello.with_max_fragment_len(NonZeroUsize::new(16_384));
        let records = fragmented.record_bytes().unwrap();
        let limits = ParseLimits {
            max_handshake_len: 70_000,
            ..ParseLimits::default()
        };
        let body = decode_body(&records, limits);
        assert_eq!(body, fragmented.body_bytes().unwrap());
    }

    #[test]
    fn every_truncation_is_an_error_except_extensionless_form() {
        let hello = tls13_hello();
        let body = hello.body_bytes().unwrap();
        let without_extensions = hello.clone().with_extensions([]).body_bytes().unwrap();
        assert!(body.starts_with(&without_extensions));

        for len in 0..body.len() {
            let result = ClientHelloView::parse(&body[..len]);
            if len == without_extensions.len() {
                assert!(result.is_ok(), "длина {len}");
            } else {
                assert!(result.is_err(), "длина {len}");
            }
        }
        assert!(ClientHelloView::parse(&body).is_ok());
    }

    #[test]
    fn parse_errors() {
        // Нечётная длина списка suites.
        let mut body = vec![0x03, 0x03];
        body.extend([0x11_u8; RANDOM_LEN]);
        body.extend([0x00, 0x00, 0x03, 0x00, 0x0A, 0x00, 0x01, 0x00]);
        assert_eq!(
            ClientHelloView::parse(&body).unwrap_err(),
            ParseError::InvalidValue {
                position: 35,
                what: "нечётная длина списка cipher suites",
            }
        );

        // Лишний байт после блока расширений.
        let mut body = tls13_hello().body_bytes().unwrap();
        let end = body.len();
        body.push(0x00);
        assert_eq!(
            ClientHelloView::parse(&body).unwrap_err(),
            ParseError::TrailingBytes {
                position: end,
                remaining: 1,
            }
        );

        // Расширение внутри блока заявляет больше байтов, чем есть.
        let mut body = ClientHello::new(RANDOM).body_bytes().unwrap();
        body.extend([0x00, 0x05, 0x00, 0x17, 0x00, 0x04, 0xAA]);
        assert!(matches!(
            ClientHelloView::parse(&body),
            Err(ParseError::UnexpectedEof { .. })
        ));
    }
}
