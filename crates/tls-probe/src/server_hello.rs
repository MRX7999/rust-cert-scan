//! Разбор ServerHello и HelloRetryRequest.
//!
//! [`ServerHello::parse`] разбирает тело сообщения `server_hello` поверх
//! [`Reader`]: все срезы заимствуют входной буфер, память по длинам из
//! данных не выделяется. HelloRetryRequest имеет тот же формат и
//! распознаётся по специальному значению `random`
//! ([`HELLO_RETRY_REQUEST_RANDOM`]).
//!
//! Итоговая версия протокола ([`ServerHello::version`]) берётся из
//! расширения `supported_versions`, только если оно встретилось ровно один
//! раз и разобрано корректно; иначе из `legacy_version`. ServerHello без
//! поля расширений (SSLv3, TLS 1.0) разбирается так же, как с ним.
//!
//! Отклонения, которые разбору не мешают, но нужны проверкам как находки
//! (дубликат расширения, повреждённое `supported_versions`,
//! `supported_versions` со значением ниже TLS 1.3), возвращает
//! [`ServerHello::anomalies`].
//!
//! # Расширения
//!
//! Формат списка расширений (тип, длина, тело) проверяется при разборе
//! hello: если он нарушен, границы расширений неизвестны и ошибкой
//! становится весь ServerHello. Тела расширений разбираются при обходе
//! [`ServerHello::extensions`] и в [`ServerHello::extension`]; исключение —
//! `supported_versions`: его тело разбирается ещё и в
//! [`ServerHello::parse`], чтобы определить [`ServerHello::version`].
//! Результат разбора тела:
//!
//! - известное расширение с корректным телом — типизированный вариант
//!   [`ServerExtension`];
//! - неизвестное расширение — [`ServerExtension::Unknown`] с типом и срезом
//!   тела;
//! - известное расширение с некорректным телом —
//!   [`ServerExtension::Malformed`] с типом, сырыми байтами и ошибкой.
//!   Остальные поля ServerHello и остальные расширения при этом не теряются.
//!   Позиция в такой ошибке отсчитывается от начала тела расширения.
//!   Повреждённое `supported_versions` на [`ServerHello::version`] не
//!   влияет: возвращается `legacy_version`.
//!
//! Расширение одного типа не должно встречаться дважды (RFC 8446, раздел
//! 4.2). Если встречается, [`ServerHello::extension`] для этого типа
//! возвращает `None`: выбрать один экземпляр нельзя, не разойдясь с
//! [`ServerHello::version`]. Все экземпляры доступны через
//! [`ServerHello::extensions`] и [`ServerHello::raw_extensions`].

use tls_data::{CipherSuite, ExtensionType, NamedGroup};

use crate::codec::Reader;
use crate::error::ParseError;
use crate::ext::{RawExtension, RawExtensions, kind};
use crate::record::ProtocolVersion;

/// Длина поля `random` в байтах.
pub const RANDOM_LEN: usize = 32;

/// Значение `random`, по которому ServerHello распознаётся как
/// HelloRetryRequest: SHA-256 от строки "HelloRetryRequest".
///
/// Источник: RFC 8446, раздел 4.1.3.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; RANDOM_LEN] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Последние 8 байтов `random`, которыми сервер с поддержкой TLS 1.3
/// помечает согласование TLS 1.2 («DOWNGRD» и 0x01).
///
/// Источник: RFC 8446, раздел 4.1.3.
pub const DOWNGRADE_MARKER_TLS12: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];

/// Последние 8 байтов `random`, которыми сервер помечает согласование
/// TLS 1.1 или ниже («DOWNGRD» и 0x00).
///
/// Источник: RFC 8446, раздел 4.1.3.
pub const DOWNGRADE_MARKER_TLS11_OR_BELOW: [u8; 8] =
    [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

/// Наибольшая длина `session_id` по RFC 5246 и RFC 8446.
const MAX_SESSION_ID_LEN: usize = 32;

/// Маркер downgrade в последних байтах `random` (RFC 8446, раздел 4.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DowngradeMarker {
    /// Сервер умеет TLS 1.3, но согласовал TLS 1.2.
    Tls12,
    /// Сервер умеет более новую версию, но согласовал TLS 1.1 или ниже.
    Tls11OrBelow,
}

/// Расширение `key_share` в ответе сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKeyShare<'a> {
    /// Форма ServerHello: группа и публичное значение сервера.
    Entry {
        /// Выбранная группа.
        group: NamedGroup,
        /// Публичное значение сервера.
        key_exchange: &'a [u8],
    },
    /// Форма HelloRetryRequest: группа, для которой сервер ждёт key share.
    RetryGroup(NamedGroup),
}

impl ServerKeyShare<'_> {
    /// Группа из расширения в любой форме.
    #[must_use]
    pub fn group(&self) -> NamedGroup {
        match *self {
            Self::Entry { group, .. } | Self::RetryGroup(group) => group,
        }
    }
}

/// Список имён протоколов из расширения NPN: последовательность векторов
/// с однобайтовой длиной. Формат проверен при разборе расширения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolNames<'a>(&'a [u8]);

impl<'a> ProtocolNames<'a> {
    /// Список как байты.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Имена в порядке следования.
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        let mut reader = Reader::new(self.0);
        std::iter::from_fn(move || {
            if reader.is_empty() {
                None
            } else {
                reader.vec_u8().ok()
            }
        })
    }
}

/// Расширение ServerHello; правила — в документации модуля.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerExtension<'a> {
    /// `supported_versions`: выбранная версия.
    SupportedVersions(ProtocolVersion),
    /// `key_share`.
    KeyShare(ServerKeyShare<'a>),
    /// ALPN: имя выбранного протокола.
    Alpn(&'a [u8]),
    /// NPN: протоколы, объявленные сервером.
    NextProtocolNegotiation(ProtocolNames<'a>),
    /// `renegotiation_info`: значение `renegotiated_connection`.
    RenegotiationInfo(&'a [u8]),
    /// `session_ticket`: сервер выдаст ticket.
    SessionTicket,
    /// `status_request`: сервер пришлёт CertificateStatus.
    StatusRequest,
    /// `extended_master_secret` (код 23). Снимок IANA называет этот код
    /// `extended_main_secret`; имя IANA доступно через `tls-data`
    /// (`docs/DECISIONS.md`, D-12).
    ExtendedMasterSecret,
    /// `encrypt_then_mac`.
    EncryptThenMac,
    /// `heartbeat`: режим.
    Heartbeat(u8),
    /// `ec_point_formats`: список форматов.
    EcPointFormats(&'a [u8]),
    /// `server_name`: сервер принял SNI.
    ServerName,
    /// Расширение без типизированного разбора: тип и тело.
    Unknown(RawExtension<'a>),
    /// Известное расширение с некорректным телом.
    Malformed {
        /// Тип и сырые байты тела.
        raw: RawExtension<'a>,
        /// Ошибка разбора; позиция — от начала тела расширения.
        error: ParseError,
    },
}

impl<'a> ServerExtension<'a> {
    /// Разбирает тело расширения. `hello_retry` выбирает форму `key_share`.
    #[must_use]
    pub fn parse(raw: RawExtension<'a>, hello_retry: bool) -> Self {
        match parse_known(raw, hello_retry) {
            Ok(Some(extension)) => extension,
            Ok(None) => Self::Unknown(raw),
            Err(error) => Self::Malformed { raw, error },
        }
    }
}

fn parse_known<'a>(
    raw: RawExtension<'a>,
    hello_retry: bool,
) -> Result<Option<ServerExtension<'a>>, ParseError> {
    let mut reader = Reader::new(raw.data);
    let extension = match raw.ext_type {
        kind::SUPPORTED_VERSIONS => {
            ServerExtension::SupportedVersions(ProtocolVersion(reader.u16()?))
        }
        kind::KEY_SHARE => {
            let group = NamedGroup(reader.u16()?);
            if hello_retry {
                ServerExtension::KeyShare(ServerKeyShare::RetryGroup(group))
            } else {
                ServerExtension::KeyShare(ServerKeyShare::Entry {
                    group,
                    key_exchange: reader.vec_u16()?,
                })
            }
        }
        kind::ALPN => {
            let mut list = reader.sub_u16()?;
            let name = list.vec_u8()?;
            list.finish()?;
            ServerExtension::Alpn(name)
        }
        kind::NEXT_PROTOCOL_NEGOTIATION => {
            let names = reader.rest();
            let mut check = Reader::new(names);
            while !check.is_empty() {
                check.vec_u8()?;
            }
            ServerExtension::NextProtocolNegotiation(ProtocolNames(names))
        }
        kind::RENEGOTIATION_INFO => ServerExtension::RenegotiationInfo(reader.vec_u8()?),
        kind::SESSION_TICKET => ServerExtension::SessionTicket,
        kind::STATUS_REQUEST => ServerExtension::StatusRequest,
        kind::EXTENDED_MASTER_SECRET => ServerExtension::ExtendedMasterSecret,
        kind::ENCRYPT_THEN_MAC => ServerExtension::EncryptThenMac,
        kind::HEARTBEAT => ServerExtension::Heartbeat(reader.u8()?),
        kind::EC_POINT_FORMATS => ServerExtension::EcPointFormats(reader.vec_u8()?),
        kind::SERVER_NAME => ServerExtension::ServerName,
        _ => return Ok(None),
    };
    reader.finish()?;
    Ok(Some(extension))
}

/// Отклонение в ServerHello, которое не мешает разбору, но является
/// находкой для проверок; см. [`ServerHello::anomalies`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerHelloAnomaly {
    /// Расширение этого типа встретилось более одного раза (RFC 8446,
    /// раздел 4.2). Сообщается один раз на тип.
    DuplicateExtension(ExtensionType),
    /// Расширение `supported_versions` с некорректным телом; ошибка разбора
    /// с позицией от начала тела расширения.
    MalformedSupportedVersions(ParseError),
    /// Расширение `supported_versions` со значением ниже TLS 1.3: сервер,
    /// согласующий TLS 1.2 и ниже, это расширение слать не должен
    /// (RFC 8446, раздел 4.2.1).
    SupportedVersionsBelowTls13(ProtocolVersion),
}

/// Разобранный ServerHello или HelloRetryRequest.
#[derive(Debug, Clone)]
pub struct ServerHello<'a> {
    /// Значение `legacy_version` (в TLS 1.2 и ниже — `server_version`).
    pub legacy_version: ProtocolVersion,
    /// Значение `random`.
    pub random: [u8; RANDOM_LEN],
    /// Значение `session_id` (в TLS 1.3 — `legacy_session_id_echo`).
    pub session_id: &'a [u8],
    /// Выбранный cipher suite.
    pub cipher_suite: CipherSuite,
    /// Выбранный метод сжатия.
    pub compression_method: u8,
    /// Содержимое блока расширений; `None`, если поля нет.
    extensions: Option<Reader<'a>>,
    /// Версия из `supported_versions`, если расширение встретилось ровно
    /// один раз и разобрано корректно.
    selected_version: Option<ProtocolVersion>,
}

impl<'a> ServerHello<'a> {
    /// Разбирает тело сообщения `server_hello` (без заголовка
    /// handshake-сообщения).
    ///
    /// # Errors
    ///
    /// - [`ParseError::UnexpectedEof`] — тело обрезано либо расширение
    ///   заявляет больше байтов, чем есть в блоке;
    /// - [`ParseError::InvalidValue`] — `session_id` длиннее 32 байтов;
    /// - [`ParseError::TrailingBytes`] — после блока расширений остались
    ///   байты.
    ///
    /// Некорректное тело отдельного расширения ошибкой не считается, см.
    /// документацию модуля.
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(body);
        let legacy_version = ProtocolVersion(reader.u16()?);
        let random = reader.array::<RANDOM_LEN>()?;
        let session_id_position = reader.position();
        let session_id = reader.vec_u8()?;
        if session_id.len() > MAX_SESSION_ID_LEN {
            return Err(ParseError::InvalidValue {
                position: session_id_position,
                what: "session_id длиннее 32 байтов",
            });
        }
        let cipher_suite = CipherSuite(reader.u16()?);
        let compression_method = reader.u8()?;

        let extensions = if reader.is_empty() {
            None
        } else {
            let block = reader.sub_u16()?;
            reader.finish()?;
            Some(block)
        };

        let hello_retry = random == HELLO_RETRY_REQUEST_RANDOM;
        let mut selected_version = None;
        let mut versions_seen = 0_usize;
        if let Some(block) = &extensions {
            for raw in RawExtensions::new(block.clone()) {
                let raw = raw?;
                if raw.ext_type == kind::SUPPORTED_VERSIONS {
                    versions_seen = versions_seen.saturating_add(1);
                    selected_version = match ServerExtension::parse(raw, hello_retry) {
                        ServerExtension::SupportedVersions(version) => Some(version),
                        _ => None,
                    };
                }
            }
        }
        // Дубликат supported_versions: ни один экземпляр не используется.
        if versions_seen != 1 {
            selected_version = None;
        }

        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
            selected_version,
        })
    }

    /// Истина, если сообщение — HelloRetryRequest: `random` равен
    /// специальному значению из RFC 8446, раздел 4.1.3.
    #[must_use]
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }

    /// Итоговая версия протокола.
    ///
    /// Значение расширения `supported_versions`, только если расширение
    /// встретилось ровно один раз и разобрано корректно; во всех остальных
    /// случаях (расширения нет, тело повреждено, расширение повторяется) —
    /// `legacy_version`. Значение расширения возвращается как есть, в том
    /// числе ниже TLS 1.3: это отклонение сообщает
    /// [`ServerHello::anomalies`].
    ///
    /// Результат всегда согласован с [`ServerHello::extension`]: если
    /// `extension(kind::SUPPORTED_VERSIONS)` вернул
    /// [`ServerExtension::SupportedVersions`], `version()` равна его
    /// значению, иначе — `legacy_version`.
    #[must_use]
    pub fn version(&self) -> ProtocolVersion {
        self.selected_version.unwrap_or(self.legacy_version)
    }

    /// Отклонения ServerHello, не мешающие разбору: сначала дубликаты
    /// расширений по возрастанию кода типа (по одному на тип), затем
    /// отклонения `supported_versions` в порядке следования расширений.
    ///
    /// Память выделяется по числу фактически присутствующих расширений.
    #[must_use]
    pub fn anomalies(&self) -> Vec<ServerHelloAnomaly> {
        let mut types: Vec<u16> = self
            .raw_extensions()
            .filter_map(Result::ok)
            .map(|raw| raw.ext_type.0)
            .collect();
        types.sort_unstable();

        let mut anomalies = Vec::new();
        let mut previous = None;
        let mut reported = None;
        for ext_type in types {
            if previous == Some(ext_type) && reported != Some(ext_type) {
                anomalies.push(ServerHelloAnomaly::DuplicateExtension(ExtensionType(
                    ext_type,
                )));
                reported = Some(ext_type);
            }
            previous = Some(ext_type);
        }

        for extension in self.extensions() {
            match extension {
                ServerExtension::Malformed { raw, error }
                    if raw.ext_type == kind::SUPPORTED_VERSIONS =>
                {
                    anomalies.push(ServerHelloAnomaly::MalformedSupportedVersions(error));
                }
                ServerExtension::SupportedVersions(version)
                    if version.0 < ProtocolVersion::TLS1_3.0 =>
                {
                    anomalies.push(ServerHelloAnomaly::SupportedVersionsBelowTls13(version));
                }
                _ => {}
            }
        }
        anomalies
    }

    /// Маркер downgrade в последних 8 байтах `random` (RFC 8446, раздел
    /// 4.1.3). Для HelloRetryRequest всегда `None`. Сопоставление маркера с
    /// согласованной версией — дело проверки, а не парсера.
    #[must_use]
    pub fn downgrade_marker(&self) -> Option<DowngradeMarker> {
        if self.is_hello_retry_request() {
            return None;
        }
        let tail = self.random.last_chunk::<8>()?;
        if *tail == DOWNGRADE_MARKER_TLS12 {
            Some(DowngradeMarker::Tls12)
        } else if *tail == DOWNGRADE_MARKER_TLS11_OR_BELOW {
            Some(DowngradeMarker::Tls11OrBelow)
        } else {
            None
        }
    }

    /// Истина, если поле расширений присутствует (в том числе пустое).
    #[must_use]
    pub fn has_extensions_block(&self) -> bool {
        self.extensions.is_some()
    }

    /// Расширения как тип и срез тела, в порядке следования.
    #[must_use]
    pub fn raw_extensions(&self) -> RawExtensions<'a> {
        RawExtensions::new(self.extensions.clone().unwrap_or_else(|| Reader::new(&[])))
    }

    /// Расширения с типизированным разбором, в порядке следования.
    pub fn extensions(&self) -> impl Iterator<Item = ServerExtension<'a>> + 'a {
        let hello_retry = self.is_hello_retry_request();
        self.raw_extensions()
            .filter_map(Result::ok)
            .map(move |raw| ServerExtension::parse(raw, hello_retry))
    }

    /// Единственное расширение с заданным типом, с типизированным разбором.
    ///
    /// `None`, если расширения этого типа нет либо оно встретилось более
    /// одного раза: при дубликате ни один экземпляр не выбирается (то же
    /// правило, что в [`ServerHello::version`]). Дубликат сообщает
    /// [`ServerHello::anomalies`], все экземпляры отдаёт
    /// [`ServerHello::extensions`].
    #[must_use]
    pub fn extension(&self, ext_type: ExtensionType) -> Option<ServerExtension<'a>> {
        let hello_retry = self.is_hello_retry_request();
        let mut found = self
            .raw_extensions()
            .filter_map(Result::ok)
            .filter(|raw| raw.ext_type == ext_type);
        let single = found.next()?;
        if found.next().is_some() {
            return None;
        }
        Some(ServerExtension::parse(single, hello_retry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;

    const RANDOM: [u8; RANDOM_LEN] = [0x5A; RANDOM_LEN];

    /// Собирает синтетическое тело ServerHello.
    fn hello(
        version: u16,
        random: [u8; RANDOM_LEN],
        session_id: &[u8],
        suite: u16,
        compression: u8,
        extensions: Option<&[(u16, &[u8])]>,
    ) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.put_u16(version);
        writer.put_slice(&random);
        writer.put_vec_u8(session_id).unwrap();
        writer.put_u16(suite);
        writer.put_u8(compression);
        if let Some(extensions) = extensions {
            writer
                .nested_u16(|block| {
                    for (ext_type, data) in extensions {
                        block.put_u16(*ext_type);
                        block.put_vec_u16(data)?;
                    }
                    Ok(())
                })
                .unwrap();
        }
        writer.as_slice().to_vec()
    }

    fn random_with_tail(tail: [u8; 8]) -> [u8; RANDOM_LEN] {
        let mut random = RANDOM;
        random[RANDOM_LEN - 8..].copy_from_slice(&tail);
        random
    }

    #[test]
    fn hello_without_extensions() {
        // Форма SSLv3 и TLS 1.0: поля расширений нет.
        for version in [0x0300_u16, 0x0301] {
            let body = hello(version, RANDOM, &[0xAB; 32], 0x002F, 0x00, None);
            assert_eq!(body.len(), 2 + 32 + 1 + 32 + 2 + 1);
            let parsed = ServerHello::parse(&body).unwrap();
            assert_eq!(parsed.legacy_version, ProtocolVersion(version));
            assert_eq!(parsed.version(), ProtocolVersion(version));
            assert_eq!(parsed.random, RANDOM);
            assert_eq!(parsed.session_id, &[0xAB; 32][..]);
            assert_eq!(parsed.cipher_suite, CipherSuite(0x002F));
            assert_eq!(parsed.compression_method, 0);
            assert!(!parsed.has_extensions_block());
            assert_eq!(parsed.extensions().count(), 0);
            assert_eq!(parsed.raw_extensions().count(), 0);
            assert!(!parsed.is_hello_retry_request());
            assert_eq!(parsed.downgrade_marker(), None);
        }
    }

    #[test]
    fn empty_extensions_block() {
        let body = hello(0x0303, RANDOM, &[], 0xC02F, 0x00, Some(&[]));
        let parsed = ServerHello::parse(&body).unwrap();
        assert!(parsed.has_extensions_block());
        assert_eq!(parsed.extensions().count(), 0);
        assert!(parsed.session_id.is_empty());
    }

    #[test]
    fn tls12_hello_with_typed_extensions() {
        let alpn = [0x00, 0x03, 0x02, b'h', b'2'];
        let npn = [
            0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        let extensions: &[(u16, &[u8])] = &[
            (0xFF01, &[0x00]),
            (0x0000, &[]),
            (0x000B, &[0x03, 0x00, 0x01, 0x02]),
            (0x0023, &[]),
            (0x0010, &alpn),
            (0x0005, &[]),
            (0x0017, &[]),
            (0x0016, &[]),
            (0x000F, &[0x01]),
            (0x3374, &npn),
            (0xABCD, &[0xDE, 0xAD]),
        ];
        let body = hello(0x0303, RANDOM, &[0x01; 32], 0xC02C, 0x00, Some(extensions));
        let parsed = ServerHello::parse(&body).unwrap();
        assert_eq!(parsed.version(), ProtocolVersion::TLS1_2);
        assert_eq!(parsed.cipher_suite, CipherSuite(0xC02C));

        let typed: Vec<_> = parsed.extensions().collect();
        assert_eq!(typed.len(), extensions.len());
        let mut iter = typed.into_iter();
        assert_eq!(iter.next(), Some(ServerExtension::RenegotiationInfo(&[])));
        assert_eq!(iter.next(), Some(ServerExtension::ServerName));
        assert_eq!(
            iter.next(),
            Some(ServerExtension::EcPointFormats(&[0x00, 0x01, 0x02]))
        );
        assert_eq!(iter.next(), Some(ServerExtension::SessionTicket));
        assert_eq!(iter.next(), Some(ServerExtension::Alpn(b"h2")));
        assert_eq!(iter.next(), Some(ServerExtension::StatusRequest));
        assert_eq!(iter.next(), Some(ServerExtension::ExtendedMasterSecret));
        assert_eq!(iter.next(), Some(ServerExtension::EncryptThenMac));
        assert_eq!(iter.next(), Some(ServerExtension::Heartbeat(0x01)));
        match iter.next() {
            Some(ServerExtension::NextProtocolNegotiation(names)) => {
                assert_eq!(names.as_bytes(), &npn[..]);
                let names: Vec<&[u8]> = names.iter().collect();
                assert_eq!(names, vec![&b"h2"[..], &b"http/1.1"[..]]);
            }
            other => panic!("ожидался NPN, получено {other:?}"),
        }
        assert_eq!(
            iter.next(),
            Some(ServerExtension::Unknown(RawExtension {
                ext_type: ExtensionType(0xABCD),
                data: &[0xDE, 0xAD],
            }))
        );
        assert_eq!(iter.next(), None);

        assert_eq!(
            parsed.extension(kind::HEARTBEAT),
            Some(ServerExtension::Heartbeat(0x01))
        );
        assert_eq!(parsed.extension(kind::KEY_SHARE), None);
    }

    #[test]
    fn tls13_hello_uses_supported_versions() {
        let mut key_share = vec![0x00, 0x1D, 0x00, 0x20];
        key_share.extend([0x77_u8; 32]);
        let extensions: &[(u16, &[u8])] = &[(0x002B, &[0x03, 0x04]), (0x0033, &key_share)];
        let body = hello(0x0303, RANDOM, &[0xEE; 32], 0x1302, 0x00, Some(extensions));
        let parsed = ServerHello::parse(&body).unwrap();
        assert_eq!(parsed.legacy_version, ProtocolVersion::TLS1_2);
        assert_eq!(parsed.version(), ProtocolVersion::TLS1_3);
        assert!(!parsed.is_hello_retry_request());
        assert_eq!(
            parsed.extension(kind::SUPPORTED_VERSIONS),
            Some(ServerExtension::SupportedVersions(ProtocolVersion::TLS1_3))
        );
        let share = parsed.extension(kind::KEY_SHARE);
        assert_eq!(
            share,
            Some(ServerExtension::KeyShare(ServerKeyShare::Entry {
                group: NamedGroup(0x001D),
                key_exchange: &[0x77; 32],
            }))
        );
        match share {
            Some(ServerExtension::KeyShare(share)) => {
                assert_eq!(share.group(), NamedGroup(0x001D));
            }
            other => panic!("ожидался key_share, получено {other:?}"),
        }
    }

    #[test]
    fn hello_retry_request_is_recognized() {
        let extensions: &[(u16, &[u8])] = &[(0x002B, &[0x03, 0x04]), (0x0033, &[0x00, 0x17])];
        let body = hello(
            0x0303,
            HELLO_RETRY_REQUEST_RANDOM,
            &[0xEE; 32],
            0x1301,
            0x00,
            Some(extensions),
        );
        let parsed = ServerHello::parse(&body).unwrap();
        assert!(parsed.is_hello_retry_request());
        assert_eq!(parsed.version(), ProtocolVersion::TLS1_3);
        assert_eq!(parsed.downgrade_marker(), None);
        let share = parsed.extension(kind::KEY_SHARE);
        assert_eq!(
            share,
            Some(ServerExtension::KeyShare(ServerKeyShare::RetryGroup(
                NamedGroup(0x0017)
            )))
        );

        // То же тело key_share в обычном ServerHello некорректно: нет ключа.
        let body = hello(0x0303, RANDOM, &[], 0x1301, 0x00, Some(extensions));
        let parsed = ServerHello::parse(&body).unwrap();
        assert!(matches!(
            parsed.extension(kind::KEY_SHARE),
            Some(ServerExtension::Malformed { .. })
        ));

        // Отличие в одном байте random — уже не HRR.
        let mut random = HELLO_RETRY_REQUEST_RANDOM;
        random[RANDOM_LEN - 1] ^= 0x01;
        let body = hello(0x0303, random, &[], 0x1301, 0x00, Some(extensions));
        assert!(!ServerHello::parse(&body).unwrap().is_hello_retry_request());
    }

    #[test]
    fn special_random_values_have_expected_edges() {
        // Только края значений из RFC 8446, раздел 4.1.3. Все 32 байта
        // HELLO_RETRY_REQUEST_RANDOM сравниваются с записанным ответом
        // сервера в fixture_tests::hello_retry_request.
        assert_eq!(HELLO_RETRY_REQUEST_RANDOM.first(), Some(&0xCF));
        assert_eq!(HELLO_RETRY_REQUEST_RANDOM.last(), Some(&0x9C));
        assert_eq!(&DOWNGRADE_MARKER_TLS12[..7], b"DOWNGRD");
        assert_eq!(&DOWNGRADE_MARKER_TLS11_OR_BELOW[..7], b"DOWNGRD");
    }

    #[test]
    fn downgrade_markers() {
        let cases = [
            (DOWNGRADE_MARKER_TLS12, Some(DowngradeMarker::Tls12)),
            (
                DOWNGRADE_MARKER_TLS11_OR_BELOW,
                Some(DowngradeMarker::Tls11OrBelow),
            ),
            ([0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x02], None),
            ([0x00; 8], None),
        ];
        for (tail, expected) in cases {
            let body = hello(0x0303, random_with_tail(tail), &[], 0xC02F, 0x00, None);
            let parsed = ServerHello::parse(&body).unwrap();
            assert_eq!(parsed.downgrade_marker(), expected, "{tail:02x?}");
        }
    }

    #[test]
    fn malformed_known_extension_keeps_other_fields() {
        let extensions: &[(u16, &[u8])] = &[
            (0x002B, &[0x03]),
            (0x0017, &[]),
            (0x0033, &[0x00, 0x1D, 0x00, 0x20, 0xAA]),
            (0xFF01, &[0x00]),
        ];
        let body = hello(0x0303, RANDOM, &[0x09; 4], 0x1301, 0x00, Some(extensions));
        let parsed = ServerHello::parse(&body).unwrap();

        // Остальные поля на месте; версия — из legacy_version.
        assert_eq!(parsed.version(), ProtocolVersion::TLS1_2);
        assert_eq!(parsed.cipher_suite, CipherSuite(0x1301));
        assert_eq!(parsed.session_id, &[0x09; 4][..]);

        let typed: Vec<_> = parsed.extensions().collect();
        assert_eq!(typed.len(), 4);
        assert_eq!(
            typed.first(),
            Some(&ServerExtension::Malformed {
                raw: RawExtension {
                    ext_type: kind::SUPPORTED_VERSIONS,
                    data: &[0x03],
                },
                error: ParseError::UnexpectedEof {
                    position: 0,
                    needed: 2,
                    available: 1,
                },
            })
        );
        assert_eq!(typed.get(1), Some(&ServerExtension::ExtendedMasterSecret));
        assert!(matches!(
            typed.get(2),
            Some(ServerExtension::Malformed {
                error: ParseError::UnexpectedEof { position: 4, .. },
                ..
            })
        ));
        assert_eq!(typed.get(3), Some(&ServerExtension::RenegotiationInfo(&[])));
    }

    #[test]
    fn duplicate_supported_versions_is_ignored_and_reported() {
        // Первое повреждено, второе корректно: не используется ни одно.
        let extensions: &[(u16, &[u8])] = &[(0x002B, &[]), (0x002B, &[0x03, 0x04])];
        let body = hello(0x0303, RANDOM, &[], 0x1301, 0x00, Some(extensions));
        let parsed = ServerHello::parse(&body).unwrap();
        assert_eq!(parsed.version(), ProtocolVersion::TLS1_2);
        assert_eq!(parsed.extension(kind::SUPPORTED_VERSIONS), None);
        assert_eq!(parsed.extensions().count(), 2);
        assert_eq!(
            parsed.anomalies(),
            vec![
                ServerHelloAnomaly::DuplicateExtension(kind::SUPPORTED_VERSIONS),
                ServerHelloAnomaly::MalformedSupportedVersions(ParseError::UnexpectedEof {
                    position: 0,
                    needed: 2,
                    available: 0,
                }),
            ]
        );

        // Два корректных, в любом порядке: тоже legacy_version.
        for extensions in [
            &[(0x002B_u16, &[0x03_u8, 0x04][..]), (0x002B, &[0x03, 0x03])],
            &[(0x002B_u16, &[0x03_u8, 0x03][..]), (0x002B, &[0x03, 0x04])],
        ] {
            let body = hello(0x0303, RANDOM, &[], 0x1301, 0x00, Some(extensions));
            let parsed = ServerHello::parse(&body).unwrap();
            assert_eq!(parsed.version(), ProtocolVersion::TLS1_2);
            assert_eq!(parsed.extension(kind::SUPPORTED_VERSIONS), None);
            assert_eq!(
                parsed.anomalies(),
                vec![
                    ServerHelloAnomaly::DuplicateExtension(kind::SUPPORTED_VERSIONS),
                    ServerHelloAnomaly::SupportedVersionsBelowTls13(ProtocolVersion::TLS1_2),
                ]
            );
        }
    }

    #[test]
    fn supported_versions_below_tls13_is_returned_and_reported() {
        let extensions: &[(u16, &[u8])] = &[(0x002B, &[0x03, 0x02])];
        let body = hello(0x0303, RANDOM, &[], 0xC02F, 0x00, Some(extensions));
        let parsed = ServerHello::parse(&body).unwrap();
        assert_eq!(parsed.version(), ProtocolVersion::TLS1_1);
        assert_eq!(
            parsed.extension(kind::SUPPORTED_VERSIONS),
            Some(ServerExtension::SupportedVersions(ProtocolVersion::TLS1_1))
        );
        assert_eq!(
            parsed.anomalies(),
            vec![ServerHelloAnomaly::SupportedVersionsBelowTls13(
                ProtocolVersion::TLS1_1
            )]
        );
    }

    #[test]
    fn malformed_supported_versions_is_reported() {
        let extensions: &[(u16, &[u8])] = &[(0x002B, &[0x03, 0x04, 0x00])];
        let body = hello(0x0303, RANDOM, &[], 0x1301, 0x00, Some(extensions));
        let parsed = ServerHello::parse(&body).unwrap();
        assert_eq!(parsed.version(), ProtocolVersion::TLS1_2);
        assert_eq!(
            parsed.anomalies(),
            vec![ServerHelloAnomaly::MalformedSupportedVersions(
                ParseError::TrailingBytes {
                    position: 2,
                    remaining: 1,
                }
            )]
        );
    }

    #[test]
    fn duplicate_extensions_are_reported_once_per_type() {
        let extensions: &[(u16, &[u8])] = &[
            (0xFF01, &[0x00]),
            (0x0017, &[]),
            (0x002B, &[0x03, 0x04]),
            (0x0017, &[]),
            (0xFF01, &[0x00]),
            (0x0017, &[]),
        ];
        let body = hello(0x0303, RANDOM, &[], 0x1301, 0x00, Some(extensions));
        let parsed = ServerHello::parse(&body).unwrap();
        assert_eq!(
            parsed.anomalies(),
            vec![
                ServerHelloAnomaly::DuplicateExtension(kind::EXTENDED_MASTER_SECRET),
                ServerHelloAnomaly::DuplicateExtension(kind::RENEGOTIATION_INFO),
            ]
        );
        // Дубликат другого типа на версию не влияет.
        assert_eq!(parsed.version(), ProtocolVersion::TLS1_3);
        assert_eq!(parsed.extension(kind::RENEGOTIATION_INFO), None);
        assert_eq!(parsed.extension(kind::EXTENDED_MASTER_SECRET), None);
        assert_eq!(parsed.extensions().count(), 6);
    }

    #[test]
    fn regular_hellos_have_no_anomalies() {
        let without_block = hello(0x0301, RANDOM, &[], 0x002F, 0x00, None);
        let empty_block = hello(0x0303, RANDOM, &[], 0xC02F, 0x00, Some(&[]));
        let tls12 = hello(
            0x0303,
            RANDOM,
            &[],
            0xC02F,
            0x00,
            Some(&[(0xFF01, &[0x00]), (0x0017, &[])]),
        );
        let tls13 = hello(
            0x0303,
            RANDOM,
            &[],
            0x1301,
            0x00,
            Some(&[(0x002B, &[0x03, 0x04])]),
        );
        for body in [without_block, empty_block, tls12, tls13] {
            assert_eq!(ServerHello::parse(&body).unwrap().anomalies(), Vec::new());
        }
    }

    #[test]
    fn version_agrees_with_extension_lookup() {
        let cases: &[&[(u16, &[u8])]] = &[
            &[],
            &[(0x002B, &[0x03, 0x04])],
            &[(0x002B, &[0x03, 0x02])],
            &[(0x002B, &[0x03])],
            &[(0x002B, &[]), (0x002B, &[0x03, 0x04])],
            &[(0x002B, &[0x03, 0x04]), (0x002B, &[0x03, 0x04])],
            &[(0x002B, &[0x03, 0x04]), (0x0017, &[]), (0x002B, &[0x03])],
        ];
        for extensions in cases {
            let body = hello(0x0303, RANDOM, &[], 0x1301, 0x00, Some(extensions));
            let parsed = ServerHello::parse(&body).unwrap();
            let expected = match parsed.extension(kind::SUPPORTED_VERSIONS) {
                Some(ServerExtension::SupportedVersions(version)) => version,
                _ => parsed.legacy_version,
            };
            assert_eq!(parsed.version(), expected, "{extensions:02x?}");
        }
    }

    #[test]
    fn every_known_extension_has_a_malformed_form() {
        let cases: &[(u16, &[u8])] = &[
            (0x002B, &[0x03, 0x04, 0x00]),
            (0x0033, &[0x00]),
            (0x0033, &[0x00, 0x1D, 0x00, 0x01, 0xAA, 0xBB]),
            (0x0010, &[0x00, 0x06, 0x02, b'h', b'2', 0x02, b'h', b'3']),
            (0x0010, &[0x00, 0x05, 0x02, b'h', b'2']),
            (0x0010, &[0x00, 0x03, 0x05, b'h', b'2']),
            (0x3374, &[0x05, b'h', b'2']),
            (0xFF01, &[0x02, 0xAA]),
            (0xFF01, &[]),
            (0x0023, &[0x00]),
            (0x0005, &[0x01]),
            (0x0017, &[0x00]),
            (0x0016, &[0x00]),
            (0x000F, &[]),
            (0x000F, &[0x01, 0x02]),
            (0x000B, &[0x02, 0x00]),
            (0x0000, &[0x00]),
        ];
        for (ext_type, data) in cases {
            let raw = RawExtension {
                ext_type: ExtensionType(*ext_type),
                data,
            };
            match ServerExtension::parse(raw, false) {
                ServerExtension::Malformed { raw: kept, .. } => assert_eq!(kept, raw),
                other => panic!("тип {ext_type:#06x}: ожидался Malformed, получено {other:?}"),
            }
        }

        // Форма HRR для key_share: ровно два байта.
        let raw = RawExtension {
            ext_type: kind::KEY_SHARE,
            data: &[0x00, 0x1D, 0x00],
        };
        assert!(matches!(
            ServerExtension::parse(raw, true),
            ServerExtension::Malformed {
                error: ParseError::TrailingBytes { .. },
                ..
            }
        ));
    }

    #[test]
    fn empty_npn_list_is_valid() {
        let raw = RawExtension {
            ext_type: kind::NEXT_PROTOCOL_NEGOTIATION,
            data: &[],
        };
        match ServerExtension::parse(raw, false) {
            ServerExtension::NextProtocolNegotiation(names) => {
                assert_eq!(names.iter().count(), 0);
            }
            other => panic!("ожидался NPN, получено {other:?}"),
        }
    }

    #[test]
    fn every_truncation_is_an_error_except_extensionless_form() {
        let extensions: &[(u16, &[u8])] = &[(0x002B, &[0x03, 0x04]), (0xFF01, &[0x00])];
        let body = hello(0x0303, RANDOM, &[0x07; 32], 0x1301, 0x00, Some(extensions));
        let without_extensions = hello(0x0303, RANDOM, &[0x07; 32], 0x1301, 0x00, None);
        for len in 0..body.len() {
            let result = ServerHello::parse(&body[..len]);
            if len == without_extensions.len() {
                assert!(result.is_ok(), "длина {len}");
            } else {
                assert!(
                    matches!(result, Err(ParseError::UnexpectedEof { .. })),
                    "длина {len}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn session_id_longer_than_32_bytes() {
        let body = hello(0x0303, RANDOM, &[0x00; 33], 0xC02F, 0x00, None);
        assert_eq!(
            ServerHello::parse(&body).unwrap_err(),
            ParseError::InvalidValue {
                position: 34,
                what: "session_id длиннее 32 байтов",
            }
        );
    }

    #[test]
    fn trailing_bytes_after_extensions() {
        let mut body = hello(0x0303, RANDOM, &[], 0xC02F, 0x00, Some(&[(0x0017, &[])]));
        let end = body.len();
        body.push(0xFF);
        assert_eq!(
            ServerHello::parse(&body).unwrap_err(),
            ParseError::TrailingBytes {
                position: end,
                remaining: 1,
            }
        );
    }

    #[test]
    fn broken_extension_framing_fails_whole_hello() {
        // Блок из 5 байтов: расширение заявляет 4 байта тела, есть 1.
        let mut body = hello(0x0303, RANDOM, &[], 0xC02F, 0x00, None);
        let block_start = body.len();
        body.extend([0x00, 0x05, 0x00, 0x17, 0x00, 0x04, 0xAA]);
        assert_eq!(
            ServerHello::parse(&body).unwrap_err(),
            ParseError::UnexpectedEof {
                position: block_start + 6,
                needed: 4,
                available: 1,
            }
        );

        // Блок заявляет больше байтов, чем осталось в сообщении.
        let mut body = hello(0x0303, RANDOM, &[], 0xC02F, 0x00, None);
        body.extend([0x00, 0x09, 0x00, 0x17, 0x00, 0x00]);
        assert!(matches!(
            ServerHello::parse(&body),
            Err(ParseError::UnexpectedEof { .. })
        ));
    }
}
