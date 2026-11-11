//! SSLv2: сборка CLIENT-HELLO, разбор SERVER-HELLO и ERROR, отдельный
//! декодер ответа.
//!
//! Формат сверен со спецификацией SSL 2.0 (draft-hickman-netscape-ssl-00,
//! апрель 1995): заголовок записи — раздел 4.1, CLIENT-HELLO — 5.5.1,
//! SERVER-HELLO — 5.6.1, ERROR — 5.7.1, коды — приложение C.
//!
//! # Заголовок записи
//!
//! - Двухбайтовый: старший бит первого байта установлен, длина тела —
//!   15 бит (`((b0 & 0x7f) << 8) | b1`), padding нет.
//! - Трёхбайтовый: старший бит сброшен, длина тела — 14 бит
//!   (`((b0 & 0x3f) << 8) | b1`), бит `0x40` — признак security escape,
//!   третий байт — число байтов padding в конце тела.
//!
//! [`Sslv2RecordHeader::parse`] разбирает оба вида. [`Sslv2Decoder`]
//! принимает только двухбайтовый заголовок: padding появляется лишь у
//! зашифрованных записей с блочным шифром, а до конца открытой части
//! handshake (SERVER-HELLO, ERROR) их не бывает. План (P1-08) разбора
//! трёхбайтового заголовка в декодере не требует.
//!
//! # Связь с основным декодером
//!
//! [`Decoder`](crate::decoder::Decoder) на ответ SSLv2-сервера возвращает
//! [`ParseError::NotTls`], и его поведение не меняется. Вызывающий код,
//! отправивший SSLv2 CLIENT-HELLO, подаёт ответ в [`Sslv2Decoder`]. Если
//! сервер ответил TLS-записью (обычно alert), декодер возвращает
//! [`Sslv2Event::TlsReply`] — это означает «SSLv2 не поддерживается»;
//! забранные к этому моменту байты доступны в событии, и вместе с остатком
//! входа их можно подать в основной декодер.
//!
//! Гарантии те же, что у основного декодера: подача порциями любого
//! размера, проверка длин по [`ParseLimits`] до чтения тела, буфер растёт
//! только на фактически поданные байты (не на заявленную длину), паник нет.
//!
//! Модуль не выполняет I/O, не генерирует случайные числа (challenge
//! передаёт вызывающий код) и не разбирает X.509: сертификат отдаётся
//! срезом DER.

use tls_data::sslv2::Sslv2CipherKind;

use crate::codec::{Reader, Writer};
use crate::error::{EncodeError, NOT_TLS_PREFIX_LEN, ParseError};
use crate::limits::ParseLimits;
use crate::record::ProtocolVersion;

/// Версия SSL 2.0 в полях CLIENT-VERSION и SERVER-VERSION (`0x0002`).
pub const SSL2_VERSION: ProtocolVersion = ProtocolVersion(0x0002);

/// Код сообщения ERROR (`SSL_MT_ERROR`).
pub const MSG_ERROR: u8 = 0;
/// Код сообщения CLIENT-HELLO (`SSL_MT_CLIENT_HELLO`).
pub const MSG_CLIENT_HELLO: u8 = 1;
/// Код сообщения SERVER-HELLO (`SSL_MT_SERVER_HELLO`).
pub const MSG_SERVER_HELLO: u8 = 4;

/// Наибольшая длина тела записи с двухбайтовым заголовком.
pub const MAX_SHORT_RECORD_LEN: usize = 0x7FFF;
/// Наибольшая длина тела записи с трёхбайтовым заголовком.
pub const MAX_LONG_RECORD_LEN: usize = 0x3FFF;

/// Длина одного cipher kind в списке CIPHER-SPECS.
const CIPHER_KIND_LEN: usize = 3;
/// Длина CLIENT-HELLO без данных переменной длины: тип, версия, три длины.
const CLIENT_HELLO_FIXED_LEN: usize = 9;
/// Длина двухбайтового заголовка записи.
const SHORT_HEADER_LEN: usize = 2;
/// Длина трёхбайтового заголовка записи.
const LONG_HEADER_LEN: usize = 3;
/// Признак двухбайтового заголовка в первом байте.
const SHORT_HEADER_FLAG: u8 = 0x80;
/// Признак security escape в первом байте трёхбайтового заголовка.
const ESCAPE_FLAG: u8 = 0x40;
/// Типы содержимого TLS-записи, которые распознаёт основной декодер.
const TLS_CONTENT_TYPES: std::ops::RangeInclusive<u8> = 20..=24;
/// Старший байт версии TLS-записи.
const TLS_MAJOR_VERSION: u8 = 3;

/// Код ошибки в сообщении ERROR (`SSL_PE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sslv2ErrorCode(pub u16);

impl Sslv2ErrorCode {
    /// `SSL_PE_NO_CIPHER` (`0x0001`).
    pub const NO_CIPHER: Self = Self(0x0001);
    /// `SSL_PE_NO_CERTIFICATE` (`0x0002`).
    pub const NO_CERTIFICATE: Self = Self(0x0002);
    /// `SSL_PE_BAD_CERTIFICATE` (`0x0004`).
    pub const BAD_CERTIFICATE: Self = Self(0x0004);
    /// `SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE` (`0x0006`).
    pub const UNSUPPORTED_CERTIFICATE_TYPE: Self = Self(0x0006);

    /// Имя кода по спецификации; `None` для неизвестного значения.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::NO_CIPHER => Some("NO-CIPHER-ERROR"),
            Self::NO_CERTIFICATE => Some("NO-CERTIFICATE-ERROR"),
            Self::BAD_CERTIFICATE => Some("BAD-CERTIFICATE-ERROR"),
            Self::UNSUPPORTED_CERTIFICATE_TYPE => Some("UNSUPPORTED-CERTIFICATE-TYPE-ERROR"),
            _ => None,
        }
    }
}

/// Тип сертификата в SERVER-HELLO (`SSL_CT_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sslv2CertificateType(pub u8);

impl Sslv2CertificateType {
    /// `SSL_CT_X509_CERTIFICATE` (`0x01`).
    pub const X509: Self = Self(0x01);
}

/// Заголовок записи SSLv2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sslv2RecordHeader {
    /// Длина тела записи, считая padding.
    pub body_len: usize,
    /// Число байтов padding в конце тела; 0 у двухбайтового заголовка.
    pub padding: u8,
    /// Признак security escape; `false` у двухбайтового заголовка.
    pub is_escape: bool,
    /// Длина самого заголовка: 2 или 3.
    pub header_len: usize,
}

impl Sslv2RecordHeader {
    /// Читает двух- или трёхбайтовый заголовок записи. При ошибке позиция
    /// читателя не меняется.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если заголовок оборван.
    pub fn parse(reader: &mut Reader<'_>) -> Result<Self, ParseError> {
        let mut probe = reader.clone();
        let first = probe.u8()?;
        let second = probe.u8()?;
        let header = if first & SHORT_HEADER_FLAG == 0 {
            let padding = probe.u8()?;
            Self {
                body_len: usize::from(u16::from_be_bytes([
                    first & !(SHORT_HEADER_FLAG | ESCAPE_FLAG),
                    second,
                ])),
                padding,
                is_escape: first & ESCAPE_FLAG != 0,
                header_len: LONG_HEADER_LEN,
            }
        } else {
            Self {
                body_len: short_body_len(first, second),
                padding: 0,
                is_escape: false,
                header_len: SHORT_HEADER_LEN,
            }
        };
        *reader = probe;
        Ok(header)
    }
}

/// Длина тела по двухбайтовому заголовку.
fn short_body_len(first: u8, second: u8) -> usize {
    usize::from(u16::from_be_bytes([first & !SHORT_HEADER_FLAG, second]))
}

/// Итератор по трёхбайтовым cipher kinds списка CIPHER-SPECS. Неполный
/// хвост (длина не кратна трём) в итератор не попадает; парсеры этого
/// модуля такой список отвергают.
fn cipher_kinds_of(specs: &[u8]) -> impl Iterator<Item = Sslv2CipherKind> + '_ {
    specs
        .chunks_exact(CIPHER_KIND_LEN)
        .filter_map(|chunk| <[u8; CIPHER_KIND_LEN]>::try_from(chunk).ok())
        .map(Sslv2CipherKind::from_bytes)
}

/// Проверяет, что длина списка CIPHER-SPECS кратна трём.
fn check_cipher_specs(specs: &[u8], position: usize) -> Result<(), ParseError> {
    if specs.len().is_multiple_of(CIPHER_KIND_LEN) {
        Ok(())
    } else {
        Err(ParseError::InvalidValue {
            position,
            what: "длина CIPHER-SPECS в SSLv2 hello не кратна 3",
        })
    }
}

/// SSLv2 CLIENT-HELLO для сборки.
///
/// Ограничения спецификации (непустой список шифров, session id длиной 0
/// или 16, challenge от 16 до 32 байтов) при сборке не проверяются:
/// пробнику нужна возможность отправить и нестандартный hello. Проверяется
/// только то, что сообщение помещается в запись с двухбайтовым заголовком.
/// Challenge передаёт вызывающий код: случайные числа здесь не
/// генерируются.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sslv2ClientHello<'a> {
    /// CLIENT-VERSION; для SSL 2.0 — [`SSL2_VERSION`].
    pub version: ProtocolVersion,
    /// Список cipher kinds; записываются три младших байта каждого кода.
    pub cipher_kinds: &'a [Sslv2CipherKind],
    /// SESSION-ID; пустой, если сессии нет.
    pub session_id: &'a [u8],
    /// CHALLENGE.
    pub challenge: &'a [u8],
}

impl Sslv2ClientHello<'_> {
    /// Пишет запись с двухбайтовым заголовком и сообщением CLIENT-HELLO.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если сообщение длиннее 32767 байтов;
    /// буфер при этом не меняется.
    pub fn encode(&self, writer: &mut Writer) -> Result<(), EncodeError> {
        let specs_len = self.cipher_kinds.len().saturating_mul(CIPHER_KIND_LEN);
        let body_len = CLIENT_HELLO_FIXED_LEN
            .saturating_add(specs_len)
            .saturating_add(self.session_id.len())
            .saturating_add(self.challenge.len());

        let record_len = record_len_field(body_len, body_len)?;
        let specs_len = record_len_field(specs_len, body_len)?;
        let session_id_len = record_len_field(self.session_id.len(), body_len)?;
        let challenge_len = record_len_field(self.challenge.len(), body_len)?;

        let [length_high, length_low] = record_len.to_be_bytes();
        writer.put_u8(length_high | SHORT_HEADER_FLAG);
        writer.put_u8(length_low);
        writer.put_u8(MSG_CLIENT_HELLO);
        writer.put_u16(self.version.0);
        writer.put_u16(specs_len);
        writer.put_u16(session_id_len);
        writer.put_u16(challenge_len);
        for kind in self.cipher_kinds {
            writer.put_slice(&kind.to_bytes());
        }
        writer.put_slice(self.session_id);
        writer.put_slice(self.challenge);
        Ok(())
    }
}

/// Длина поля как `u16`; ошибка, если всё сообщение (`body_len`) не
/// помещается в запись с двухбайтовым заголовком.
fn record_len_field(len: usize, body_len: usize) -> Result<u16, EncodeError> {
    let overflow = EncodeError::LengthOverflow {
        prefix_bytes: SHORT_HEADER_LEN,
        max: 0x7FFF,
        actual: body_len,
    };
    if body_len > MAX_SHORT_RECORD_LEN {
        return Err(overflow);
    }
    u16::try_from(len).map_err(|_| overflow)
}

/// Разобранный SSLv2 CLIENT-HELLO: нужен для проверки собранных сообщений
/// (тесты, фаззинг пары «билдер — парсер»).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sslv2ClientHelloView<'a> {
    /// CLIENT-VERSION.
    pub version: ProtocolVersion,
    /// CIPHER-SPECS-DATA; длина кратна трём.
    pub cipher_specs: &'a [u8],
    /// SESSION-ID-DATA.
    pub session_id: &'a [u8],
    /// CHALLENGE-DATA.
    pub challenge: &'a [u8],
}

impl<'a> Sslv2ClientHelloView<'a> {
    /// Разбирает сообщение CLIENT-HELLO (тело записи, начиная с байта типа).
    ///
    /// # Errors
    ///
    /// - [`ParseError::UnexpectedEof`], если сообщение оборвано;
    /// - [`ParseError::InvalidValue`], если тип сообщения — не CLIENT-HELLO
    ///   или длина CIPHER-SPECS не кратна трём;
    /// - [`ParseError::TrailingBytes`], если после challenge остались байты.
    pub fn parse(message: &'a [u8]) -> Result<Self, ParseError> {
        Self::read(Reader::new(message))
    }

    /// Разбирает запись целиком: заголовок и сообщение CLIENT-HELLO.
    ///
    /// # Errors
    ///
    /// Ошибки [`Sslv2ClientHelloView::parse`], а также
    /// [`ParseError::InvalidValue`] для записи с padding или security
    /// escape и [`ParseError::TrailingBytes`] для байтов после записи.
    pub fn parse_record(record: &'a [u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(record);
        let position = reader.position();
        let header = Sslv2RecordHeader::parse(&mut reader)?;
        if header.is_escape || header.padding != 0 {
            return Err(ParseError::InvalidValue {
                position,
                what: "запись SSLv2 с padding или security escape в открытой части handshake",
            });
        }
        let body = reader.sub(header.body_len)?;
        reader.finish()?;
        Self::read(body)
    }

    /// Итератор по cipher kinds.
    pub fn cipher_kinds(&self) -> impl Iterator<Item = Sslv2CipherKind> + 'a {
        cipher_kinds_of(self.cipher_specs)
    }

    fn read(mut reader: Reader<'a>) -> Result<Self, ParseError> {
        let position = reader.position();
        if reader.u8()? != MSG_CLIENT_HELLO {
            return Err(ParseError::InvalidValue {
                position,
                what: "тип сообщения SSLv2 — не CLIENT-HELLO",
            });
        }
        let version = ProtocolVersion(reader.u16()?);
        let specs_position = reader.position();
        let specs_len = usize::from(reader.u16()?);
        let session_id_len = usize::from(reader.u16()?);
        let challenge_len = usize::from(reader.u16()?);
        let cipher_specs = reader.take(specs_len)?;
        let session_id = reader.take(session_id_len)?;
        let challenge = reader.take(challenge_len)?;
        reader.finish()?;
        check_cipher_specs(cipher_specs, specs_position)?;
        Ok(Self {
            version,
            cipher_specs,
            session_id,
            challenge,
        })
    }
}

/// SSLv2 SERVER-HELLO.
///
/// Требования спецификации к значениям (CONNECTION-ID от 16 до 32 байтов,
/// нулевые поля сертификата и шифров при SESSION-ID-HIT) не проверяются:
/// отклонения — предмет анализа вызывающего кода, а не ошибка разбора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sslv2ServerHello<'a> {
    /// SESSION-ID-HIT: истина, если байт ненулевой.
    pub session_id_hit: bool,
    /// CERTIFICATE-TYPE; 0 при SESSION-ID-HIT.
    pub certificate_type: Sslv2CertificateType,
    /// SERVER-VERSION.
    pub version: ProtocolVersion,
    /// CERTIFICATE-DATA: сертификат в DER без разбора; может быть пустым.
    pub certificate: &'a [u8],
    /// CIPHER-SPECS-DATA; длина кратна трём.
    pub cipher_specs: &'a [u8],
    /// CONNECTION-ID-DATA.
    pub connection_id: &'a [u8],
}

impl<'a> Sslv2ServerHello<'a> {
    /// Разбирает сообщение SERVER-HELLO (тело записи, начиная с байта типа).
    ///
    /// # Errors
    ///
    /// - [`ParseError::UnexpectedEof`], если сообщение оборвано или длина
    ///   поля больше остатка;
    /// - [`ParseError::InvalidValue`], если тип сообщения — не SERVER-HELLO
    ///   или длина CIPHER-SPECS не кратна трём;
    /// - [`ParseError::LimitExceeded`], если сертификат длиннее
    ///   `max_certificate_len`;
    /// - [`ParseError::TrailingBytes`], если после CONNECTION-ID остались
    ///   байты.
    pub fn parse(message: &'a [u8], limits: &ParseLimits) -> Result<Self, ParseError> {
        let mut reader = Reader::new(message);
        let position = reader.position();
        if reader.u8()? != MSG_SERVER_HELLO {
            return Err(ParseError::InvalidValue {
                position,
                what: "тип сообщения SSLv2 — не SERVER-HELLO",
            });
        }
        let session_id_hit = reader.u8()? != 0;
        let certificate_type = Sslv2CertificateType(reader.u8()?);
        let version = ProtocolVersion(reader.u16()?);
        let certificate_position = reader.position();
        let certificate_len = usize::from(reader.u16()?);
        limits.check_certificate_len(certificate_len, certificate_position)?;
        let specs_position = reader.position();
        let specs_len = usize::from(reader.u16()?);
        let connection_id_len = usize::from(reader.u16()?);
        let certificate = reader.take(certificate_len)?;
        let cipher_specs = reader.take(specs_len)?;
        let connection_id = reader.take(connection_id_len)?;
        reader.finish()?;
        check_cipher_specs(cipher_specs, specs_position)?;
        Ok(Self {
            session_id_hit,
            certificate_type,
            version,
            certificate,
            cipher_specs,
            connection_id,
        })
    }

    /// Итератор по cipher kinds, которые перечислил сервер.
    pub fn cipher_kinds(&self) -> impl Iterator<Item = Sslv2CipherKind> + 'a {
        cipher_kinds_of(self.cipher_specs)
    }
}

/// Событие декодера SSLv2-ответа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sslv2Event<'a> {
    /// Данных недостаточно, вход забран полностью.
    NeedMore,
    /// Сообщение SERVER-HELLO.
    ServerHello(Sslv2ServerHello<'a>),
    /// Сообщение ERROR.
    Error(Sslv2ErrorCode),
    /// Запись SSLv2 с другим типом сообщения; тело — без байта типа.
    Other {
        /// Код типа сообщения.
        msg_type: u8,
        /// Остаток записи после байта типа.
        body: &'a [u8],
    },
    /// Ответ начинается с TLS-записи: сервер SSLv2 не поддерживает.
    /// `prefix` — байты, которые декодер успел забрать из входа; вместе с
    /// остатком входа их можно подать в
    /// [`Decoder`](crate::decoder::Decoder).
    TlsReply {
        /// Забранное начало TLS-потока (два байта).
        prefix: &'a [u8],
    },
}

/// Разбирает одно сообщение SSLv2 (тело записи, начиная с байта типа).
///
/// # Errors
///
/// Ошибки [`Sslv2ServerHello::parse`] для SERVER-HELLO;
/// [`ParseError::UnexpectedEof`] и [`ParseError::TrailingBytes`] для ERROR
/// неверной длины; [`ParseError::UnexpectedEof`] для пустого сообщения.
pub fn parse_message<'a>(
    message: &'a [u8],
    limits: &ParseLimits,
) -> Result<Sslv2Event<'a>, ParseError> {
    let mut reader = Reader::new(message);
    match reader.u8()? {
        MSG_SERVER_HELLO => Sslv2ServerHello::parse(message, limits).map(Sslv2Event::ServerHello),
        MSG_ERROR => {
            let code = Sslv2ErrorCode(reader.u16()?);
            reader.finish()?;
            Ok(Sslv2Event::Error(code))
        }
        msg_type => Ok(Sslv2Event::Other {
            msg_type,
            body: reader.rest(),
        }),
    }
}

/// Итог продвижения декодера без заимствования буфера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    NeedMore,
    Record,
    Tls,
}

/// Инкрементальный декодер ответа на SSLv2 CLIENT-HELLO.
///
/// Каждое событие, кроме [`Sslv2Event::NeedMore`], соответствует одной
/// записи. Ошибка окончательна: повторный вызов возвращает её же и вход не
/// забирает. [`Sslv2Event::TlsReply`] тоже окончателен: повторный вызов
/// возвращает то же событие и вход не забирает.
#[derive(Debug, Clone)]
pub struct Sslv2Decoder {
    limits: ParseLimits,
    /// Байты текущей записи, включая заголовок.
    buf: Vec<u8>,
    /// Смещение начала `buf` в потоке.
    offset: usize,
    /// Запись из `buf` уже выдана событием и будет сброшена следующим
    /// вызовом.
    delivered: bool,
    /// Поток распознан как TLS.
    tls: bool,
    /// Окончательная ошибка.
    failed: Option<ParseError>,
}

impl Default for Sslv2Decoder {
    fn default() -> Self {
        Self::new(ParseLimits::default())
    }
}

impl Sslv2Decoder {
    /// Декодер с заданными лимитами. Используются `max_record_len`,
    /// `max_total_bytes` и `max_certificate_len`.
    #[must_use]
    pub fn new(limits: ParseLimits) -> Self {
        Self {
            limits,
            buf: Vec::new(),
            offset: 0,
            delivered: false,
            tls: false,
            failed: None,
        }
    }

    /// Забирает из `input` столько байтов, сколько нужно до конца текущей
    /// записи, и возвращает событие. `input` сдвигается на забранные байты.
    ///
    /// # Errors
    ///
    /// - [`ParseError::NotTls`] — начало ответа не похоже ни на запись
    ///   SSLv2 с двухбайтовым заголовком, ни на TLS-запись;
    /// - [`ParseError::InvalidValue`] — запись нулевой длины или
    ///   недопустимое значение в сообщении;
    /// - [`ParseError::LimitExceeded`] — превышен `max_record_len`,
    ///   `max_total_bytes` или `max_certificate_len`;
    /// - [`ParseError::UnexpectedEof`], [`ParseError::TrailingBytes`] —
    ///   длины полей сообщения не согласуются с длиной записи.
    pub fn feed(&mut self, input: &mut &[u8]) -> Result<Sslv2Event<'_>, ParseError> {
        match self.advance(input)? {
            Step::NeedMore => Ok(Sslv2Event::NeedMore),
            Step::Tls => Ok(Sslv2Event::TlsReply { prefix: &self.buf }),
            Step::Record => {
                let base = self.offset.saturating_add(SHORT_HEADER_LEN);
                let message = self
                    .buf
                    .get(SHORT_HEADER_LEN..)
                    .ok_or(ParseError::Internal {
                        position: self.offset,
                        what: "запись SSLv2 в буфере короче заголовка",
                    })?;
                // Сообщение уже проверено в `advance`, ошибки здесь не будет.
                parse_message(message, &self.limits).map_err(|error| error.offset_by(base))
            }
        }
    }

    /// Продвигает состояние и запоминает ошибку. Результат не заимствует
    /// буфер, поэтому событие строится отдельно, в `feed`.
    fn advance(&mut self, input: &mut &[u8]) -> Result<Step, ParseError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.tls {
            return Ok(Step::Tls);
        }
        let result = self.advance_record(input);
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }

    fn advance_record(&mut self, input: &mut &[u8]) -> Result<Step, ParseError> {
        if self.delivered {
            self.offset = self.offset.saturating_add(self.buf.len());
            self.buf.clear();
            self.delivered = false;
        }

        self.fill(input, SHORT_HEADER_LEN);
        let (first, second) = match self.buf.as_slice() {
            [first, second, ..] => (*first, *second),
            _ => return Ok(Step::NeedMore),
        };

        if first & SHORT_HEADER_FLAG == 0 {
            if TLS_CONTENT_TYPES.contains(&first) && second == TLS_MAJOR_VERSION {
                self.tls = true;
                return Ok(Step::Tls);
            }
            self.fill(input, NOT_TLS_PREFIX_LEN);
            return Err(not_tls(self.offset, &self.buf));
        }

        let body_len = short_body_len(first, second);
        if body_len == 0 {
            return Err(ParseError::InvalidValue {
                position: self.offset,
                what: "запись SSLv2 нулевой длины",
            });
        }
        self.limits.check_record_len(body_len, self.offset)?;
        let record_len = SHORT_HEADER_LEN.saturating_add(body_len);
        self.limits
            .check_total_bytes(self.offset.saturating_add(record_len), self.offset)?;

        self.fill(input, record_len);
        if self.buf.len() < record_len {
            return Ok(Step::NeedMore);
        }

        let base = self.offset.saturating_add(SHORT_HEADER_LEN);
        let message = self
            .buf
            .get(SHORT_HEADER_LEN..)
            .ok_or(ParseError::Internal {
                position: self.offset,
                what: "запись SSLv2 в буфере короче заголовка",
            })?;
        parse_message(message, &self.limits).map_err(|error| error.offset_by(base))?;
        self.delivered = true;
        Ok(Step::Record)
    }

    /// Дополняет буфер из входа до `target` байтов, если вход позволяет.
    fn fill(&mut self, input: &mut &[u8], target: usize) {
        let missing = target.saturating_sub(self.buf.len());
        let count = missing.min(input.len());
        if let Some((head, tail)) = input.split_at_checked(count) {
            self.buf.extend_from_slice(head);
            *input = tail;
        }
    }
}

/// Ошибка [`ParseError::NotTls`] с первыми байтами `data`.
fn not_tls(position: usize, data: &[u8]) -> ParseError {
    let mut prefix = [0_u8; NOT_TLS_PREFIX_LEN];
    let mut prefix_len = 0_usize;
    for (slot, byte) in prefix.iter_mut().zip(data) {
        *slot = *byte;
        prefix_len = prefix_len.saturating_add(1);
    }
    ParseError::NotTls {
        position,
        prefix,
        prefix_len,
    }
}

#[cfg(test)]
mod tests {
    //! Синтетические тесты: все байты составлены вручную по
    //! draft-hickman-netscape-ssl-00, это НЕ записи реальных серверов.
    //! Стенд на OpenSSL 4.1.0 SSLv2 не поддерживает, записанных фикстур нет.
    //! «Сертификат» в SERVER-HELLO — произвольные байты, не X.509.

    use super::*;

    const CHALLENGE: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    const CONNECTION_ID: [u8; 16] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF,
    ];

    /// SERVER-HELLO без заголовка записи: 11 + 4 + 6 + 16 = 37 байтов.
    fn server_hello_message() -> Vec<u8> {
        let mut message = vec![
            0x04, // MSG-SERVER-HELLO
            0x00, // SESSION-ID-HIT
            0x01, // CERTIFICATE-TYPE = SSL_CT_X509_CERTIFICATE
            0x00, 0x02, // SERVER-VERSION
            0x00, 0x04, // CERTIFICATE-LENGTH
            0x00, 0x06, // CIPHER-SPECS-LENGTH
            0x00, 0x10, // CONNECTION-ID-LENGTH
            0x30, 0x02, 0x05, 0x00, // CERTIFICATE-DATA (произвольные байты)
            0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
            0x07, 0x00, 0xC0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        ];
        message.extend_from_slice(&CONNECTION_ID);
        message
    }

    /// Запись с двухбайтовым заголовком вокруг сообщения.
    fn record(message: &[u8]) -> Vec<u8> {
        let len = u16::try_from(message.len()).unwrap();
        assert!(len <= 0x7FFF);
        let mut bytes = (len | 0x8000).to_be_bytes().to_vec();
        bytes.extend_from_slice(message);
        bytes
    }

    fn expected_server_hello(message: &[u8]) -> Sslv2ServerHello<'_> {
        Sslv2ServerHello {
            session_id_hit: false,
            certificate_type: Sslv2CertificateType::X509,
            version: SSL2_VERSION,
            certificate: &message[11..15],
            cipher_specs: &message[15..21],
            connection_id: &message[21..37],
        }
    }

    #[test]
    fn client_hello_matches_bytes_written_by_hand() {
        // Ожидаемые байты выписаны по разделам 4.1 и 5.5.1 спецификации,
        // а не получены обратным разбором.
        let expected: [u8; 33] = [
            0x80,
            0x1F, // заголовок: старший бит, длина тела 31 = 9 + 6 + 0 + 16
            0x01, // MSG-CLIENT-HELLO
            0x00, 0x02, // CLIENT-VERSION = 0x0002
            0x00, 0x06, // CIPHER-SPECS-LENGTH = 2 × 3
            0x00, 0x00, // SESSION-ID-LENGTH = 0
            0x00, 0x10, // CHALLENGE-LENGTH = 16
            0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
            0x07, 0x00, 0xC0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
            // CHALLENGE-DATA
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let kinds = [Sslv2CipherKind(0x01_0080), Sslv2CipherKind(0x07_00C0)];
        let hello = Sslv2ClientHello {
            version: SSL2_VERSION,
            cipher_kinds: &kinds,
            session_id: &[],
            challenge: &CHALLENGE,
        };
        let mut writer = Writer::new();
        assert_eq!(hello.encode(&mut writer), Ok(()));
        assert_eq!(writer.as_slice(), &expected[..]);
    }

    #[test]
    fn client_hello_with_session_id_parses_back() {
        let session_id = [0xB7_u8; 16];
        let kinds = [Sslv2CipherKind(0x06_0040)];
        let hello = Sslv2ClientHello {
            version: SSL2_VERSION,
            cipher_kinds: &kinds,
            session_id: &session_id,
            challenge: &CHALLENGE,
        };
        let mut writer = Writer::new();
        writer.put_u8(0xEE);
        assert_eq!(hello.encode(&mut writer), Ok(()));
        let bytes = writer.as_slice();
        // 9 + 3 + 16 + 16 = 44 = 0x2C.
        assert_eq!(&bytes[..3], &[0xEE, 0x80, 0x2C][..]);
        assert_eq!(bytes.len(), 1 + 2 + 44);

        let view = Sslv2ClientHelloView::parse_record(&bytes[1..]).unwrap();
        assert_eq!(view.version, SSL2_VERSION);
        assert_eq!(view.cipher_specs, &[0x06, 0x00, 0x40][..]);
        assert_eq!(view.cipher_kinds().collect::<Vec<_>>(), kinds.to_vec());
        assert_eq!(view.session_id, &session_id[..]);
        assert_eq!(view.challenge, &CHALLENGE[..]);

        assert_eq!(Sslv2ClientHelloView::parse(&bytes[3..]), Ok(view));
    }

    #[test]
    fn client_hello_too_long_leaves_buffer_untouched() {
        // 10 920 × 3 + 9 = 32 769 > 32 767.
        let kinds = vec![Sslv2CipherKind(0x01_0080); 10_920];
        let hello = Sslv2ClientHello {
            version: SSL2_VERSION,
            cipher_kinds: &kinds,
            session_id: &[],
            challenge: &[],
        };
        let mut writer = Writer::new();
        writer.put_u8(0x55);
        assert_eq!(
            hello.encode(&mut writer),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                max: 0x7FFF,
                actual: 32_769,
            })
        );
        assert_eq!(writer.as_slice(), &[0x55_u8][..]);

        // 10 919 × 3 + 9 = 32 766 = 0x7FFE: помещается.
        let hello = Sslv2ClientHello {
            cipher_kinds: &kinds[..10_919],
            ..hello
        };
        let mut writer = Writer::new();
        assert_eq!(hello.encode(&mut writer), Ok(()));
        assert_eq!(&writer.as_slice()[..2], &[0xFF, 0xFE][..]);
        assert_eq!(writer.len(), 2 + 32_766);
    }

    #[test]
    fn client_hello_view_rejects_malformed_input() {
        let kinds = [Sslv2CipherKind(0x01_0080)];
        let hello = Sslv2ClientHello {
            version: SSL2_VERSION,
            cipher_kinds: &kinds,
            session_id: &[],
            challenge: &CHALLENGE,
        };
        let mut writer = Writer::new();
        hello.encode(&mut writer).unwrap();
        let bytes = writer.as_slice().to_vec();
        let message = &bytes[2..];

        for cut in 0..message.len() {
            assert!(
                matches!(
                    Sslv2ClientHelloView::parse(&message[..cut]),
                    Err(ParseError::UnexpectedEof { .. })
                ),
                "обрыв на {cut}"
            );
        }

        let mut trailing = message.to_vec();
        trailing.push(0x00);
        assert_eq!(
            Sslv2ClientHelloView::parse(&trailing),
            Err(ParseError::TrailingBytes {
                position: message.len(),
                remaining: 1,
            })
        );

        let mut wrong_type = message.to_vec();
        *wrong_type.first_mut().unwrap() = MSG_SERVER_HELLO;
        assert!(matches!(
            Sslv2ClientHelloView::parse(&wrong_type),
            Err(ParseError::InvalidValue { position: 0, .. })
        ));

        // CIPHER-SPECS-LENGTH = 2, CHALLENGE-LENGTH = 1: длины сходятся,
        // но список не кратен трём.
        let odd = [
            0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x80,
        ];
        assert!(matches!(
            Sslv2ClientHelloView::parse(&odd),
            Err(ParseError::InvalidValue { position: 3, .. })
        ));

        // Трёхбайтовый заголовок с padding для CLIENT-HELLO не принимается.
        let mut padded = vec![0x00, 0x1C, 0x01];
        padded.extend_from_slice(message);
        assert!(matches!(
            Sslv2ClientHelloView::parse_record(&padded),
            Err(ParseError::InvalidValue { position: 0, .. })
        ));

        // Байт после записи.
        let mut after = bytes.clone();
        after.push(0xFF);
        assert!(matches!(
            Sslv2ClientHelloView::parse_record(&after),
            Err(ParseError::TrailingBytes { remaining: 1, .. })
        ));
    }

    #[test]
    fn record_header_two_and_three_bytes() {
        let mut reader = Reader::new(&[0x80, 0x1F, 0xAA]);
        assert_eq!(
            Sslv2RecordHeader::parse(&mut reader),
            Ok(Sslv2RecordHeader {
                body_len: 31,
                padding: 0,
                is_escape: false,
                header_len: 2,
            })
        );
        assert_eq!(reader.position(), 2);

        let mut reader = Reader::new(&[0xFF, 0xFF]);
        assert_eq!(
            Sslv2RecordHeader::parse(&mut reader).map(|header| header.body_len),
            Ok(MAX_SHORT_RECORD_LEN)
        );

        let mut reader = Reader::new(&[0x01, 0x00, 0x08]);
        assert_eq!(
            Sslv2RecordHeader::parse(&mut reader),
            Ok(Sslv2RecordHeader {
                body_len: 256,
                padding: 8,
                is_escape: false,
                header_len: 3,
            })
        );
        assert_eq!(reader.position(), 3);

        let mut reader = Reader::new(&[0x41, 0x00, 0x00]);
        assert_eq!(
            Sslv2RecordHeader::parse(&mut reader),
            Ok(Sslv2RecordHeader {
                body_len: 256,
                padding: 0,
                is_escape: true,
                header_len: 3,
            })
        );

        let mut reader = Reader::new(&[0x3F, 0xFF, 0x00]);
        assert_eq!(
            Sslv2RecordHeader::parse(&mut reader).map(|header| header.body_len),
            Ok(MAX_LONG_RECORD_LEN)
        );
    }

    #[test]
    fn record_header_truncated_keeps_position() {
        for data in [&[][..], &[0x80][..], &[0x01][..], &[0x01, 0x00][..]] {
            let mut reader = Reader::new(data);
            assert!(
                matches!(
                    Sslv2RecordHeader::parse(&mut reader),
                    Err(ParseError::UnexpectedEof { .. })
                ),
                "{data:02x?}"
            );
            assert_eq!(reader.position(), 0);
        }
    }

    #[test]
    fn server_hello_fields() {
        let message = server_hello_message();
        assert_eq!(message.len(), 37);
        let hello = Sslv2ServerHello::parse(&message, &ParseLimits::default()).unwrap();
        assert_eq!(hello, expected_server_hello(&message));
        assert_eq!(hello.certificate, &[0x30, 0x02, 0x05, 0x00][..]);
        assert_eq!(hello.connection_id, &CONNECTION_ID[..]);
        assert_eq!(
            hello.cipher_kinds().collect::<Vec<_>>(),
            vec![Sslv2CipherKind(0x01_0080), Sslv2CipherKind(0x07_00C0)]
        );
    }

    #[test]
    fn server_hello_session_id_hit_has_empty_certificate_and_ciphers() {
        let mut message = vec![
            0x04, // MSG-SERVER-HELLO
            0x01, // SESSION-ID-HIT
            0x00, // CERTIFICATE-TYPE
            0x00, 0x02, // SERVER-VERSION
            0x00, 0x00, // CERTIFICATE-LENGTH
            0x00, 0x00, // CIPHER-SPECS-LENGTH
            0x00, 0x10, // CONNECTION-ID-LENGTH
        ];
        message.extend_from_slice(&CONNECTION_ID);
        let hello = Sslv2ServerHello::parse(&message, &ParseLimits::default()).unwrap();
        assert!(hello.session_id_hit);
        assert_eq!(hello.certificate_type, Sslv2CertificateType(0));
        assert!(hello.certificate.is_empty());
        assert_eq!(hello.cipher_kinds().count(), 0);
        assert_eq!(hello.connection_id, &CONNECTION_ID[..]);
    }

    #[test]
    fn server_hello_truncated_at_every_offset() {
        let message = server_hello_message();
        for cut in 0..message.len() {
            assert!(
                matches!(
                    Sslv2ServerHello::parse(&message[..cut], &ParseLimits::default()),
                    Err(ParseError::UnexpectedEof { .. })
                ),
                "обрыв на {cut}"
            );
        }
    }

    #[test]
    fn server_hello_malformed() {
        let limits = ParseLimits::default();
        let message = server_hello_message();

        let mut trailing = message.clone();
        trailing.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            Sslv2ServerHello::parse(&trailing, &limits),
            Err(ParseError::TrailingBytes {
                position: 37,
                remaining: 2,
            })
        );

        let mut wrong_type = message.clone();
        *wrong_type.first_mut().unwrap() = MSG_CLIENT_HELLO;
        assert!(matches!(
            Sslv2ServerHello::parse(&wrong_type, &limits),
            Err(ParseError::InvalidValue { position: 0, .. })
        ));

        // Длина списка шифров больше остатка.
        let mut long_list = message.clone();
        *long_list.get_mut(7).unwrap() = 0x7F;
        assert!(matches!(
            Sslv2ServerHello::parse(&long_list, &limits),
            Err(ParseError::UnexpectedEof { .. })
        ));

        // CIPHER-SPECS-LENGTH = 5, CONNECTION-ID-LENGTH = 17: сумма та же,
        // но список не кратен трём.
        let mut odd = message.clone();
        *odd.get_mut(8).unwrap() = 0x05;
        *odd.get_mut(10).unwrap() = 0x11;
        assert!(matches!(
            Sslv2ServerHello::parse(&odd, &limits),
            Err(ParseError::InvalidValue { position: 7, .. })
        ));
    }

    #[test]
    fn server_hello_certificate_limit() {
        let limits = ParseLimits {
            max_certificate_len: 3,
            ..ParseLimits::default()
        };
        assert_eq!(
            Sslv2ServerHello::parse(&server_hello_message(), &limits),
            Err(ParseError::LimitExceeded {
                position: 5,
                limit: "max_certificate_len",
                max: 3,
                actual: 4,
            })
        );

        // Лимит срабатывает по заявленной длине, до чтения тела.
        let hostile = [0x04, 0x00, 0x01, 0x00, 0x02, 0xFF, 0xFF];
        assert!(matches!(
            Sslv2ServerHello::parse(&hostile, &ParseLimits::default()),
            Err(ParseError::LimitExceeded {
                limit: "max_certificate_len",
                actual: 0xFFFF,
                ..
            })
        ));
    }

    #[test]
    fn error_message() {
        let limits = ParseLimits::default();
        // MSG-ERROR, ERROR-CODE = SSL_PE_NO_CIPHER.
        assert_eq!(
            parse_message(&[0x00, 0x00, 0x01], &limits),
            Ok(Sslv2Event::Error(Sslv2ErrorCode::NO_CIPHER))
        );
        assert_eq!(
            parse_message(&[0x00, 0x12, 0x34], &limits),
            Ok(Sslv2Event::Error(Sslv2ErrorCode(0x1234)))
        );
        assert!(matches!(
            parse_message(&[0x00, 0x00], &limits),
            Err(ParseError::UnexpectedEof { position: 1, .. })
        ));
        assert_eq!(
            parse_message(&[0x00, 0x00, 0x01, 0xFF], &limits),
            Err(ParseError::TrailingBytes {
                position: 3,
                remaining: 1,
            })
        );
        assert!(matches!(
            parse_message(&[], &limits),
            Err(ParseError::UnexpectedEof { position: 0, .. })
        ));
    }

    #[test]
    fn error_code_names() {
        assert_eq!(Sslv2ErrorCode::NO_CIPHER.name(), Some("NO-CIPHER-ERROR"));
        assert_eq!(
            Sslv2ErrorCode::NO_CERTIFICATE.name(),
            Some("NO-CERTIFICATE-ERROR")
        );
        assert_eq!(
            Sslv2ErrorCode::BAD_CERTIFICATE.name(),
            Some("BAD-CERTIFICATE-ERROR")
        );
        assert_eq!(
            Sslv2ErrorCode::UNSUPPORTED_CERTIFICATE_TYPE.name(),
            Some("UNSUPPORTED-CERTIFICATE-TYPE-ERROR")
        );
        assert_eq!(Sslv2ErrorCode(0x0003).name(), None);
    }

    #[test]
    fn other_message_type_is_returned_as_body() {
        // MSG-SERVER-VERIFY (5) с произвольным телом.
        assert_eq!(
            parse_message(&[0x05, 0xDE, 0xAD], &ParseLimits::default()),
            Ok(Sslv2Event::Other {
                msg_type: 5,
                body: &[0xDE, 0xAD],
            })
        );
    }

    #[test]
    fn decoder_whole_server_hello() {
        let message = server_hello_message();
        let bytes = record(&message);
        assert_eq!(&bytes[..2], &[0x80, 0x25][..]);

        let mut decoder = Sslv2Decoder::default();
        let mut input = &bytes[..];
        assert_eq!(
            decoder.feed(&mut input),
            Ok(Sslv2Event::ServerHello(expected_server_hello(&message)))
        );
        assert!(input.is_empty());
        assert_eq!(decoder.feed(&mut input), Ok(Sslv2Event::NeedMore));
    }

    #[test]
    fn decoder_byte_by_byte() {
        let message = server_hello_message();
        let bytes = record(&message);
        let mut decoder = Sslv2Decoder::default();
        let (last, head) = bytes.split_last().unwrap();
        for byte in head {
            let mut chunk = std::slice::from_ref(byte);
            assert_eq!(decoder.feed(&mut chunk), Ok(Sslv2Event::NeedMore));
            assert!(chunk.is_empty());
        }
        let mut chunk = std::slice::from_ref(last);
        assert_eq!(
            decoder.feed(&mut chunk),
            Ok(Sslv2Event::ServerHello(expected_server_hello(&message)))
        );
        assert!(chunk.is_empty());
    }

    #[test]
    fn decoder_takes_only_one_record_per_event() {
        let mut bytes = record(&[0x00, 0x00, 0x01]);
        bytes.extend_from_slice(&record(&[0x00, 0x00, 0x04]));
        let mut decoder = Sslv2Decoder::default();
        let mut input = &bytes[..];
        assert_eq!(
            decoder.feed(&mut input),
            Ok(Sslv2Event::Error(Sslv2ErrorCode::NO_CIPHER))
        );
        assert_eq!(input.len(), 5);
        assert_eq!(
            decoder.feed(&mut input),
            Ok(Sslv2Event::Error(Sslv2ErrorCode::BAD_CERTIFICATE))
        );
        assert!(input.is_empty());
    }

    #[test]
    fn decoder_tls_reply_means_sslv2_unsupported() {
        // TLS-запись alert (fatal, handshake_failure), составлена по
        // RFC 5246, раздел 7.2: так TLS-сервер отвечает на SSLv2 hello.
        let alert = [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28];
        let mut decoder = Sslv2Decoder::default();
        let mut input = &alert[..];
        assert_eq!(
            decoder.feed(&mut input),
            Ok(Sslv2Event::TlsReply {
                prefix: &[0x15, 0x03],
            })
        );
        assert_eq!(input, &alert[2..]);

        // Повторный вызов возвращает то же событие и вход не забирает.
        assert_eq!(
            decoder.feed(&mut input),
            Ok(Sslv2Event::TlsReply {
                prefix: &[0x15, 0x03],
            })
        );
        assert_eq!(input, &alert[2..]);

        // Одного байта для решения недостаточно.
        let mut decoder = Sslv2Decoder::default();
        let mut input = &alert[..1];
        assert_eq!(decoder.feed(&mut input), Ok(Sslv2Event::NeedMore));
        let mut input = &alert[1..];
        assert!(matches!(
            decoder.feed(&mut input),
            Ok(Sslv2Event::TlsReply { .. })
        ));
    }

    #[test]
    fn decoder_rejects_unknown_protocol_and_repeats_error() {
        let banner = b"HTTP/1.1 400 Bad Request\r\n";
        let mut decoder = Sslv2Decoder::default();
        let mut input = &banner[..];
        let error = decoder.feed(&mut input).unwrap_err();
        assert!(matches!(
            error,
            ParseError::NotTls {
                position: 0,
                prefix_len: 16,
                ..
            }
        ));
        assert_eq!(error.not_tls_prefix(), Some(&banner[..16]));
        assert_eq!(input, &banner[16..]);

        let mut more = &b"more"[..];
        assert_eq!(decoder.feed(&mut more), Err(error));
        assert_eq!(more, &b"more"[..]);

        // Трёхбайтовый заголовок SSLv2 декодером не принимается.
        let mut decoder = Sslv2Decoder::default();
        let mut input = &[0x00, 0x03, 0x00, 0x00, 0x00, 0x01][..];
        assert!(matches!(
            decoder.feed(&mut input),
            Err(ParseError::NotTls { prefix_len: 6, .. })
        ));
    }

    #[test]
    fn decoder_limits() {
        let mut decoder = Sslv2Decoder::default();
        let mut input = &[0x80, 0x00][..];
        assert!(matches!(
            decoder.feed(&mut input),
            Err(ParseError::InvalidValue { position: 0, .. })
        ));

        // Заявлено 32 767 байтов тела, самого тела нет: лимит срабатывает
        // по заголовку, буфер под заявленную длину не выделяется.
        let mut decoder = Sslv2Decoder::default();
        let mut input = &[0xFF, 0xFF][..];
        let error = decoder.feed(&mut input).unwrap_err();
        assert_eq!(
            error,
            ParseError::LimitExceeded {
                position: 0,
                limit: "max_record_len",
                max: 18_432,
                actual: 32_767,
            }
        );
        assert_eq!(decoder.feed(&mut input), Err(error));

        let mut decoder = Sslv2Decoder::new(ParseLimits {
            max_total_bytes: 10,
            ..ParseLimits::default()
        });
        let mut input = &[0x80, 0x14][..];
        assert_eq!(
            decoder.feed(&mut input),
            Err(ParseError::LimitExceeded {
                position: 0,
                limit: "max_total_bytes",
                max: 10,
                actual: 22,
            })
        );

        // Лимит общего объёма считается от начала потока: вторая запись
        // начинается на смещении 5.
        let mut bytes = record(&[0x00, 0x00, 0x01]);
        bytes.extend_from_slice(&record(&[0x00, 0x00, 0x01]));
        let mut decoder = Sslv2Decoder::new(ParseLimits {
            max_total_bytes: 9,
            ..ParseLimits::default()
        });
        let mut input = &bytes[..];
        assert!(decoder.feed(&mut input).is_ok());
        assert_eq!(
            decoder.feed(&mut input),
            Err(ParseError::LimitExceeded {
                position: 5,
                limit: "max_total_bytes",
                max: 9,
                actual: 10,
            })
        );
    }

    #[test]
    fn decoder_reports_stream_positions_in_message_errors() {
        // Вторая запись — ERROR с лишним байтом: позиция считается от
        // начала потока (5 байтов первой записи + 2 заголовка + 3).
        let mut bytes = record(&[0x00, 0x00, 0x01]);
        bytes.extend_from_slice(&record(&[0x00, 0x00, 0x01, 0xFF]));
        let mut decoder = Sslv2Decoder::default();
        let mut input = &bytes[..];
        assert!(decoder.feed(&mut input).is_ok());
        let error = decoder.feed(&mut input).unwrap_err();
        assert_eq!(
            error,
            ParseError::TrailingBytes {
                position: 10,
                remaining: 1,
            }
        );
        assert_eq!(decoder.feed(&mut input), Err(error));
    }
}
