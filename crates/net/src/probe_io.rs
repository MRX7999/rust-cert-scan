//! Обмен пробником: отправка подготовленных байтов и чтение ответа через
//! декодер `tls-probe` до условия остановки.
//!
//! # Как пользоваться
//!
//! [`send_and_collect`] — один обмен на соединении: отправить, прочитать,
//! закрыть. [`ProbeSession`] — то же по шагам, когда на одном соединении
//! нужно несколько раундов:
//!
//! - обмен с HelloRetryRequest: первый раунд с [`Until::ServerHello`]
//!   возвращает HRR ([`ProbeTranscript::awaiting_second_hello`] — истина),
//!   вызывающий код собирает второй ClientHello и вызывает
//!   [`ProbeSession::send_and_collect`] ещё раз. Декодер и непрочитанный
//!   остаток буфера сохраняются между раундами, поэтому ChangeCipherSpec,
//!   пришедший вместе с HRR, не теряется;
//! - дочитывание: раунд с пустым `hello` ничего не отправляет и продолжает
//!   чтение.
//!
//! Транспорт — любой `AsyncRead + AsyncWrite + Unpin`: `TcpStream` от
//! [`Connector`](crate::connector::Connector), `tokio::io::duplex` в тестах,
//! будущие слои proxy и STARTTLS.
//!
//! # Зашифрованное содержимое (`docs/DECISIONS.md`, D-14)
//!
//! Декодер включает режим `Opaque` только по ChangeCipherSpec. После
//! ServerHello TLS 1.3 без CCS (сервер без режима совместимости, OpenSSL в
//! обмене с HRR) шифртекст приходит событием `ApplicationData`. Поэтому
//! запись помечается как шифртекст ([`OwnedRecord::ciphertext`]) в двух
//! случаях: событие `Opaque` после CCS; событие `ApplicationData` после
//! ServerHello, который не является HRR. Версию `net` не согласует: запись
//! `application_data` после ServerHello в TLS 1.2 и ниже допустима только
//! после CCS, так что открытым текстом она быть не может ни в одной версии.
//! [`Until::FirstEncrypted`] и [`Until::ServerFlight`] срабатывают на обе
//! формы.
//!
//! # Копирование и граница zero-copy
//!
//! События декодера заимствуют его внутренний буфер и живут до следующего
//! вызова `feed`, поэтому вынести их из цикла чтения нельзя. Обмен копирует
//! каждое сообщение один раз — во владеющий [`TranscriptItem`]. Это
//! допустимо: суммарный объём копий не превышает
//! [`ParseLimits::max_total_bytes`] (декодер отвергает поток длиннее лимита
//! по заголовку записи, до чтения тела), а копия живёт дольше соединения —
//! её читают проверки и кэш фактов. Граница zero-copy проходит здесь:
//! `tls-probe` разбирает без копий ([`ServerMessage`](tls_probe::ServerMessage)
//! и остальные разборщики принимают срезы [`OwnedHandshake::body`]), а
//! `net` владеет байтами.
//!
//! Буфер чтения — [`READ_BUFFER_LEN`] байтов, выделяется один раз на сессию
//! и переиспользуется; по длинам, заявленным сервером, память не
//! выделяется ни здесь, ни в декодере.
//!
//! # Таймауты
//!
//! Раздельные: `write` — на отправку пробника целиком, `handshake` — от
//! отправки до первого байта ответа, `read` — между порциями. Каждая
//! операция дополнительно ограничена остатком до общего дедлайна
//! ([`Timeouts::exchange`] от создания сессии и
//! [`ProbeSession::set_deadline`]), поэтому сервер, отдающий по байту, не
//! удержит соединение дольше дедлайна.
//!
//! # Ошибка записи
//!
//! Если запись не удалась из-за ошибки ввода-вывода (сервер закрыл
//! соединение раньше), обмен всё равно читает ответ: сервер мог прислать
//! alert или текст и закрыть сокет. Сведения об ошибке записи остаются в
//! [`ProbeTranscript::write_failure`], а прочитанное — в
//! [`ProbeTranscript::items`].
//!
//! # Закрытие соединения
//!
//! [`ProbeSession::close`] закрывает сторону записи (`shutdown`, для TCP —
//! FIN) и отпускает сокет; ожидание ограничено
//! [`CLOSE_TIMEOUT`], ответа сервера не
//! ждём. `close_notify` не отправляется: handshake не завершён, ключей нет,
//! а в TLS 1.3 alert после ServerHello обязан быть зашифрован — открытый
//! `close_notify` был бы нарушением протокола. `SO_LINGER 0` не ставится:
//! RST вместо FIN выглядит для сервера и IDS как обрыв. Предварительное
//! решение — `docs/DECISIONS.md`, D-17.

use std::fmt;
use std::io;
use std::time::Duration;

use tls_probe::record::HANDSHAKE_HEADER_LEN;
use tls_probe::{
    Alert, ContentType, Decoder, Event, HandshakeType, NOT_TLS_PREFIX_LEN, ParseError, ParseLimits,
    ProtocolVersion, Sslv2CertificateType, Sslv2Decoder, Sslv2ErrorCode, Sslv2Event,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::connector::Conn;
use crate::timeouts::{CLOSE_TIMEOUT, Deadline, Timeouts};

/// Размер буфера чтения сессии: 16 КиБ, одна полная запись TLS.
pub const READ_BUFFER_LEN: usize = 16 * 1024;

/// Handshake-сообщение с собственной копией байтов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedHandshake {
    /// Тип сообщения.
    pub msg_type: HandshakeType,
    raw: Vec<u8>,
}

impl OwnedHandshake {
    /// Тело сообщения без заголовка.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.raw.get(HANDSHAKE_HEADER_LEN..).unwrap_or(&[])
    }

    /// Сообщение целиком: заголовок из четырёх байтов и тело (нужно для
    /// хеша транскрипта).
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

/// Запись, которую декодер не интерпретирует, с собственной копией тела.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRecord {
    /// Тип содержимого.
    pub content_type: ContentType,
    /// Версия record layer; `None`, если декодер её не сообщил (событие
    /// `ApplicationData`).
    pub version: Option<ProtocolVersion>,
    /// Тело записи.
    pub payload: Vec<u8>,
    /// Истина, если запись — шифртекст: получена после ChangeCipherSpec
    /// либо это `application_data` после ServerHello (D-14).
    pub ciphertext: bool,
}

/// SSLv2 SERVER-HELLO с собственными копиями полей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedSslv2ServerHello {
    /// SESSION-ID-HIT.
    pub session_id_hit: bool,
    /// CERTIFICATE-TYPE.
    pub certificate_type: Sslv2CertificateType,
    /// SERVER-VERSION.
    pub version: ProtocolVersion,
    /// CERTIFICATE-DATA (DER).
    pub certificate: Vec<u8>,
    /// CIPHER-SPECS-DATA; длина кратна трём.
    pub cipher_specs: Vec<u8>,
    /// CONNECTION-ID-DATA.
    pub connection_id: Vec<u8>,
}

/// Одно полученное сообщение или запись, в порядке получения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptItem {
    /// Handshake-сообщение.
    Handshake(OwnedHandshake),
    /// Alert.
    Alert(Alert),
    /// ChangeCipherSpec.
    ChangeCipherSpec,
    /// Запись без интерпретации: шифртекст, `heartbeat`, неизвестный тип.
    Record(OwnedRecord),
    /// SSLv2 SERVER-HELLO.
    Sslv2ServerHello(OwnedSslv2ServerHello),
    /// SSLv2 ERROR.
    Sslv2Error(Sslv2ErrorCode),
    /// Запись SSLv2 с другим типом сообщения.
    Sslv2Other {
        /// Код типа сообщения.
        msg_type: u8,
        /// Остаток записи после байта типа.
        body: Vec<u8>,
    },
}

impl TranscriptItem {
    /// Истина для fatal alert и для SSLv2 ERROR: после них сервер обмен не
    /// продолжает.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::Alert(alert) => alert.is_fatal(),
            Self::Sslv2Error(_) => true,
            _ => false,
        }
    }

    /// Истина, если это handshake-сообщение заданного типа.
    #[must_use]
    pub fn is_handshake(&self, msg_type: HandshakeType) -> bool {
        matches!(self, Self::Handshake(message) if message.msg_type == msg_type)
    }

    /// Истина, если это запись с шифртекстом.
    #[must_use]
    pub fn is_ciphertext(&self) -> bool {
        matches!(self, Self::Record(record) if record.ciphertext)
    }
}

/// Условие остановки чтения. Fatal alert (и SSLv2 ERROR), закрытие
/// соединения, таймауты и ошибки останавливают обмен при любом условии.
pub enum Until {
    /// Первое сообщение `server_hello` (в том числе HelloRetryRequest) либо
    /// SSLv2 SERVER-HELLO.
    ServerHello,
    /// Сообщение `server_hello_done` (TLS 1.2 и ниже).
    ServerHelloDone,
    /// Первая запись с шифртекстом, см. [`OwnedRecord::ciphertext`].
    FirstEncrypted,
    /// Конец открытой части ответа в любой версии: `server_hello_done`,
    /// первая запись с шифртекстом либо SSLv2 SERVER-HELLO.
    ServerFlight,
    /// Любой alert (и SSLv2 ERROR), в том числе уровня warning.
    Alert,
    /// Произвольный предикат; вызывается для каждого элемента в порядке
    /// получения, истина останавливает чтение.
    Predicate(Box<dyn FnMut(&TranscriptItem) -> bool + Send>),
}

impl Until {
    /// Условие с произвольным предикатом.
    #[must_use]
    pub fn predicate(predicate: impl FnMut(&TranscriptItem) -> bool + Send + 'static) -> Self {
        Self::Predicate(Box::new(predicate))
    }

    fn matches(&mut self, item: &TranscriptItem) -> bool {
        match self {
            Self::ServerHello => {
                item.is_handshake(HandshakeType::SERVER_HELLO)
                    || matches!(item, TranscriptItem::Sslv2ServerHello(_))
            }
            Self::ServerHelloDone => item.is_handshake(HandshakeType::SERVER_HELLO_DONE),
            Self::FirstEncrypted => item.is_ciphertext(),
            Self::ServerFlight => {
                item.is_handshake(HandshakeType::SERVER_HELLO_DONE)
                    || item.is_ciphertext()
                    || matches!(item, TranscriptItem::Sslv2ServerHello(_))
            }
            Self::Alert => matches!(
                item,
                TranscriptItem::Alert(_) | TranscriptItem::Sslv2Error(_)
            ),
            Self::Predicate(predicate) => predicate(item),
        }
    }
}

impl fmt::Debug for Until {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ServerHello => "ServerHello",
            Self::ServerHelloDone => "ServerHelloDone",
            Self::FirstEncrypted => "FirstEncrypted",
            Self::ServerFlight => "ServerFlight",
            Self::Alert => "Alert",
            Self::Predicate(_) => "Predicate(..)",
        })
    }
}

/// В какой момент сервер закрыл соединение.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EofKind {
    /// До первого байта ответа за всё время сессии.
    BeforeFirstByte,
    /// На границе сообщений: всё полученное разобрано полностью.
    AtMessageBoundary,
    /// Посреди записи, handshake-сообщения или alert: ответ обрезан.
    MidMessage,
}

/// Неудачная отправка пробника.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteFailure {
    /// Вид ошибки; [`io::ErrorKind::TimedOut`] — истёк таймаут записи.
    pub kind: io::ErrorKind,
    /// Сколько байтов транспорт принял до ошибки.
    pub written: usize,
    /// Сколько байтов требовалось отправить.
    pub total: usize,
}

/// Причина, по которой обмен остановился.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Выполнено условие [`Until`].
    ConditionMet,
    /// Получен fatal alert или SSLv2 ERROR, условие при этом не выполнено.
    /// Это результат обмена, а не ошибка.
    FatalAlert,
    /// Сервер закрыл соединение.
    Eof(EofKind),
    /// Соединение сброшено (RST) при чтении.
    Reset {
        /// Исходный вид ошибки.
        kind: io::ErrorKind,
    },
    /// После отправки пробника не пришло ни байта за `handshake`.
    HandshakeTimeout,
    /// Очередная порция ответа не пришла за `read`.
    ReadTimeout,
    /// Истёк общий дедлайн обмена.
    Deadline,
    /// Ответ не похож на TLS (и на SSLv2 — для SSLv2-сессии).
    NotTls {
        /// Первые байты ответа, не более [`NOT_TLS_PREFIX_LEN`].
        first_bytes: Vec<u8>,
    },
    /// Ошибка разбора ответа.
    Parse(ParseError),
    /// Превышен лимит разбора (`ParseError::LimitExceeded`): длина записи
    /// или сообщения, общий объём, число пустых записей.
    LimitExceeded(ParseError),
    /// Пробник отправить не удалось, и содержательного ответа не получено.
    WriteFailed(WriteFailure),
    /// Прочая ошибка чтения.
    Io {
        /// Исходный вид ошибки.
        kind: io::ErrorKind,
    },
}

impl StopReason {
    /// Короткая метка для журналов и вывода.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::ConditionMet => "condition",
            Self::FatalAlert => "fatal_alert",
            Self::Eof(EofKind::BeforeFirstByte) => "eof_before_first_byte",
            Self::Eof(EofKind::AtMessageBoundary) => "eof",
            Self::Eof(EofKind::MidMessage) => "eof_mid_message",
            Self::Reset { .. } => "reset",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::ReadTimeout => "read_timeout",
            Self::Deadline => "deadline",
            Self::NotTls { .. } => "not_tls",
            Self::Parse(_) => "parse",
            Self::LimitExceeded(_) => "limit",
            Self::WriteFailed(_) => "write",
            Self::Io { .. } => "io",
        }
    }

    /// Истина, если после этой причины соединение непригодно для следующего
    /// раунда: следующий вызов вернёт ту же причину без ввода-вывода.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::ConditionMet | Self::FatalAlert | Self::HandshakeTimeout | Self::ReadTimeout => {
                false
            }
            Self::Eof(_)
            | Self::Reset { .. }
            | Self::Deadline
            | Self::NotTls { .. }
            | Self::Parse(_)
            | Self::LimitExceeded(_)
            | Self::WriteFailed(_)
            | Self::Io { .. } => true,
        }
    }
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConditionMet => f.write_str("условие остановки выполнено"),
            Self::FatalAlert => f.write_str("сервер прислал fatal alert"),
            Self::Eof(EofKind::BeforeFirstByte) => {
                f.write_str("сервер закрыл соединение до первого байта ответа")
            }
            Self::Eof(EofKind::AtMessageBoundary) => {
                f.write_str("сервер закрыл соединение на границе сообщений")
            }
            Self::Eof(EofKind::MidMessage) => {
                f.write_str("сервер закрыл соединение посреди сообщения")
            }
            Self::Reset { kind } => write!(f, "соединение сброшено при чтении ({kind:?})"),
            Self::HandshakeTimeout => f.write_str("таймаут handshake: нет первого байта ответа"),
            Self::ReadTimeout => f.write_str("таймаут read: нет очередной порции ответа"),
            Self::Deadline => f.write_str("истёк общий дедлайн обмена"),
            Self::NotTls { first_bytes } => {
                f.write_str("ответ не похож на TLS, первые байты:")?;
                for byte in first_bytes {
                    write!(f, " {byte:02x}")?;
                }
                Ok(())
            }
            Self::Parse(error) => write!(f, "ошибка разбора ответа: {error}"),
            Self::LimitExceeded(error) => write!(f, "превышен лимит чтения: {error}"),
            Self::WriteFailed(failure) => write!(
                f,
                "ошибка записи пробника ({:?}): отправлено {} из {} байт",
                failure.kind, failure.written, failure.total
            ),
            Self::Io { kind } => write!(f, "ошибка чтения ({kind:?})"),
        }
    }
}

/// Результат одного раунда обмена; владеет всеми данными.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTranscript {
    /// Полученные сообщения и записи в порядке получения.
    pub items: Vec<TranscriptItem>,
    /// Причина остановки.
    pub stop: StopReason,
    /// Ошибка записи пробника, если она была; при этом `stop` может
    /// описывать ответ, прочитанный после неё.
    pub write_failure: Option<WriteFailure>,
    /// Истина, если последним `server_hello` был HelloRetryRequest и второй
    /// ServerHello ещё не получен.
    pub awaiting_second_hello: bool,
    /// Сколько байтов пробника принял транспорт в этом раунде.
    pub bytes_sent: usize,
    /// Сколько байтов прочитано из транспорта в этом раунде.
    pub bytes_received: usize,
    /// Длительность раунда.
    pub duration: Duration,
}

impl ProbeTranscript {
    /// Истина, если обмен остановлен выполненным условием.
    #[must_use]
    pub fn condition_met(&self) -> bool {
        self.stop == StopReason::ConditionMet
    }

    /// Handshake-сообщения в порядке получения.
    pub fn handshake_messages(&self) -> impl Iterator<Item = &OwnedHandshake> {
        self.items.iter().filter_map(|item| match item {
            TranscriptItem::Handshake(message) => Some(message),
            _ => None,
        })
    }

    /// Первое handshake-сообщение заданного типа.
    #[must_use]
    pub fn handshake(&self, msg_type: HandshakeType) -> Option<&OwnedHandshake> {
        self.handshake_messages()
            .find(|message| message.msg_type == msg_type)
    }

    /// Alert'ы в порядке получения.
    pub fn alerts(&self) -> impl Iterator<Item = Alert> + '_ {
        self.items.iter().filter_map(|item| match item {
            TranscriptItem::Alert(alert) => Some(*alert),
            _ => None,
        })
    }

    /// Первый fatal alert.
    #[must_use]
    pub fn fatal_alert(&self) -> Option<Alert> {
        self.alerts().find(Alert::is_fatal)
    }
}

/// Декодер ответа: TLS либо SSLv2.
#[derive(Debug)]
enum Framing {
    Tls(Decoder),
    Sslv2 {
        decoder: Sslv2Decoder,
        /// Получена часть записи, событие по ней ещё не выдано.
        partial: bool,
    },
}

impl Framing {
    fn is_idle(&self) -> bool {
        match self {
            Self::Tls(decoder) => decoder.is_idle(),
            Self::Sslv2 { partial, .. } => !partial,
        }
    }

    fn awaits_second_hello(&self) -> bool {
        match self {
            Self::Tls(decoder) => decoder.awaits_second_hello(),
            Self::Sslv2 { .. } => false,
        }
    }
}

/// Итог одного вызова декодера, без заимствований.
enum Fed {
    NeedMore,
    Item(TranscriptItem),
    /// SSLv2-декодер увидел TLS-запись; внутри — забранное им начало потока.
    TlsReply(Vec<u8>),
}

fn feed_once(
    framing: &mut Framing,
    input: &mut &[u8],
    server_hello_seen: &mut bool,
) -> Result<Fed, ParseError> {
    match framing {
        Framing::Tls(decoder) => feed_tls(decoder, input, server_hello_seen),
        Framing::Sslv2 { decoder, partial } => feed_sslv2(decoder, partial, input),
    }
}

fn feed_tls(
    decoder: &mut Decoder,
    input: &mut &[u8],
    server_hello_seen: &mut bool,
) -> Result<Fed, ParseError> {
    // Единственное копирование: событие заимствует буфер декодера.
    let (mut item, after_ccs_only) = match decoder.feed(input)? {
        Event::NeedMore => return Ok(Fed::NeedMore),
        Event::Handshake(message) => (
            TranscriptItem::Handshake(OwnedHandshake {
                msg_type: message.msg_type,
                raw: message.raw.to_vec(),
            }),
            false,
        ),
        Event::Alert(bytes) => (TranscriptItem::Alert(Alert::parse(bytes)?), false),
        Event::ChangeCipherSpec => (TranscriptItem::ChangeCipherSpec, false),
        Event::ApplicationData(body) => (
            TranscriptItem::Record(OwnedRecord {
                content_type: ContentType::APPLICATION_DATA,
                version: None,
                payload: body.to_vec(),
                ciphertext: false,
            }),
            false,
        ),
        Event::Opaque(record) => (
            TranscriptItem::Record(OwnedRecord {
                content_type: record.content_type,
                version: Some(record.version),
                payload: record.fragment.to_vec(),
                ciphertext: false,
            }),
            true,
        ),
    };
    match &mut item {
        TranscriptItem::Handshake(message)
            if message.msg_type == HandshakeType::SERVER_HELLO
                && !decoder.awaits_second_hello() =>
        {
            *server_hello_seen = true;
        }
        TranscriptItem::Record(record) => {
            // D-14: `Opaque` — шифртекст только после CCS (до CCS это
            // heartbeat или неизвестный тип); `ApplicationData` — шифртекст
            // после ServerHello, не являющегося HRR.
            record.ciphertext = if after_ccs_only {
                decoder.is_opaque()
            } else {
                *server_hello_seen
            };
        }
        _ => {}
    }
    Ok(Fed::Item(item))
}

fn feed_sslv2(
    decoder: &mut Sslv2Decoder,
    partial: &mut bool,
    input: &mut &[u8],
) -> Result<Fed, ParseError> {
    let before = input.len();
    let event = decoder.feed(input)?;
    let consumed = before.saturating_sub(input.len());
    let item = match event {
        Sslv2Event::NeedMore => {
            if consumed > 0 {
                *partial = true;
            }
            return Ok(Fed::NeedMore);
        }
        Sslv2Event::TlsReply { prefix } => return Ok(Fed::TlsReply(prefix.to_vec())),
        Sslv2Event::ServerHello(hello) => TranscriptItem::Sslv2ServerHello(OwnedSslv2ServerHello {
            session_id_hit: hello.session_id_hit,
            certificate_type: hello.certificate_type,
            version: hello.version,
            certificate: hello.certificate.to_vec(),
            cipher_specs: hello.cipher_specs.to_vec(),
            connection_id: hello.connection_id.to_vec(),
        }),
        Sslv2Event::Error(code) => TranscriptItem::Sslv2Error(code),
        Sslv2Event::Other { msg_type, body } => TranscriptItem::Sslv2Other {
            msg_type,
            body: body.to_vec(),
        },
    };
    *partial = false;
    Ok(Fed::Item(item))
}

/// Чем закончилась отправка.
enum SendError {
    /// Общий дедлайн истёк до или во время записи.
    Deadline,
    /// Ошибка или таймаут записи.
    Failed(WriteFailure),
}

/// Обмен пробниками на одном соединении; описание — в документации модуля.
pub struct ProbeSession<S> {
    stream: S,
    framing: Framing,
    limits: ParseLimits,
    timeouts: Timeouts,
    deadline: Deadline,
    /// Буфер чтения фиксированного размера; действующие данные —
    /// `buf[pos..end]`.
    buf: Vec<u8>,
    pos: usize,
    end: usize,
    received_total: usize,
    sent_total: usize,
    first_bytes: [u8; NOT_TLS_PREFIX_LEN],
    first_len: usize,
    /// После отправки пробника ещё не получено ни байта.
    awaiting_first_byte: bool,
    /// Получен ServerHello, не являющийся HRR.
    server_hello_seen: bool,
    terminal: Option<StopReason>,
}

impl<S> fmt::Debug for ProbeSession<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeSession")
            .field("timeouts", &self.timeouts)
            .field("deadline", &self.deadline)
            .field("buffered", &self.end.saturating_sub(self.pos))
            .field("received_total", &self.received_total)
            .field("sent_total", &self.sent_total)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

impl<S> ProbeSession<S> {
    /// Сессия для TLS-пробника (ответ разбирает [`Decoder`]).
    #[must_use]
    pub fn new(stream: S, timeouts: Timeouts, limits: ParseLimits) -> Self {
        Self::with_framing(stream, timeouts, limits, Framing::Tls(Decoder::new(limits)))
    }

    /// Сессия для SSLv2 CLIENT-HELLO (ответ разбирает [`Sslv2Decoder`]).
    /// Если сервер отвечает TLS-записью, сессия переключается на
    /// [`Decoder`] и разбирает ответ как TLS.
    #[must_use]
    pub fn sslv2(stream: S, timeouts: Timeouts, limits: ParseLimits) -> Self {
        let framing = Framing::Sslv2 {
            decoder: Sslv2Decoder::new(limits),
            partial: false,
        };
        Self::with_framing(stream, timeouts, limits, framing)
    }

    /// TLS-сессия поверх соединения от
    /// [`Connector`](crate::connector::Connector), с его таймаутами.
    #[must_use]
    pub fn from_conn(conn: Conn<S>, limits: ParseLimits) -> Self {
        let timeouts = *conn.timeouts();
        Self::new(conn.into_stream(), timeouts, limits)
    }

    fn with_framing(stream: S, timeouts: Timeouts, limits: ParseLimits, framing: Framing) -> Self {
        Self {
            stream,
            framing,
            limits,
            timeouts,
            deadline: Deadline::after(Instant::now(), timeouts.exchange),
            buf: vec![0; READ_BUFFER_LEN],
            pos: 0,
            end: 0,
            received_total: 0,
            sent_total: 0,
            first_bytes: [0; NOT_TLS_PREFIX_LEN],
            first_len: 0,
            awaiting_first_byte: false,
            server_hello_seen: false,
            terminal: None,
        }
    }

    /// Ужесточает общий дедлайн: действует более ранний из текущего и
    /// заданного (например, дедлайн всей проверки).
    pub fn set_deadline(&mut self, deadline: Deadline) {
        self.deadline = self.deadline.earliest(deadline);
    }

    /// Действующий общий дедлайн.
    #[must_use]
    pub fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Сколько байтов отправлено за всю сессию.
    #[must_use]
    pub fn bytes_sent(&self) -> usize {
        self.sent_total
    }

    /// Сколько байтов прочитано за всю сессию.
    #[must_use]
    pub fn bytes_received(&self) -> usize {
        self.received_total
    }

    /// Первые байты ответа, не более [`NOT_TLS_PREFIX_LEN`].
    #[must_use]
    pub fn first_bytes(&self) -> &[u8] {
        self.first_bytes.get(..self.first_len).unwrap_or(&[])
    }

    /// Забирает транспорт без закрытия. Байты, прочитанные, но не
    /// разобранные декодером, при этом теряются.
    #[must_use]
    pub fn into_stream(self) -> S {
        self.stream
    }

    fn parse_stop(&self, error: ParseError) -> StopReason {
        match error {
            ParseError::NotTls { .. } => StopReason::NotTls {
                first_bytes: self.first_bytes().to_vec(),
            },
            ParseError::LimitExceeded { .. } => StopReason::LimitExceeded(error),
            _ => StopReason::Parse(error),
        }
    }
}

impl<S> ProbeSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Один раунд: отправляет `hello` (пустой срез — ничего не отправляет)
    /// и читает ответ до условия `until` либо до другой причины остановки.
    ///
    /// Ошибок не возвращает: любой исход описан в
    /// [`ProbeTranscript::stop`], всё прочитанное — в
    /// [`ProbeTranscript::items`].
    pub async fn send_and_collect(&mut self, hello: &[u8], mut until: Until) -> ProbeTranscript {
        let started = Instant::now();
        let received_before = self.received_total;
        let mut items = Vec::new();
        let mut bytes_sent = 0;
        let mut write_failure = None;

        let stop = match self.terminal.clone() {
            Some(reason) => reason,
            None => {
                self.run(
                    hello,
                    &mut until,
                    &mut items,
                    &mut bytes_sent,
                    &mut write_failure,
                )
                .await
            }
        };
        if stop.is_terminal() {
            self.terminal = Some(stop.clone());
        }
        ProbeTranscript {
            items,
            stop,
            write_failure,
            awaiting_second_hello: self.framing.awaits_second_hello(),
            bytes_sent,
            bytes_received: self.received_total.saturating_sub(received_before),
            duration: started.elapsed(),
        }
    }

    /// Закрывает соединение: `shutdown` стороны записи с ограничением
    /// [`CLOSE_TIMEOUT`], затем сокет отпускается. `close_notify` не
    /// отправляется, ответа сервера не ждём — см. документацию модуля.
    pub async fn close(mut self) {
        // Результат не важен: при ошибке или таймауте сокет всё равно
        // закрывается при уничтожении `self`.
        let _outcome = tokio::time::timeout(CLOSE_TIMEOUT, self.stream.shutdown()).await;
    }

    async fn run(
        &mut self,
        hello: &[u8],
        until: &mut Until,
        items: &mut Vec<TranscriptItem>,
        bytes_sent: &mut usize,
        write_failure: &mut Option<WriteFailure>,
    ) -> StopReason {
        if hello.is_empty() {
            return self.collect(until, items).await;
        }
        let sent = self.send(hello, bytes_sent).await;
        self.sent_total = self.sent_total.saturating_add(*bytes_sent);
        self.awaiting_first_byte = true;
        match sent {
            Ok(()) => self.collect(until, items).await,
            Err(SendError::Deadline) => StopReason::Deadline,
            Err(SendError::Failed(failure)) => {
                *write_failure = Some(failure);
                if failure.kind == io::ErrorKind::TimedOut {
                    return StopReason::WriteFailed(failure);
                }
                // Сервер закрыл соединение раньше, чем принял пробник, но
                // мог успеть ответить: читаем то, что есть.
                match self.collect(until, items).await {
                    stop @ (StopReason::ConditionMet
                    | StopReason::FatalAlert
                    | StopReason::NotTls { .. }
                    | StopReason::Parse(_)
                    | StopReason::LimitExceeded(_)) => stop,
                    _ => StopReason::WriteFailed(failure),
                }
            }
        }
    }

    /// Отправляет пробник целиком за `write`, но не позже общего дедлайна.
    /// `written` — сколько байтов принял транспорт, в том числе при ошибке.
    async fn send(&mut self, bytes: &[u8], written: &mut usize) -> Result<(), SendError> {
        let limit = self.timeouts.write;
        let Some(budget) = self.deadline.budget(Instant::now(), limit) else {
            return Err(SendError::Deadline);
        };
        let stream = &mut self.stream;
        let counter = &mut *written;
        let write = async move {
            loop {
                let rest = bytes.get(*counter..).unwrap_or(&[]);
                if rest.is_empty() {
                    break;
                }
                let accepted = stream.write(rest).await?;
                if accepted == 0 {
                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                }
                *counter = counter.saturating_add(accepted);
            }
            stream.flush().await
        };
        let outcome = tokio::time::timeout(budget, write).await;
        match outcome {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(SendError::Failed(WriteFailure {
                kind: error.kind(),
                written: *written,
                total: bytes.len(),
            })),
            Err(_elapsed) if budget < limit => Err(SendError::Deadline),
            Err(_elapsed) => Err(SendError::Failed(WriteFailure {
                kind: io::ErrorKind::TimedOut,
                written: *written,
                total: bytes.len(),
            })),
        }
    }

    /// Читает и разбирает ответ до причины остановки.
    async fn collect(&mut self, until: &mut Until, items: &mut Vec<TranscriptItem>) -> StopReason {
        loop {
            // Разбор всего, что уже прочитано. Декодер вызывается до
            // `NeedMore` даже при пустом входе: в нём могут оставаться
            // события (несколько сообщений в одной записи).
            loop {
                let chunk = self.buf.get(self.pos..self.end).unwrap_or(&[]);
                let mut input = chunk;
                let fed = feed_once(&mut self.framing, &mut input, &mut self.server_hello_seen);
                let consumed = chunk.len().saturating_sub(input.len());
                self.pos = self.pos.saturating_add(consumed);
                match fed {
                    Err(error) => return self.parse_stop(error),
                    Ok(Fed::NeedMore) => break,
                    Ok(Fed::TlsReply(prefix)) => {
                        let mut decoder = Decoder::new(self.limits);
                        let mut head = prefix.as_slice();
                        if let Err(error) = decoder.feed(&mut head) {
                            return self.parse_stop(error);
                        }
                        self.framing = Framing::Tls(decoder);
                    }
                    Ok(Fed::Item(item)) => {
                        let matched = until.matches(&item);
                        let fatal = item.is_fatal();
                        items.push(item);
                        if matched {
                            return StopReason::ConditionMet;
                        }
                        if fatal {
                            return StopReason::FatalAlert;
                        }
                    }
                }
            }

            // Очередное чтение: не дольше своего таймаута и не дольше
            // остатка до общего дедлайна.
            let awaiting = self.awaiting_first_byte;
            let limit = if awaiting {
                self.timeouts.handshake
            } else {
                self.timeouts.read
            };
            let Some(budget) = self.deadline.budget(Instant::now(), limit) else {
                return StopReason::Deadline;
            };
            let read = tokio::time::timeout(budget, self.stream.read(&mut self.buf)).await;
            let count = match read {
                Err(_elapsed) if budget < limit => return StopReason::Deadline,
                Err(_elapsed) if awaiting => return StopReason::HandshakeTimeout,
                Err(_elapsed) => return StopReason::ReadTimeout,
                Ok(Err(error)) => {
                    let kind = error.kind();
                    return match kind {
                        io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe => StopReason::Reset { kind },
                        _ => StopReason::Io { kind },
                    };
                }
                Ok(Ok(0)) => {
                    let kind = if self.received_total == 0 {
                        EofKind::BeforeFirstByte
                    } else if self.framing.is_idle() {
                        EofKind::AtMessageBoundary
                    } else {
                        EofKind::MidMessage
                    };
                    return StopReason::Eof(kind);
                }
                Ok(Ok(count)) => count.min(self.buf.len()),
            };
            for byte in self.buf.get(..count).unwrap_or(&[]) {
                let Some(slot) = self.first_bytes.get_mut(self.first_len) else {
                    break;
                };
                *slot = *byte;
                self.first_len = self.first_len.saturating_add(1);
            }
            self.received_total = self.received_total.saturating_add(count);
            self.pos = 0;
            self.end = count;
            self.awaiting_first_byte = false;
        }
    }
}

/// Один обмен на соединении: отправляет `hello_bytes`, читает ответ до
/// `until` с лимитами разбора по умолчанию и закрывает соединение
/// ([`ProbeSession::close`]). Для нескольких раундов на одном соединении
/// (HelloRetryRequest) и для своих лимитов используйте [`ProbeSession`].
pub async fn send_and_collect<S>(conn: Conn<S>, hello_bytes: &[u8], until: Until) -> ProbeTranscript
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = ProbeSession::from_conn(conn, ParseLimits::default());
    let transcript = session.send_and_collect(hello_bytes, until).await;
    session.close().await;
    transcript
}
