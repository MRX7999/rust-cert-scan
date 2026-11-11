//! Инкрементальный декодер потока TLS-записей.
//!
//! [`Decoder::feed`] принимает байты порциями любого размера и возвращает по
//! одному событию за вызов. I/O выполняет вызывающий код:
//!
//! ```
//! use tls_probe::decoder::{Decoder, Event};
//!
//! let mut decoder = Decoder::default();
//! // Запись handshake с одним сообщением ServerHelloDone.
//! let mut input: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x04, 0x0E, 0x00, 0x00, 0x00];
//! let mut seen = 0;
//! loop {
//!     match decoder.feed(&mut input) {
//!         Ok(Event::NeedMore) => break, // вход исчерпан, нужно читать дальше
//!         Ok(_event) => seen += 1,
//!         Err(_error) => break, // не TLS, превышен лимит или нарушен формат
//!     }
//! }
//! assert_eq!(seen, 1);
//! ```
//!
//! # Состояния
//!
//! - «нужно больше данных» — [`Event::NeedMore`]; возвращается, только когда
//!   переданный вход исчерпан;
//! - «готово сообщение» — остальные варианты [`Event`]; срезы в них
//!   заимствуют внутренние буферы декодера и живут до следующего вызова;
//! - «ошибка» — `Err(ParseError)`. Ошибка окончательная: все следующие вызовы
//!   возвращают её же.
//!
//! # Ответ, не похожий на TLS
//!
//! Первая запись потока проверяется по первым двум байтам: тип содержимого
//! должен быть одним из пяти известных, старший байт версии — равен 3. Иначе
//! возвращается [`ParseError::NotTls`] с первыми байтами ответа (сколько их
//! было доступно в момент проверки, не более
//! [`NOT_TLS_PREFIX_LEN`](crate::error::NOT_TLS_PREFIX_LEN)). Так
//! распознаются HTTP-текст, баннеры SMTP/FTP/POP3 и ответ SSLv2; разбор SSLv2
//! — отдельная задача (P1-08). Во второй и следующих записях неизвестный тип
//! содержимого — не ошибка (событие [`Event::Opaque`]), а старший байт
//! версии, отличный от 3, — [`ParseError::InvalidValue`].
//!
//! # Handshake-сообщения
//!
//! Декодер склеивает сообщение, разбитое на несколько записей, и разделяет
//! несколько сообщений в одной записи. Заявленная длина сообщения
//! проверяется по [`ParseLimits::max_handshake_len`], как только получен его
//! заголовок, то есть до накопления тела. Записи другого типа посреди
//! недособранного сообщения — ошибка. Пустая запись handshake — ошибка
//! [`ParseError::InvalidValue`]: фрагменты нулевой длины для handshake
//! запрещены (RFC 8446, раздел 5.1; RFC 5246, раздел 6.2.1).
//!
//! # Alert
//!
//! Событие [`Event::Alert`] выдаётся на каждые два байта потока alert. В
//! TLS 1.3 запись alert содержит ровно одно сообщение (RFC 8446, раздел 5.1),
//! в TLS 1.2 и ниже сообщения одного типа могут быть склеены в одной записи
//! или разбиты между записями (RFC 5246, раздел 6.2.1). Декодер принимает оба
//! случая: несколько alert в одной записи дают несколько событий, alert,
//! разбитый на две записи, — одно. Пустая запись alert — ошибка
//! [`ParseError::InvalidValue`] (RFC 5246, раздел 6.2.1); запись другого типа
//! после первого байта alert — тоже. Если поток закрылся после нечётного
//! числа байтов alert, [`Decoder::is_idle`] возвращает ложь.
//!
//! # Зашифрованные записи
//!
//! Расшифровки нет. Режим [`Event::Opaque`] включает только
//! ChangeCipherSpec: после него все записи, включая записи типа handshake и
//! alert, возвращаются как `Opaque`. Сам факт ServerHello TLS 1.3 этот режим
//! не включает (`docs/DECISIONS.md`, D-14), поэтому вид события для
//! зашифрованной записи зависит от того, прислал ли сервер CCS:
//!
//! - TLS 1.2 и ниже: ServerHello … ServerHelloDone открытым текстом, затем
//!   CCS и зашифрованный Finished — он приходит как `Opaque`;
//! - TLS 1.3 с CCS (режим совместимости с middlebox, обмен без HRR):
//!   ServerHello, CCS, затем зашифрованные записи `application_data` — они
//!   приходят как `Opaque`;
//! - TLS 1.3 без CCS после ServerHello: зашифрованные записи
//!   `application_data` приходят как [`Event::ApplicationData`]. Так ведёт
//!   себя сервер без режима совместимости, а также OpenSSL в обмене с
//!   HelloRetryRequest: он шлёт CCS один раз, сразу за HRR, и после второго
//!   ServerHello CCS уже нет (фикстура
//!   `tls13-serverhello-openssl-basic-after-hrr`);
//! - TLS 1.3 с HelloRetryRequest: HRR, CCS, затем второй ServerHello открытым
//!   текстом. Декодер распознаёт HRR сам: когда выдано сообщение
//!   `server_hello`, у которого `random` равен
//!   [`HELLO_RETRY_REQUEST_RANDOM`], он ждёт второй ServerHello, и CCS в этом
//!   состоянии отдаётся событием, но режим `Opaque` не включает. Ожидание
//!   заканчивается на следующем `server_hello`, который HRR не является.
//!   Если после него придёт ещё один CCS, он включит `Opaque` как обычно;
//!   если не придёт — действует предыдущий пункт.
//!
//! Следствие для вызывающего кода (`net`, `tls-session`): после ServerHello
//! с согласованной версией TLS 1.3 любую запись `application_data` надо
//! считать шифртекстом независимо от того, каким событием она пришла —
//! `Opaque` или `ApplicationData`. Декодер версию не согласует и этого
//! решения не принимает.
//!
//! Второй HRR подряд (нарушение RFC 8446, раздел 4.1.4) декодер не считает
//! ошибкой: он выдаётся событием `Handshake`, ожидание второго ServerHello
//! продолжается, CCS по-прежнему не включает `Opaque`. Число HRR считает
//! вызывающий код. Объём такого потока ограничен
//! [`ParseLimits::max_total_bytes`].
//!
//! Вызывать [`Decoder::resume_plaintext`] после HRR не требуется; метод
//! оставлен как ручное переопределение.
//!
//! # Лимиты потока
//!
//! Кроме длины записи и сообщения, декодер проверяет общий объём потока
//! ([`ParseLimits::max_total_bytes`]: смещение конца записи сравнивается с
//! лимитом, как только получен её заголовок) и число подряд идущих пустых
//! записей, для которых пустое тело допустимо: `application_data`,
//! `heartbeat`, неизвестный тип и любая запись в режиме `Opaque`
//! ([`ParseLimits::max_empty_records`]). Счётчик сбрасывается любой непустой
//! записью.
//!
//! # Память
//!
//! Буфер записи не превышает `RECORD_HEADER_LEN + max_record_len`, буфер
//! сообщения — `HANDSHAKE_HEADER_LEN + max_handshake_len`. Оба растут только
//! по фактически полученным байтам: заявленная сервером длина используется
//! для сравнения с лимитом, память по ней не выделяется.

use crate::codec::Reader;
use crate::error::{NOT_TLS_PREFIX_LEN, ParseError};
use crate::limits::ParseLimits;
use crate::record::{
    ContentType, HANDSHAKE_HEADER_LEN, HandshakeType, RECORD_HEADER_LEN, Record, RecordHeader,
};
use crate::server_hello::{HELLO_RETRY_REQUEST_RANDOM, RANDOM_LEN};

/// Длина сообщения alert: уровень и описание.
const ALERT_LEN: usize = 2;

/// Нарушенный инвариант: событие Handshake без полного заголовка сообщения.
const BROKEN_HANDSHAKE_EVENT: &str = "событие Handshake без полного заголовка сообщения";

/// Нарушенный инвариант: событие Opaque без заголовка записи.
const BROKEN_OPAQUE_EVENT: &str = "событие Opaque без заголовка записи";

/// Собранное handshake-сообщение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMessage<'a> {
    /// Тип сообщения.
    pub msg_type: HandshakeType,
    /// Тело без заголовка.
    pub body: &'a [u8],
    /// Сообщение целиком: заголовок из четырёх байтов и тело.
    pub raw: &'a [u8],
}

/// Событие декодера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// Переданный вход исчерпан, событие ещё не готово.
    NeedMore,
    /// Полное handshake-сообщение.
    Handshake(HandshakeMessage<'a>),
    /// Одно сообщение alert: ровно два байта, уровень и описание, в том
    /// числе собранные из двух записей; разбирается функцией
    /// [`Alert::parse`](crate::alert::Alert::parse).
    Alert(&'a [u8]),
    /// Запись ChangeCipherSpec с корректным телом.
    ChangeCipherSpec,
    /// Тело записи `application_data` до ChangeCipherSpec; для TLS 1.3 без
    /// CCS это зашифрованная запись.
    ApplicationData(&'a [u8]),
    /// Запись, которую декодер не интерпретирует: `heartbeat`, неизвестный
    /// тип содержимого либо любая запись после ChangeCipherSpec.
    Opaque(Record<'a>),
}

/// Результат шага без заимствований; событие строится из него отдельно.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    NeedMore,
    Handshake,
    Alert,
    ChangeCipherSpec,
    ApplicationData,
    Opaque,
}

/// Инкрементальный декодер; описание — в документации модуля.
#[derive(Debug)]
pub struct Decoder {
    limits: ParseLimits,
    /// Текущая запись: заголовок и полученная часть тела.
    record: Vec<u8>,
    /// Заголовок текущей записи, когда получены все пять его байтов.
    header: Option<RecordHeader>,
    /// Сколько байтов тела текущей записи уже разобрано на сообщения.
    fragment_pos: usize,
    /// Текущая запись отдана событием и освобождается на следующем шаге.
    release_record: bool,
    /// Текущее handshake-сообщение: заголовок и полученная часть тела.
    handshake: Vec<u8>,
    /// Полная длина текущего сообщения с заголовком, когда она известна.
    handshake_len: Option<usize>,
    /// Сообщение отдано событием и освобождается на следующем шаге.
    release_handshake: bool,
    /// Смещение начала текущей записи в потоке.
    offset: usize,
    /// Первая запись потока ещё не проверена на сходство с TLS.
    first_record: bool,
    /// После ChangeCipherSpec записи не интерпретируются.
    opaque: bool,
    /// Выдан HelloRetryRequest, второй ServerHello ещё не получен:
    /// ChangeCipherSpec не включает `opaque`.
    awaiting_retry: bool,
    /// Первый байт сообщения alert, если второй ещё не получен.
    alert_first: Option<u8>,
    /// Последнее собранное сообщение alert.
    alert: [u8; ALERT_LEN],
    /// Число подряд идущих пустых записей, для которых пустое тело допустимо.
    empty_run: usize,
    /// Окончательная ошибка.
    failed: Option<ParseError>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(ParseLimits::default())
    }
}

impl Decoder {
    /// Декодер с заданными лимитами.
    #[must_use]
    pub fn new(limits: ParseLimits) -> Self {
        Self {
            limits,
            record: Vec::new(),
            header: None,
            fragment_pos: 0,
            release_record: false,
            handshake: Vec::new(),
            handshake_len: None,
            release_handshake: false,
            offset: 0,
            first_record: true,
            opaque: false,
            awaiting_retry: false,
            alert_first: None,
            alert: [0; ALERT_LEN],
            empty_run: 0,
            failed: None,
        }
    }

    /// Лимиты декодера.
    #[must_use]
    pub fn limits(&self) -> &ParseLimits {
        &self.limits
    }

    /// Истина, если получен ChangeCipherSpec и записи возвращаются как
    /// [`Event::Opaque`]. ChangeCipherSpec, пришедший между
    /// HelloRetryRequest и вторым ServerHello, этот режим не включает.
    #[must_use]
    pub fn is_opaque(&self) -> bool {
        self.opaque
    }

    /// Истина, если выдан HelloRetryRequest, а второй ServerHello ещё не
    /// получен. В этом состоянии ChangeCipherSpec не включает режим
    /// [`Event::Opaque`].
    #[must_use]
    pub fn awaits_second_hello(&self) -> bool {
        self.awaiting_retry
    }

    /// Ручное переопределение: снова интерпретировать записи после
    /// ChangeCipherSpec.
    ///
    /// После HelloRetryRequest вызывать метод не требуется: декодер
    /// распознаёт HRR сам, см. документацию модуля. Вызов до или после CCS,
    /// следующего за HRR, ничего не ломает: ожидание второго ServerHello он
    /// не сбрасывает. Метод нужен вызывающему коду, который по своим данным
    /// знает, что записи после CCS не зашифрованы.
    pub fn resume_plaintext(&mut self) {
        self.opaque = false;
    }

    /// Сколько байтов потока декодер забрал из входа с начала работы.
    #[must_use]
    pub fn stream_offset(&self) -> usize {
        self.offset.saturating_add(self.record.len())
    }

    /// Истина, если нет недополученной записи, недособранного
    /// handshake-сообщения и половины сообщения alert. Если поток закрылся,
    /// а декодер не в этом состоянии, ответ обрезан.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        let record_done = self.release_record
            || self.record.is_empty()
            || self.header.is_some_and(|header| {
                let fragment_len = usize::from(header.length);
                self.record.len() == RECORD_HEADER_LEN.saturating_add(fragment_len)
                    && self.fragment_pos == fragment_len
            });
        let handshake_done = self.release_handshake || self.handshake.is_empty();
        record_done && handshake_done && self.alert_first.is_none()
    }

    /// Забирает из `input` байты до следующего события.
    ///
    /// `input` сдвигается на число забранных байтов. Если возвращено событие,
    /// отличное от [`Event::NeedMore`], во входе могли остаться байты: вызов
    /// надо повторять с тем же `input`, пока не вернётся `NeedMore`.
    ///
    /// # Errors
    ///
    /// - [`ParseError::NotTls`] — начало потока не похоже на TLS-запись;
    /// - [`ParseError::LimitExceeded`] — длина записи или handshake-сообщения,
    ///   общий объём потока либо число подряд идущих пустых записей больше
    ///   лимита;
    /// - [`ParseError::InvalidValue`] — версия записи с major, отличным от 3,
    ///   некорректное тело ChangeCipherSpec, пустая запись handshake или
    ///   alert, запись другого типа посреди handshake-сообщения или
    ///   сообщения alert;
    /// - [`ParseError::Internal`] — нарушен внутренний инвариант декодера.
    ///
    /// Позиция в ошибке — смещение в потоке. После ошибки декодер
    /// возвращает её же на каждый следующий вызов.
    pub fn feed(&mut self, input: &mut &[u8]) -> Result<Event<'_>, ParseError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let step = match self.advance(input) {
            Ok(step) => step,
            Err(error) => {
                self.failed = Some(error);
                return Err(error);
            }
        };
        if let Some(error) = self.invariant_error(step) {
            self.failed = Some(error);
            return Err(error);
        }
        self.event(step)
    }

    /// Проверяет, что буферы соответствуют результату шага. Нарушение —
    /// дефект декодера; оно возвращается ошибкой, а не паникой.
    fn invariant_error(&self, step: Step) -> Option<ParseError> {
        let what = match step {
            Step::Handshake if self.handshake.len() < HANDSHAKE_HEADER_LEN => {
                BROKEN_HANDSHAKE_EVENT
            }
            Step::Opaque if self.header.is_none() => BROKEN_OPAQUE_EVENT,
            _ => return None,
        };
        Some(self.internal(what))
    }

    /// Внутренняя ошибка с текущим смещением в потоке.
    fn internal(&self, what: &'static str) -> ParseError {
        ParseError::Internal {
            position: self.offset,
            what,
        }
    }

    /// Строит событие из буферов по результату шага.
    fn event(&self, step: Step) -> Result<Event<'_>, ParseError> {
        match step {
            Step::NeedMore => Ok(Event::NeedMore),
            Step::Handshake => {
                let raw = self.handshake.as_slice();
                match (raw.first(), raw.get(HANDSHAKE_HEADER_LEN..)) {
                    (Some(msg_type), Some(body)) => Ok(Event::Handshake(HandshakeMessage {
                        msg_type: HandshakeType(*msg_type),
                        body,
                        raw,
                    })),
                    _ => Err(self.internal(BROKEN_HANDSHAKE_EVENT)),
                }
            }
            Step::Alert => Ok(Event::Alert(&self.alert)),
            Step::ChangeCipherSpec => Ok(Event::ChangeCipherSpec),
            Step::ApplicationData => Ok(Event::ApplicationData(self.fragment())),
            Step::Opaque => match self.header {
                Some(header) => Ok(Event::Opaque(Record {
                    content_type: header.content_type,
                    version: header.version,
                    fragment: self.fragment(),
                })),
                None => Err(self.internal(BROKEN_OPAQUE_EVENT)),
            },
        }
    }

    /// Тело текущей записи.
    fn fragment(&self) -> &[u8] {
        self.record.get(RECORD_HEADER_LEN..).unwrap_or(&[])
    }

    /// Освобождает текущую запись и переходит к следующей.
    fn finish_record(&mut self) {
        self.offset = self.offset.saturating_add(self.record.len());
        self.record.clear();
        self.header = None;
        self.fragment_pos = 0;
        self.release_record = false;
    }

    fn advance(&mut self, input: &mut &[u8]) -> Result<Step, ParseError> {
        if self.release_handshake {
            self.handshake.clear();
            self.handshake_len = None;
            self.release_handshake = false;
        }
        if self.release_record {
            self.finish_record();
        }

        loop {
            let header = match self.header {
                Some(header) => header,
                None => {
                    take_into(&mut self.record, input, RECORD_HEADER_LEN);
                    if self.first_record {
                        self.sniff(input)?;
                    }
                    if self.record.len() < RECORD_HEADER_LEN {
                        return Ok(Step::NeedMore);
                    }
                    let offset = self.offset;
                    let mut reader = Reader::new(&self.record);
                    let header = RecordHeader::parse(&mut reader, &self.limits)
                        .map_err(|error| error.offset_by(offset))?;
                    if header.version.major() != 3 {
                        return Err(ParseError::InvalidValue {
                            position: offset.saturating_add(1),
                            what: "старший байт версии записи не равен 3",
                        });
                    }
                    // Общий объём проверяется по заявленному концу записи, до
                    // получения её тела.
                    let end = offset
                        .saturating_add(RECORD_HEADER_LEN)
                        .saturating_add(usize::from(header.length));
                    self.limits.check_total_bytes(end, offset)?;
                    self.first_record = false;
                    self.header = Some(header);
                    header
                }
            };

            let fragment_len = usize::from(header.length);
            let total = RECORD_HEADER_LEN.saturating_add(fragment_len);
            take_into(&mut self.record, input, total);
            if self.record.len() < total {
                return Ok(Step::NeedMore);
            }

            // Типы, пустое тело которых — ошибка само по себе; в режиме
            // Opaque тип записи не интерпретируется.
            let strict_type = !self.opaque
                && matches!(
                    header.content_type,
                    ContentType::HANDSHAKE | ContentType::ALERT | ContentType::CHANGE_CIPHER_SPEC
                );
            if fragment_len != 0 {
                self.empty_run = 0;
            } else if !strict_type {
                self.empty_run = self.empty_run.saturating_add(1);
                self.limits
                    .check_empty_records(self.empty_run, self.offset)?;
            }

            if self.opaque {
                self.release_record = true;
                return Ok(Step::Opaque);
            }

            if header.content_type != ContentType::HANDSHAKE && !self.handshake.is_empty() {
                return Err(ParseError::InvalidValue {
                    position: self.offset,
                    what: "запись другого типа посреди handshake-сообщения",
                });
            }
            if header.content_type != ContentType::ALERT && self.alert_first.is_some() {
                return Err(ParseError::InvalidValue {
                    position: self.offset,
                    what: "запись другого типа посреди сообщения alert",
                });
            }

            match header.content_type {
                ContentType::HANDSHAKE => {
                    if fragment_len == 0 {
                        // RFC 8446, раздел 5.1: «Implementations MUST NOT
                        // send zero-length fragments of Handshake types, even
                        // if those fragments contain padding». Для TLS 1.2 —
                        // RFC 5246, раздел 6.2.1: «Implementations MUST NOT
                        // send zero-length fragments of Handshake, Alert, or
                        // ChangeCipherSpec content types».
                        return Err(ParseError::InvalidValue {
                            position: self.offset.saturating_add(3),
                            what: "пустая запись handshake",
                        });
                    }
                    if let Some(step) = self.pump_handshake()? {
                        return Ok(step);
                    }
                    self.finish_record();
                }
                ContentType::ALERT => {
                    if fragment_len == 0 {
                        // RFC 5246, раздел 6.2.1 (цитата выше); в TLS 1.3
                        // запись alert содержит ровно одно сообщение
                        // (RFC 8446, раздел 5.1).
                        return Err(ParseError::InvalidValue {
                            position: self.offset.saturating_add(3),
                            what: "пустая запись alert",
                        });
                    }
                    if let Some(step) = self.pump_alert() {
                        return Ok(step);
                    }
                    self.finish_record();
                }
                ContentType::CHANGE_CIPHER_SPEC => {
                    self.release_record = true;
                    if self.fragment() != [0x01] {
                        return Err(ParseError::InvalidValue {
                            position: self.offset.saturating_add(RECORD_HEADER_LEN),
                            what: "тело ChangeCipherSpec не равно одному байту 0x01",
                        });
                    }
                    // После HelloRetryRequest второй ServerHello приходит
                    // открытым текстом: CCS режим Opaque не включает.
                    if !self.awaiting_retry {
                        self.opaque = true;
                    }
                    return Ok(Step::ChangeCipherSpec);
                }
                ContentType::APPLICATION_DATA => {
                    self.release_record = true;
                    return Ok(Step::ApplicationData);
                }
                _ => {
                    self.release_record = true;
                    return Ok(Step::Opaque);
                }
            }
        }
    }

    /// Проверяет начало первой записи на сходство с TLS по уже полученным
    /// байтам заголовка.
    fn sniff(&self, input: &[u8]) -> Result<(), ParseError> {
        let type_ok = self
            .record
            .first()
            .is_none_or(|byte| ContentType(*byte).is_known());
        let major_ok = self.record.get(1).is_none_or(|byte| *byte == 3);
        if type_ok && major_ok {
            return Ok(());
        }

        let mut prefix = [0_u8; NOT_TLS_PREFIX_LEN];
        let mut prefix_len = 0_usize;
        for (slot, byte) in prefix
            .iter_mut()
            .zip(self.record.iter().chain(input.iter()))
        {
            *slot = *byte;
            prefix_len = prefix_len.saturating_add(1);
        }
        Err(ParseError::NotTls {
            position: self.offset,
            prefix,
            prefix_len,
        })
    }

    /// Переносит байты тела текущей записи в буфер сообщения. Возвращает
    /// `Some(Step::Handshake)`, когда сообщение собрано, и `None`, когда тело
    /// записи исчерпано.
    fn pump_handshake(&mut self) -> Result<Option<Step>, ParseError> {
        loop {
            let fragment_pos = self.fragment_pos;
            let rest = self
                .record
                .get(RECORD_HEADER_LEN..)
                .and_then(|fragment| fragment.get(fragment_pos..))
                .unwrap_or(&[]);
            if rest.is_empty() {
                return Ok(None);
            }

            let target = self.handshake_len.unwrap_or(HANDSHAKE_HEADER_LEN);
            let needed = target.saturating_sub(self.handshake.len());
            let count = needed.min(rest.len());
            self.handshake
                .extend_from_slice(rest.get(..count).unwrap_or(&[]));
            self.fragment_pos = fragment_pos.saturating_add(count);
            if self.handshake.len() < target {
                return Ok(None);
            }

            if self.handshake_len.is_none() {
                let mut reader = Reader::new(&self.handshake);
                reader.skip(1)?;
                let body_len = usize::try_from(reader.u24()?).unwrap_or(usize::MAX);
                // Смещение поля длины в потоке, если заголовок сообщения не
                // разбит между записями; иначе — близкое к нему.
                let position = self
                    .offset
                    .saturating_add(RECORD_HEADER_LEN)
                    .saturating_add(self.fragment_pos)
                    .saturating_sub(3);
                self.limits.check_handshake_len(body_len, position)?;
                self.handshake_len = Some(HANDSHAKE_HEADER_LEN.saturating_add(body_len));
            }

            if self.handshake_len == Some(self.handshake.len()) {
                if let Some(retry) = hello_retry_state(&self.handshake) {
                    self.awaiting_retry = retry;
                }
                self.release_handshake = true;
                return Ok(Some(Step::Handshake));
            }
        }
    }

    /// Переносит байты тела текущей записи alert в буфер сообщения.
    /// Возвращает `Some(Step::Alert)` на каждые два байта и `None`, когда
    /// тело записи исчерпано.
    fn pump_alert(&mut self) -> Option<Step> {
        loop {
            let index = RECORD_HEADER_LEN.saturating_add(self.fragment_pos);
            let byte = *self.record.get(index)?;
            self.fragment_pos = self.fragment_pos.saturating_add(1);
            match self.alert_first.take() {
                None => self.alert_first = Some(byte),
                Some(first) => {
                    self.alert = [first, byte];
                    return Some(Step::Alert);
                }
            }
        }
    }
}

/// Для сообщения `server_hello` — является ли оно HelloRetryRequest; `None`
/// для сообщений других типов. `raw` — сообщение с заголовком. Слишком
/// короткий `server_hello` не считается HRR.
fn hello_retry_state(raw: &[u8]) -> Option<bool> {
    let mut reader = Reader::new(raw);
    let msg_type = reader.u8().ok().map(HandshakeType);
    if msg_type != Some(HandshakeType::SERVER_HELLO) {
        return None;
    }
    let random = server_hello_random(&mut reader);
    Some(random.is_ok_and(|random| random == HELLO_RETRY_REQUEST_RANDOM))
}

/// Читает `random` из `server_hello`; читатель стоит сразу после байта типа
/// сообщения.
fn server_hello_random(reader: &mut Reader<'_>) -> Result<[u8; RANDOM_LEN], ParseError> {
    // Длина сообщения (3 байта) и legacy_version (2 байта).
    reader.skip(3)?;
    reader.skip(2)?;
    reader.array::<RANDOM_LEN>()
}

/// Дописывает в `buffer` байты из `input`, пока длина буфера не достигнет
/// `target` или вход не закончится.
fn take_into(buffer: &mut Vec<u8>, input: &mut &[u8], target: usize) {
    let needed = target.saturating_sub(buffer.len());
    let count = needed.min(input.len());
    if let Some((head, tail)) = input.split_at_checked(count) {
        buffer.extend_from_slice(head);
        *input = tail;
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crate::codec::Writer;
    use crate::record::{
        ProtocolVersion, write_handshake_message, write_handshake_records, write_record,
    };

    /// Событие с владеющими копиями данных, для сравнения в тестах.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Owned {
        Handshake(u8, Vec<u8>),
        Alert(Vec<u8>),
        ChangeCipherSpec,
        ApplicationData(Vec<u8>),
        Opaque(u8, u16, Vec<u8>),
    }

    /// Подаёт порции в декодер и собирает события до первой ошибки.
    fn run<'a>(
        decoder: &mut Decoder,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<Owned>, ParseError> {
        let mut events = Vec::new();
        for chunk in chunks {
            let mut input = chunk;
            loop {
                let owned = match decoder.feed(&mut input)? {
                    Event::NeedMore => {
                        assert!(input.is_empty(), "NeedMore при непустом входе");
                        break;
                    }
                    Event::Handshake(message) => {
                        assert_eq!(message.raw.len(), message.body.len() + HANDSHAKE_HEADER_LEN);
                        assert_eq!(message.raw.first().copied(), Some(message.msg_type.0));
                        Owned::Handshake(message.msg_type.0, message.body.to_vec())
                    }
                    Event::Alert(body) => Owned::Alert(body.to_vec()),
                    Event::ChangeCipherSpec => Owned::ChangeCipherSpec,
                    Event::ApplicationData(body) => Owned::ApplicationData(body.to_vec()),
                    Event::Opaque(record) => Owned::Opaque(
                        record.content_type.0,
                        record.version.0,
                        record.fragment.to_vec(),
                    ),
                };
                events.push(owned);
            }
        }
        Ok(events)
    }

    fn decode_whole(stream: &[u8]) -> Result<Vec<Owned>, ParseError> {
        run(&mut Decoder::default(), [stream])
    }

    fn message(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut writer = Writer::new();
        write_handshake_message(&mut writer, HandshakeType(msg_type), body).unwrap();
        writer.as_slice().to_vec()
    }

    fn handshake_records(payload: &[u8], fragment: Option<usize>) -> Vec<u8> {
        let mut writer = Writer::new();
        write_handshake_records(
            &mut writer,
            ProtocolVersion::TLS1_2,
            payload,
            fragment.and_then(NonZeroUsize::new),
        )
        .unwrap();
        writer.as_slice().to_vec()
    }

    fn record(content_type: u8, version: u16, fragment: &[u8]) -> Vec<u8> {
        let mut writer = Writer::new();
        write_record(
            &mut writer,
            ContentType(content_type),
            ProtocolVersion(version),
            fragment,
        )
        .unwrap();
        writer.as_slice().to_vec()
    }

    fn body(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|index| seed.wrapping_add(u8::try_from(index % 251).unwrap()))
            .collect()
    }

    /// Поток: ServerHello, Certificate и ServerHelloDone в записях по 100
    /// байтов, затем alert, CCS и две непрозрачные записи.
    fn sample_stream() -> (Vec<u8>, Vec<Owned>) {
        let hello = body(70, 1);
        let certificate = body(300, 7);
        let mut payload = message(2, &hello);
        payload.extend(message(11, &certificate));
        payload.extend(message(14, &[]));

        let mut stream = handshake_records(&payload, Some(100));
        stream.extend(record(21, 0x0303, &[0x01, 0x00]));
        stream.extend(record(20, 0x0303, &[0x01]));
        stream.extend(record(22, 0x0303, &[0xDE, 0xAD, 0xBE, 0xEF]));
        stream.extend(record(23, 0x0303, &[0x99; 40]));

        let expected = vec![
            Owned::Handshake(2, hello),
            Owned::Handshake(11, certificate),
            Owned::Handshake(14, Vec::new()),
            Owned::Alert(vec![0x01, 0x00]),
            Owned::ChangeCipherSpec,
            Owned::Opaque(22, 0x0303, vec![0xDE, 0xAD, 0xBE, 0xEF]),
            Owned::Opaque(23, 0x0303, vec![0x99; 40]),
        ];
        (stream, expected)
    }

    /// Детерминированное разбиение на порции длиной от 1 до `max`.
    fn split(stream: &[u8], seed: u64, max: usize) -> Vec<&[u8]> {
        let mut state = seed;
        let mut chunks = Vec::new();
        let mut rest = stream;
        while !rest.is_empty() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let size = usize::try_from(state >> 33).unwrap() % max + 1;
            let (head, tail) = rest.split_at(size.min(rest.len()));
            chunks.push(head);
            rest = tail;
        }
        chunks
    }

    #[test]
    fn single_message_in_single_record() {
        let stream = handshake_records(&message(2, &[0xAA, 0xBB, 0xCC]), None);
        assert_eq!(
            decode_whole(&stream),
            Ok(vec![Owned::Handshake(2, vec![0xAA, 0xBB, 0xCC])])
        );
    }

    #[test]
    fn message_split_across_three_records() {
        let payload = message(11, &body(25, 3));
        let stream = handshake_records(&payload, Some(10));
        // 29 байтов сообщения по 10 — три записи.
        assert_eq!(stream.len(), payload.len() + 3 * RECORD_HEADER_LEN);
        assert_eq!(
            decode_whole(&stream),
            Ok(vec![Owned::Handshake(11, body(25, 3))])
        );
    }

    #[test]
    fn two_messages_in_one_record() {
        let mut payload = message(2, &[1_u8, 2, 3]);
        payload.extend(message(14, &[]));
        let stream = handshake_records(&payload, None);
        assert_eq!(
            decode_whole(&stream),
            Ok(vec![
                Owned::Handshake(2, vec![1_u8, 2, 3]),
                Owned::Handshake(14, Vec::new())
            ])
        );
    }

    #[test]
    fn handshake_header_split_between_records() {
        // Заголовок сообщения разрезан после второго байта.
        let payload = message(2, &[7_u8, 8, 9]);
        let mut stream = record(22, 0x0301, &payload[..2]);
        stream.extend(record(22, 0x0301, &payload[2..]));
        assert_eq!(
            decode_whole(&stream),
            Ok(vec![Owned::Handshake(2, vec![7_u8, 8, 9])])
        );
    }

    #[test]
    fn empty_handshake_record_is_rejected() {
        // Первая запись потока.
        let stream = record(22, 0x0303, &[]);
        assert_eq!(
            decode_whole(&stream),
            Err(ParseError::InvalidValue {
                position: 3,
                what: "пустая запись handshake",
            })
        );

        // После целого сообщения и посреди сообщения, по одному байту.
        let payload = message(11, &body(10, 0));
        for cut in [payload.len(), 6] {
            let mut stream = record(22, 0x0303, &payload[..cut]);
            let second = stream.len();
            stream.extend(record(22, 0x0303, &[]));
            stream.extend(record(22, 0x0303, &payload[cut..]));
            assert_eq!(
                run(&mut Decoder::default(), stream.chunks(1)).unwrap_err(),
                ParseError::InvalidValue {
                    position: second + 3,
                    what: "пустая запись handshake",
                }
            );
        }
    }

    #[test]
    fn whole_stream_at_once() {
        let (stream, expected) = sample_stream();
        assert_eq!(decode_whole(&stream), Ok(expected));
    }

    #[test]
    fn byte_by_byte() {
        let (stream, expected) = sample_stream();
        let mut decoder = Decoder::default();
        let events = run(&mut decoder, stream.chunks(1)).unwrap();
        assert_eq!(events, expected);
        assert!(decoder.is_idle());
        assert_eq!(decoder.stream_offset(), stream.len());
    }

    #[test]
    fn deterministic_random_splits() {
        let (stream, expected) = sample_stream();
        for seed in 0..64_u64 {
            for max in [2_usize, 3, 7, 16, 97, 400] {
                let chunks = split(&stream, seed, max);
                assert_eq!(chunks.concat(), stream);
                let events = run(&mut Decoder::default(), chunks).unwrap();
                assert_eq!(events, expected, "seed {seed}, max {max}");
            }
        }
    }

    #[test]
    fn need_more_and_idle_state() {
        let stream = handshake_records(&message(2, &[1_u8, 2, 3, 4]), None);
        let mut decoder = Decoder::default();
        assert!(decoder.is_idle());

        let mut input: &[u8] = &[];
        assert_eq!(decoder.feed(&mut input), Ok(Event::NeedMore));
        assert!(decoder.is_idle());

        // Запись получена не полностью: ответ обрезан.
        let mut input = &stream[..stream.len() - 1];
        assert_eq!(decoder.feed(&mut input), Ok(Event::NeedMore));
        assert!(input.is_empty());
        assert!(!decoder.is_idle());

        let mut input = &stream[stream.len() - 1..];
        assert!(matches!(decoder.feed(&mut input), Ok(Event::Handshake(_))));
        assert!(decoder.is_idle());
        assert_eq!(decoder.feed(&mut input), Ok(Event::NeedMore));

        // Запись целая, сообщение внутри неё — нет.
        let partial = record(22, 0x0303, &[0x0B, 0x00, 0x00, 0x05, 0x01]);
        let mut decoder = Decoder::default();
        assert_eq!(run(&mut decoder, [partial.as_slice()]), Ok(Vec::new()));
        assert!(!decoder.is_idle());
    }

    #[test]
    fn record_over_limit() {
        // Первая запись корректна, вторая заявляет 18433 байта.
        let mut stream = handshake_records(&message(14, &[]), None);
        let second = stream.len();
        stream.extend([0x17, 0x03, 0x03, 0x48, 0x01]);
        let mut decoder = Decoder::default();
        let expected = ParseError::LimitExceeded {
            position: second + 3,
            limit: "max_record_len",
            max: 18_432,
            actual: 18_433,
        };
        assert_eq!(run(&mut decoder, [stream.as_slice()]), Err(expected));

        // Ошибка окончательная.
        let mut more: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(decoder.feed(&mut more), Err(expected));
        assert_eq!(more.len(), 5, "после ошибки вход не забирается");
    }

    #[test]
    fn record_at_limit_is_accepted() {
        let limits = ParseLimits {
            max_record_len: 8,
            max_handshake_len: 64,
            ..ParseLimits::default()
        };
        let stream = record(23, 0x0303, &[0x55; 8]);
        assert_eq!(
            run(&mut Decoder::new(limits), [stream.as_slice()]),
            Ok(vec![Owned::ApplicationData(vec![0x55; 8])])
        );
        let stream = record(23, 0x0303, &[0x55; 9]);
        assert_eq!(
            run(&mut Decoder::new(limits), [stream.as_slice()]),
            Err(ParseError::LimitExceeded {
                position: 3,
                limit: "max_record_len",
                max: 8,
                actual: 9,
            })
        );
    }

    #[test]
    fn handshake_over_limit_is_rejected_before_body() {
        // Заголовок сообщения заявляет 16 МиБ; тела нет вовсе.
        let stream = record(22, 0x0303, &[0x0B, 0xFF, 0xFF, 0xFF]);
        let mut decoder = Decoder::default();
        assert_eq!(
            run(&mut decoder, [stream.as_slice()]),
            Err(ParseError::LimitExceeded {
                position: 6,
                limit: "max_handshake_len",
                max: 65_536,
                actual: 0x00FF_FFFF,
            })
        );
        assert!(decoder.handshake.capacity() < 1024);

        // 65537 байтов: на единицу больше лимита; 65536 — принимается.
        let over = record(22, 0x0303, &[0x0B, 0x01, 0x00, 0x01]);
        assert!(matches!(
            decode_whole(&over),
            Err(ParseError::LimitExceeded {
                limit: "max_handshake_len",
                actual: 65_537,
                ..
            })
        ));
        let exact = record(22, 0x0303, &[0x0B, 0x01, 0x00, 0x00]);
        assert_eq!(decode_whole(&exact), Ok(Vec::new()));
    }

    #[test]
    fn handshake_limit_applies_across_records() {
        let limits = ParseLimits {
            max_record_len: 16,
            max_handshake_len: 20,
            ..ParseLimits::default()
        };
        let payload = message(11, &body(20, 0));
        let stream = handshake_records(&payload, Some(16));
        assert_eq!(
            run(&mut Decoder::new(limits), [stream.as_slice()]),
            Ok(vec![Owned::Handshake(11, body(20, 0))])
        );

        let payload = message(11, &body(21, 0));
        let stream = handshake_records(&payload, Some(16));
        assert!(matches!(
            run(&mut Decoder::new(limits), stream.chunks(1)),
            Err(ParseError::LimitExceeded {
                limit: "max_handshake_len",
                max: 20,
                actual: 21,
                ..
            })
        ));
    }

    #[test]
    fn memory_does_not_follow_declared_lengths() {
        // Запись заявляет 18432 байта, сообщение — 65536; пришло 10 байтов.
        let mut decoder = Decoder::default();
        let mut input: &[u8] = &[0x16, 0x03, 0x03, 0x48, 0x00, 0x0B, 0x01, 0x00, 0x00, 0xAA];
        assert_eq!(decoder.feed(&mut input), Ok(Event::NeedMore));
        assert!(decoder.record.capacity() < 1024);
        assert!(decoder.handshake.capacity() < 1024);
        assert!(!decoder.is_idle());
    }

    #[test]
    fn buffers_stay_within_limits_on_long_stream() {
        let limits = ParseLimits {
            max_record_len: 64,
            max_handshake_len: 256,
            ..ParseLimits::default()
        };
        let mut payload = Vec::new();
        for index in 0..200_u8 {
            payload.extend(message(11, &body(200, index)));
        }
        let stream = handshake_records(&payload, Some(64));
        let mut decoder = Decoder::new(limits);
        let events = run(&mut decoder, split(&stream, 5, 300)).unwrap();
        assert_eq!(events.len(), 200);
        // Буферы не уменьшаются, поэтому их ёмкость — пиковое потребление.
        assert!(decoder.record.capacity() <= 2 * (RECORD_HEADER_LEN + 64));
        assert!(decoder.handshake.capacity() <= 2 * (HANDSHAKE_HEADER_LEN + 256));
    }

    #[test]
    fn not_tls_http_text() {
        let response = b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n";
        let error = decode_whole(response).unwrap_err();
        assert_eq!(error.position(), 0);
        assert_eq!(error.not_tls_prefix(), Some(&b"HTTP/1.1 400 Bad"[..]));
    }

    #[test]
    fn not_tls_smtp_banner_and_short_reply() {
        let error = decode_whole(b"220 mail.example.test ESMTP\r\n").unwrap_err();
        assert_eq!(error.not_tls_prefix(), Some(&b"220 mail.example"[..]));

        // Ответ короче заголовка записи распознаётся без ожидания данных.
        let error = decode_whole(b"+OK\n").unwrap_err();
        assert_eq!(error.not_tls_prefix(), Some(&b"+OK\n"[..]));
    }

    #[test]
    fn not_tls_sslv2_reply() {
        // Синтетический двухбайтовый заголовок SSLv2 и тип SERVER-HELLO.
        let reply = [0x80, 0x0B, 0x04, 0x00, 0x01, 0x00, 0x02];
        let error = decode_whole(&reply).unwrap_err();
        assert!(matches!(error, ParseError::NotTls { .. }), "{error:?}");
        assert_eq!(error.not_tls_prefix(), Some(&reply[..]));
    }

    #[test]
    fn not_tls_detected_by_version_byte() {
        // Первый байт совпал с типом handshake, версия — нет.
        let reply = [0x16, 0x02, 0x00, 0x00, 0x01, 0x00];
        let error = decode_whole(&reply).unwrap_err();
        assert_eq!(error.not_tls_prefix(), Some(&reply[..]));
    }

    #[test]
    fn not_tls_when_fed_byte_by_byte() {
        let mut decoder = Decoder::default();
        let error = run(&mut decoder, b"HTTP/1.1 200 OK\r\n".chunks(1)).unwrap_err();
        // При подаче по одному байту в момент проверки доступен один байт.
        assert_eq!(error.not_tls_prefix(), Some(&b"H"[..]));

        let mut decoder = Decoder::default();
        let error = run(&mut decoder, [0x16_u8, 0x48, 0x54].chunks(1)).unwrap_err();
        assert_eq!(error.not_tls_prefix(), Some(&[0x16_u8, 0x48][..]));
    }

    #[test]
    fn unknown_content_type_in_first_record_is_not_tls() {
        let stream = record(0x63, 0x0303, &[1_u8, 2, 3]);
        assert!(matches!(
            decode_whole(&stream),
            Err(ParseError::NotTls { prefix_len: 8, .. })
        ));
    }

    #[test]
    fn unknown_content_type_later_is_kept_as_value() {
        let mut stream = handshake_records(&message(14, &[]), None);
        stream.extend(record(0x63, 0x0303, &[1_u8, 2, 3]));
        stream.extend(record(24, 0x0302, &[4_u8, 5]));
        assert_eq!(
            decode_whole(&stream),
            Ok(vec![
                Owned::Handshake(14, Vec::new()),
                Owned::Opaque(0x63, 0x0303, vec![1_u8, 2, 3]),
                Owned::Opaque(24, 0x0302, vec![4_u8, 5]),
            ])
        );
    }

    #[test]
    fn bad_record_version_after_first_record() {
        let mut stream = record(21, 0x0303, &[0x01, 0x00]);
        let second = stream.len();
        stream.extend(record(22, 0x0403, &[0x0E, 0x00, 0x00, 0x00]));
        assert_eq!(
            decode_whole(&stream),
            Err(ParseError::InvalidValue {
                position: second + 1,
                what: "старший байт версии записи не равен 3",
            })
        );
    }

    #[test]
    fn alert_and_application_data_events() {
        let mut stream = record(21, 0x0301, &[0x02, 0x28]);
        stream.extend(record(23, 0x0303, &[]));
        // Alert, разбитый на две записи, — одно событие.
        stream.extend(record(21, 0x0303, &[0x01]));
        stream.extend(record(21, 0x0303, &[0x00]));
        for chunk in [stream.len(), 1] {
            let mut decoder = Decoder::default();
            assert_eq!(
                run(&mut decoder, stream.chunks(chunk)),
                Ok(vec![
                    Owned::Alert(vec![0x02, 0x28]),
                    Owned::ApplicationData(Vec::new()),
                    Owned::Alert(vec![0x01, 0x00]),
                ])
            );
            assert!(decoder.is_idle());
            assert_eq!(decoder.stream_offset(), stream.len());
        }
    }

    #[test]
    fn several_alerts_in_one_record() {
        // Три alert в одной записи и четвёртый, начатый в ней же.
        let mut stream = record(21, 0x0303, &[0x01, 0x00, 0x02, 0x28, 0x01, 0x5A, 0x02]);
        stream.extend(record(21, 0x0303, &[0x46]));
        for chunk in [stream.len(), 1, 3] {
            let mut decoder = Decoder::default();
            assert_eq!(
                run(&mut decoder, stream.chunks(chunk)),
                Ok(vec![
                    Owned::Alert(vec![0x01, 0x00]),
                    Owned::Alert(vec![0x02, 0x28]),
                    Owned::Alert(vec![0x01, 0x5A]),
                    Owned::Alert(vec![0x02, 0x46]),
                ])
            );
            assert!(decoder.is_idle());
        }
    }

    #[test]
    fn half_alert_is_not_idle() {
        let stream = record(21, 0x0303, &[0x02]);
        let mut decoder = Decoder::default();
        assert_eq!(run(&mut decoder, [stream.as_slice()]), Ok(Vec::new()));
        assert!(!decoder.is_idle());
        assert_eq!(decoder.stream_offset(), stream.len());
    }

    #[test]
    fn empty_alert_record_is_rejected() {
        let stream = record(21, 0x0303, &[]);
        assert_eq!(
            decode_whole(&stream),
            Err(ParseError::InvalidValue {
                position: 3,
                what: "пустая запись alert",
            })
        );

        // Пустая запись между половинами alert — тоже ошибка.
        let mut stream = record(21, 0x0303, &[0x02]);
        let second = stream.len();
        stream.extend(record(21, 0x0303, &[]));
        stream.extend(record(21, 0x0303, &[0x28]));
        assert_eq!(
            decode_whole(&stream),
            Err(ParseError::InvalidValue {
                position: second + 3,
                what: "пустая запись alert",
            })
        );
    }

    #[test]
    fn other_record_inside_alert_message() {
        for other in [
            record(22, 0x0303, &message(14, &[])),
            record(20, 0x0303, &[0x01]),
            record(23, 0x0303, &[0x55]),
            record(24, 0x0303, &[0x55]),
        ] {
            let mut stream = record(21, 0x0303, &[0x02]);
            let second = stream.len();
            stream.extend(other);
            stream.extend(record(21, 0x0303, &[0x28]));
            assert_eq!(
                decode_whole(&stream),
                Err(ParseError::InvalidValue {
                    position: second,
                    what: "запись другого типа посреди сообщения alert",
                })
            );
        }
    }

    #[test]
    fn change_cipher_spec_makes_following_records_opaque() {
        let mut stream = handshake_records(&message(2, &[1_u8]), None);
        stream.extend(record(20, 0x0303, &[0x01]));
        stream.extend(record(21, 0x0303, &[0xAA; 26]));
        let mut decoder = Decoder::default();
        assert!(!decoder.is_opaque());
        assert_eq!(
            run(&mut decoder, [stream.as_slice()]),
            Ok(vec![
                Owned::Handshake(2, vec![1_u8]),
                Owned::ChangeCipherSpec,
                Owned::Opaque(21, 0x0303, vec![0xAA; 26]),
            ])
        );
        assert!(decoder.is_opaque());
    }

    #[test]
    fn resume_plaintext_is_manual_override() {
        // Сообщение типа server_hello с коротким телом HRR не является:
        // CCS включает Opaque, resume_plaintext его снимает.
        let mut first = handshake_records(&message(2, &[0xCF]), None);
        first.extend(record(20, 0x0303, &[0x01]));
        let second = handshake_records(&message(2, &[0x5E]), None);

        let mut decoder = Decoder::default();
        assert_eq!(
            run(&mut decoder, [first.as_slice()]),
            Ok(vec![
                Owned::Handshake(2, vec![0xCF]),
                Owned::ChangeCipherSpec
            ])
        );
        decoder.resume_plaintext();
        assert!(!decoder.is_opaque());
        assert_eq!(
            run(&mut decoder, [second.as_slice()]),
            Ok(vec![Owned::Handshake(2, vec![0x5E])])
        );

        // Без вызова resume_plaintext та же запись непрозрачна.
        let mut decoder = Decoder::default();
        run(&mut decoder, [first.as_slice()]).unwrap();
        assert!(matches!(
            run(&mut decoder, [second.as_slice()]).unwrap().as_slice(),
            [Owned::Opaque(22, 0x0303, _)]
        ));
    }

    #[test]
    fn malformed_change_cipher_spec() {
        for fragment in [&[][..], &[0x02][..], &[0x01, 0x01][..]] {
            let stream = record(20, 0x0303, fragment);
            assert_eq!(
                decode_whole(&stream),
                Err(ParseError::InvalidValue {
                    position: RECORD_HEADER_LEN,
                    what: "тело ChangeCipherSpec не равно одному байту 0x01",
                })
            );
        }
    }

    #[test]
    fn other_record_inside_handshake_message() {
        let payload = message(11, &body(10, 0));
        let mut stream = record(22, 0x0303, &payload[..6]);
        let second = stream.len();
        stream.extend(record(21, 0x0303, &[0x01, 0x00]));
        stream.extend(record(22, 0x0303, &payload[6..]));
        assert_eq!(
            decode_whole(&stream),
            Err(ParseError::InvalidValue {
                position: second,
                what: "запись другого типа посреди handshake-сообщения",
            })
        );
    }

    #[test]
    fn limits_accessor() {
        let limits = ParseLimits {
            max_record_len: 1,
            max_handshake_len: 2,
            max_total_bytes: 3,
            max_empty_records: 4,
            max_certificates: 5,
            max_certificate_len: 6,
        };
        assert_eq!(Decoder::new(limits).limits(), &limits);
        assert_eq!(Decoder::default().limits(), &ParseLimits::default());
    }

    /// Тело ServerHello с заданным `random`: пустой session_id, шифр
    /// 0x1301, без сжатия, пустой список расширений.
    fn hello_body(random: [u8; RANDOM_LEN]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend(random);
        body.extend([0x00, 0x13, 0x01, 0x00, 0x00, 0x00]);
        body
    }

    /// Обмен с HelloRetryRequest по частям: HRR, CCS, второй ServerHello,
    /// CCS, зашифрованная запись — и ожидаемые события.
    fn retry_exchange() -> (Vec<Vec<u8>>, Vec<Owned>) {
        let retry = hello_body(HELLO_RETRY_REQUEST_RANDOM);
        let hello = hello_body([0x5A; RANDOM_LEN]);
        let parts = vec![
            handshake_records(&message(2, &retry), None),
            record(20, 0x0303, &[0x01]),
            handshake_records(&message(2, &hello), None),
            record(20, 0x0303, &[0x01]),
            record(23, 0x0303, &[0xAA; 24]),
        ];
        let expected = vec![
            Owned::Handshake(2, retry),
            Owned::ChangeCipherSpec,
            Owned::Handshake(2, hello),
            Owned::ChangeCipherSpec,
            Owned::Opaque(23, 0x0303, vec![0xAA; 24]),
        ];
        (parts, expected)
    }

    #[test]
    fn hello_retry_request_and_ccs_in_one_chunk() {
        let (parts, expected) = retry_exchange();
        let stream = parts.concat();
        let mut decoder = Decoder::default();
        assert_eq!(run(&mut decoder, [stream.as_slice()]), Ok(expected));
        assert!(decoder.is_opaque());
        assert!(!decoder.awaits_second_hello());
        assert!(decoder.is_idle());
    }

    #[test]
    fn ccs_in_separate_chunk_after_hello_retry_request() {
        let (parts, expected) = retry_exchange();
        let mut decoder = Decoder::default();
        assert!(!decoder.awaits_second_hello());

        assert_eq!(
            run(&mut decoder, parts[..1].iter().map(Vec::as_slice)).as_deref(),
            Ok(&expected[..1])
        );
        assert!(decoder.awaits_second_hello());
        assert!(!decoder.is_opaque());

        assert_eq!(
            run(&mut decoder, parts[1..2].iter().map(Vec::as_slice)),
            Ok(vec![Owned::ChangeCipherSpec])
        );
        assert!(decoder.awaits_second_hello());
        assert!(!decoder.is_opaque());

        assert_eq!(
            run(&mut decoder, parts[2..3].iter().map(Vec::as_slice)).as_deref(),
            Ok(&expected[2..3])
        );
        assert!(!decoder.awaits_second_hello());
        assert!(!decoder.is_opaque());

        assert_eq!(
            run(&mut decoder, parts[3..].iter().map(Vec::as_slice)).as_deref(),
            Ok(&expected[3..])
        );
        assert!(decoder.is_opaque());
    }

    #[test]
    fn resume_plaintext_before_ccs_after_hello_retry_request() {
        // Вызов resume_plaintext до того, как декодер прочитал CCS, раньше
        // приводил к потере второго ServerHello.
        let (parts, expected) = retry_exchange();
        let mut decoder = Decoder::default();
        assert_eq!(
            run(&mut decoder, parts[..1].iter().map(Vec::as_slice)).as_deref(),
            Ok(&expected[..1])
        );
        decoder.resume_plaintext();
        assert!(decoder.awaits_second_hello());
        assert_eq!(
            run(&mut decoder, parts[1..].iter().map(Vec::as_slice)).as_deref(),
            Ok(&expected[1..])
        );

        // Вызов после CCS тоже ничего не ломает.
        let mut decoder = Decoder::default();
        assert_eq!(
            run(&mut decoder, parts[..2].iter().map(Vec::as_slice)).as_deref(),
            Ok(&expected[..2])
        );
        decoder.resume_plaintext();
        assert_eq!(
            run(&mut decoder, parts[2..].iter().map(Vec::as_slice)).as_deref(),
            Ok(&expected[2..])
        );
    }

    #[test]
    fn hello_retry_request_byte_by_byte_and_random_splits() {
        let (parts, expected) = retry_exchange();
        let stream = parts.concat();
        let mut decoder = Decoder::default();
        assert_eq!(run(&mut decoder, stream.chunks(1)).as_ref(), Ok(&expected));
        assert!(decoder.is_idle());
        assert_eq!(decoder.stream_offset(), stream.len());

        for seed in 0..32_u64 {
            for max in [2_usize, 5, 40] {
                let events = run(&mut Decoder::default(), split(&stream, seed, max));
                assert_eq!(events.as_ref(), Ok(&expected), "seed {seed}, max {max}");
            }
        }
    }

    #[test]
    fn second_hello_retry_request_keeps_waiting() {
        // Сервер-нарушитель: два HRR подряд. Оба выдаются событиями, CCS
        // между ними и после них Opaque не включает; после настоящего
        // ServerHello CCS включает Opaque.
        let (parts, expected) = retry_exchange();
        let mut stream = parts[..2].concat();
        stream.extend(parts.concat());
        let mut events = expected[..2].to_vec();
        events.extend(expected);

        for chunk in [stream.len(), 1] {
            let mut decoder = Decoder::default();
            assert_eq!(
                run(&mut decoder, stream.chunks(chunk)).as_ref(),
                Ok(&events)
            );
            assert!(decoder.is_opaque());
        }

        // Состояние после второго HRR.
        let mut decoder = Decoder::default();
        let mut prefix = parts[..2].concat();
        prefix.extend(parts[..2].concat());
        run(&mut decoder, [prefix.as_slice()]).unwrap();
        assert!(decoder.awaits_second_hello());
        assert!(!decoder.is_opaque());
    }

    #[test]
    fn regular_handshakes_are_unchanged_by_retry_detection() {
        let hello = hello_body([0x5A; RANDOM_LEN]);

        // TLS 1.3: ServerHello, CCS, зашифрованные записи.
        let mut stream = handshake_records(&message(2, &hello), None);
        stream.extend(record(20, 0x0303, &[0x01]));
        stream.extend(record(23, 0x0303, &[0xAA; 30]));
        let mut decoder = Decoder::default();
        assert_eq!(
            run(&mut decoder, [stream.as_slice()]),
            Ok(vec![
                Owned::Handshake(2, hello.clone()),
                Owned::ChangeCipherSpec,
                Owned::Opaque(23, 0x0303, vec![0xAA; 30]),
            ])
        );
        assert!(!decoder.awaits_second_hello());

        // TLS 1.2: ServerHello … ServerHelloDone, затем CCS и Finished.
        let mut payload = message(2, &hello);
        payload.extend(message(14, &[]));
        let mut stream = handshake_records(&payload, None);
        stream.extend(record(20, 0x0303, &[0x01]));
        stream.extend(record(22, 0x0303, &[0xBB; 40]));
        assert_eq!(
            decode_whole(&stream),
            Ok(vec![
                Owned::Handshake(2, hello),
                Owned::Handshake(14, Vec::new()),
                Owned::ChangeCipherSpec,
                Owned::Opaque(22, 0x0303, vec![0xBB; 40]),
            ])
        );
    }

    #[test]
    fn hello_retry_state_reads_random() {
        let retry = message(2, &hello_body(HELLO_RETRY_REQUEST_RANDOM));
        assert_eq!(hello_retry_state(&retry), Some(true));

        let mut random = HELLO_RETRY_REQUEST_RANDOM;
        random[RANDOM_LEN - 1] ^= 0x01;
        assert_eq!(
            hello_retry_state(&message(2, &hello_body(random))),
            Some(false)
        );

        // Короткий server_hello — не HRR; другой тип сообщения — None.
        assert_eq!(hello_retry_state(&message(2, &[0x03, 0x03])), Some(false));
        assert_eq!(hello_retry_state(&retry[..20]), Some(false));
        let other = message(11, &hello_body(HELLO_RETRY_REQUEST_RANDOM));
        assert_eq!(hello_retry_state(&other), None);
        assert_eq!(hello_retry_state(&[]), None);
    }

    #[test]
    fn total_bytes_limit() {
        let limits = ParseLimits {
            max_total_bytes: 20,
            ..ParseLimits::default()
        };

        // Две записи заканчиваются ровно на лимите.
        let mut stream = record(23, 0x0303, &[0x55; 10]);
        stream.extend(record(23, 0x0303, &[]));
        let mut decoder = Decoder::new(limits);
        assert_eq!(
            run(&mut decoder, [stream.as_slice()]),
            Ok(vec![
                Owned::ApplicationData(vec![0x55; 10]),
                Owned::ApplicationData(Vec::new()),
            ])
        );
        assert_eq!(decoder.stream_offset(), 20);

        // Любая следующая запись выходит за лимит уже своим заголовком.
        let mut input: &[u8] = &[0x17, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(
            decoder.feed(&mut input),
            Err(ParseError::LimitExceeded {
                position: 20,
                limit: "max_total_bytes",
                max: 20,
                actual: 25,
            })
        );

        // Лимит срабатывает по заявленной длине, до получения тела.
        let mut decoder = Decoder::new(limits);
        let mut input: &[u8] = &[0x17, 0x03, 0x03, 0x00, 0x10];
        assert_eq!(
            decoder.feed(&mut input),
            Err(ParseError::LimitExceeded {
                position: 0,
                limit: "max_total_bytes",
                max: 20,
                actual: 21,
            })
        );
    }

    #[test]
    fn total_bytes_limit_on_long_stream() {
        // Значение по умолчанию — 1 МиБ; записи по 16 КиБ.
        let chunk = record(23, 0x0303, &vec![0x55; 16_384]);
        let fits = 1_048_576 / chunk.len();
        let mut decoder = Decoder::default();
        for _ in 0..fits {
            assert_eq!(
                run(&mut decoder, [chunk.as_slice()]).map(|events| events.len()),
                Ok(1)
            );
        }
        let error = run(&mut decoder, [chunk.as_slice()]).unwrap_err();
        assert_eq!(
            error,
            ParseError::LimitExceeded {
                position: fits * chunk.len(),
                limit: "max_total_bytes",
                max: 1_048_576,
                actual: (fits + 1) * chunk.len(),
            }
        );
    }

    #[test]
    fn thousands_of_empty_records_are_rejected() {
        let mut stream = Vec::new();
        for _ in 0..5_000 {
            stream.extend(record(23, 0x0303, &[]));
        }
        for chunk in [stream.len(), 1] {
            let mut decoder = Decoder::default();
            assert_eq!(
                run(&mut decoder, stream.chunks(chunk)),
                Err(ParseError::LimitExceeded {
                    position: 16 * RECORD_HEADER_LEN,
                    limit: "max_empty_records",
                    max: 16,
                    actual: 17,
                })
            );
            // Декодер остановился на семнадцатой записи.
            assert_eq!(decoder.stream_offset(), 17 * RECORD_HEADER_LEN);
        }
    }

    #[test]
    fn empty_records_limit_counts_consecutive_records_of_any_lenient_type() {
        let limits = ParseLimits {
            max_empty_records: 2,
            ..ParseLimits::default()
        };

        // application_data, heartbeat и неизвестный тип считаются вместе.
        let mut stream = record(23, 0x0303, &[]);
        stream.extend(record(24, 0x0303, &[]));
        assert_eq!(
            run(&mut Decoder::new(limits), [stream.as_slice()]),
            Ok(vec![
                Owned::ApplicationData(Vec::new()),
                Owned::Opaque(24, 0x0303, Vec::new()),
            ])
        );
        stream.extend(record(0x63, 0x0303, &[]));
        assert_eq!(
            run(&mut Decoder::new(limits), [stream.as_slice()]),
            Err(ParseError::LimitExceeded {
                position: 2 * RECORD_HEADER_LEN,
                limit: "max_empty_records",
                max: 2,
                actual: 3,
            })
        );

        // Непустая запись сбрасывает счётчик.
        let mut stream = Vec::new();
        for _ in 0..4 {
            stream.extend(record(23, 0x0303, &[]));
            stream.extend(record(24, 0x0303, &[]));
            stream.extend(record(23, 0x0303, &[0x55]));
        }
        assert_eq!(
            run(&mut Decoder::new(limits), [stream.as_slice()]).map(|events| events.len()),
            Ok(12)
        );
    }

    #[test]
    fn empty_records_limit_applies_in_opaque_mode() {
        // После CCS тип записи не интерпретируется: пустые записи типа
        // handshake и alert — Opaque и считаются лимитом.
        let mut stream = handshake_records(&message(2, &[1_u8]), None);
        stream.extend(record(20, 0x0303, &[0x01]));
        let prefix = stream.len();
        for _ in 0..8 {
            stream.extend(record(22, 0x0303, &[]));
            stream.extend(record(21, 0x0303, &[]));
        }
        assert_eq!(decode_whole(&stream).map(|events| events.len()), Ok(18));

        stream.extend(record(20, 0x0303, &[]));
        assert_eq!(
            decode_whole(&stream),
            Err(ParseError::LimitExceeded {
                position: prefix + 16 * RECORD_HEADER_LEN,
                limit: "max_empty_records",
                max: 16,
                actual: 17,
            })
        );
    }

    #[test]
    fn broken_invariants_are_internal_errors() {
        // Состояния недостижимы через feed; проверяется, что вместо паники
        // и вместо NeedMore возвращается ParseError::Internal.
        let decoder = Decoder::default();
        assert_eq!(
            decoder.event(Step::Opaque),
            Err(ParseError::Internal {
                position: 0,
                what: BROKEN_OPAQUE_EVENT,
            })
        );
        assert_eq!(
            decoder.event(Step::Handshake),
            Err(ParseError::Internal {
                position: 0,
                what: BROKEN_HANDSHAKE_EVENT,
            })
        );
        assert_eq!(
            decoder.invariant_error(Step::Opaque),
            decoder.event(Step::Opaque).err()
        );
        assert_eq!(
            decoder.invariant_error(Step::Handshake),
            decoder.event(Step::Handshake).err()
        );
        for step in [
            Step::NeedMore,
            Step::Alert,
            Step::ChangeCipherSpec,
            Step::ApplicationData,
        ] {
            assert_eq!(decoder.invariant_error(step), None);
            assert!(decoder.event(step).is_ok());
        }
    }
}
