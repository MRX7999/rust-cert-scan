//! Классификация исходов соединений и адаптивный backoff (AIMD) на хост.
//!
//! # Классификация исходов
//!
//! Единственное место, где исходу соединения или обмена сопоставляется
//! сигнал для backoff и circuit breaker, — [`Outcome::signal`]. Исход
//! строится из ошибки [`net::Connector::connect`]
//! ([`Outcome::from_connect_error`]) либо из причины остановки обмена
//! ([`Outcome::from_stop`]).
//!
//! | Исход | Источник в `net` | Сигнал |
//! |---|---|---|
//! | `ConditionMet` | `StopReason::ConditionMet` | [`Signal::Success`] |
//! | `FatalAlert` | `StopReason::FatalAlert` | [`Signal::Neutral`] |
//! | `EofAtMessageBoundary` | `StopReason::Eof(AtMessageBoundary)` | [`Signal::Neutral`] |
//! | `Parse` | `StopReason::Parse` | [`Signal::Neutral`] |
//! | `LimitExceeded` | `StopReason::LimitExceeded` | [`Signal::Neutral`] |
//! | `Deadline` | `StopReason::Deadline` | [`Signal::Neutral`] |
//! | `NotTls` | `StopReason::NotTls` | [`Signal::NotTls`] |
//! | `EofBeforeFirstByte` | `StopReason::Eof(BeforeFirstByte)` | [`Signal::AmbiguousEof`] |
//! | `EofMidMessage` | `StopReason::Eof(MidMessage)` | [`Signal::Overload`] |
//! | `Reset` | `StopReason::Reset` | [`Signal::Overload`] |
//! | `HandshakeTimeout` | `StopReason::HandshakeTimeout` | [`Signal::Overload`] |
//! | `ReadTimeout` | `StopReason::ReadTimeout` | [`Signal::Overload`] |
//! | `WriteFailed` | `StopReason::WriteFailed` | [`Signal::Overload`] |
//! | `Io` | `StopReason::Io` | [`Signal::Overload`] |
//! | `ConnectReset` | `ConnectErrorClass::Reset` | [`Signal::Overload`] |
//! | `ConnectTimeout` | `ConnectErrorClass::Timeout` | [`Signal::Overload`] |
//! | `ConnectUnreachable` | `ConnectErrorClass::Unreachable` | [`Signal::Overload`] |
//! | `ConnectOther` | `ConnectErrorClass::Other` | [`Signal::Overload`] |
//! | `ConnectRefused` | `ConnectErrorClass::Refused` | [`Signal::Refused`] |
//! | `ConnectUnresolved` | `ConnectErrorClass::Unresolved` | [`Signal::Unresolved`] |
//! | `LocalExhaustion` | вид ошибки ОС, см. [`is_local_exhaustion`] | [`Signal::Local`] |
//!
//! Пояснения:
//!
//! - Успех — только выполненное условие обмена: сервер ответил тем, о чём
//!   его спрашивали. Успехи восстанавливают скорость.
//! - Нейтральные исходы — штатные результаты сканирования: сервер ответил,
//!   но отказал. Fatal alert (`handshake_failure`, `protocol_version`),
//!   закрытие на границе сообщений после alert, неразборчивый или слишком
//!   длинный ответ ничего не говорят о перегрузке. Они не запускают backoff
//!   и не восстанавливают скорость, но прерывают серию неуспехов: сервер
//!   жив. Истёкший общий дедлайн — бюджет самой проверки, а не признак
//!   состояния сервера.
//! - EOF до первого байта неоднозначен: так старые стеки отвечают на
//!   неподдерживаемый hello, и так же ведут себя перегруженный сервер и
//!   средство защиты. Одиночный случай нейтрален; серия подряд — признак
//!   блокировки. Порог серии — в конфигурации breaker'а
//!   (`crate::limits::breaker`).
//! - `Refused`, `Unresolved`, `NotTls` зависят от истории хоста: первый
//!   отказ в соединении означает закрытый порт (ранний выход), отказ после
//!   удачных соединений — перегрузку. Решение принимает breaker.
//! - `Local` — нехватка ресурсов сканирующей машины; хост за неё не
//!   штрафуется, сигнал идёт в глобальный контур.
//!
//! # AIMD
//!
//! [`Aimd`] — чистый автомат без часов и ввода-вывода. При сигнале
//! перегрузки эффективный лимит соединений и скорость хоста делятся на
//! [`AimdConfig::decrease_divisor`] (не ниже одного соединения и
//! [`AimdConfig::min_rate`]), а задержка между соединениями растёт в
//! [`AimdConfig::delay_multiplier`] раз до [`AimdConfig::delay_max`]. Каждые
//! [`AimdConfig::successes_per_step`] успехов подряд лимит и скорость
//! увеличиваются на фиксированный шаг до настроенного максимума, задержка
//! уменьшается во столько же раз, во сколько росла, и обнуляется, когда
//! опускается ниже начальной.
//!
//! Если настроенная скорость хоста — [`Rate::Unlimited`], AIMD её не
//! трогает: делить нечего. Замедление в этом случае дают лимит соединений
//! и задержка.

use std::io;
use std::time::Duration;

use net::{ConnectError, ConnectErrorClass, EofKind, StopReason};

use super::token_bucket::Rate;

/// Исход соединения или обмена — вход backoff и circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Имя не разрешилось.
    ConnectUnresolved,
    /// Отказ в соединении.
    ConnectRefused,
    /// Соединение сброшено при установлении.
    ConnectReset,
    /// Таймаут установления соединения.
    ConnectTimeout,
    /// Сеть или хост недостижимы.
    ConnectUnreachable,
    /// Прочая ошибка установления соединения.
    ConnectOther,
    /// Не хватило ресурсов сканирующей машины: дескрипторов, локальных
    /// портов, памяти под сокет.
    LocalExhaustion,
    /// Условие обмена выполнено.
    ConditionMet,
    /// Сервер ответил fatal alert.
    FatalAlert,
    /// Сервер закрыл соединение до первого байта ответа.
    EofBeforeFirstByte,
    /// Сервер закрыл соединение на границе сообщений.
    EofAtMessageBoundary,
    /// Сервер закрыл соединение посреди сообщения.
    EofMidMessage,
    /// Соединение сброшено при чтении.
    Reset,
    /// После отправки пробника не пришло ни байта.
    HandshakeTimeout,
    /// Очередная порция ответа не пришла вовремя.
    ReadTimeout,
    /// Истёк общий дедлайн обмена.
    Deadline,
    /// Ответ не похож на TLS.
    NotTls,
    /// Ошибка разбора ответа.
    Parse,
    /// Превышен лимит разбора.
    LimitExceeded,
    /// Пробник отправить не удалось.
    WriteFailed,
    /// Прочая ошибка чтения.
    Io,
}

/// Число вариантов [`Outcome`].
const OUTCOMES: usize = 21;

/// Сигнал, который исход даёт backoff и circuit breaker; таблица — в
/// документации модуля.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    /// Сервер ответил тем, о чём его спрашивали.
    Success,
    /// Штатный результат сканирования: сервер жив, но отказал.
    Neutral,
    /// Признак перегрузки или блокировки.
    Overload,
    /// EOF до первого байта: нейтрален поодиночке, перегрузка в серии.
    AmbiguousEof,
    /// Отказ в соединении: закрытый порт либо перегрузка — по истории.
    Refused,
    /// Имя не разрешилось: работа с целью прекращается.
    Unresolved,
    /// Ответ не TLS: ранний выход либо нейтральный исход — по истории.
    NotTls,
    /// Нехватка ресурсов сканирующей машины.
    Local,
}

impl Outcome {
    /// Все исходы.
    pub const ALL: [Self; OUTCOMES] = [
        Self::ConnectUnresolved,
        Self::ConnectRefused,
        Self::ConnectReset,
        Self::ConnectTimeout,
        Self::ConnectUnreachable,
        Self::ConnectOther,
        Self::LocalExhaustion,
        Self::ConditionMet,
        Self::FatalAlert,
        Self::EofBeforeFirstByte,
        Self::EofAtMessageBoundary,
        Self::EofMidMessage,
        Self::Reset,
        Self::HandshakeTimeout,
        Self::ReadTimeout,
        Self::Deadline,
        Self::NotTls,
        Self::Parse,
        Self::LimitExceeded,
        Self::WriteFailed,
        Self::Io,
    ];

    /// Исход по классу ошибки соединения.
    #[must_use]
    pub fn from_class(class: ConnectErrorClass) -> Self {
        match class {
            ConnectErrorClass::Unresolved => Self::ConnectUnresolved,
            ConnectErrorClass::Refused => Self::ConnectRefused,
            ConnectErrorClass::Reset => Self::ConnectReset,
            ConnectErrorClass::Timeout => Self::ConnectTimeout,
            ConnectErrorClass::Unreachable => Self::ConnectUnreachable,
            ConnectErrorClass::Other => Self::ConnectOther,
        }
    }

    /// Исход по ошибке [`net::Connector::connect`]. Нехватка локальных
    /// ресурсов распознаётся по последней попытке и имеет приоритет над
    /// классом ошибки.
    #[must_use]
    pub fn from_connect_error(error: &ConnectError) -> Self {
        let local = error
            .attempts()
            .last()
            .is_some_and(|attempt| is_local_exhaustion(attempt.io_kind, attempt.raw_os_error));
        if local {
            Self::LocalExhaustion
        } else {
            Self::from_class(error.class())
        }
    }

    /// Исход по причине остановки обмена.
    #[must_use]
    pub fn from_stop(stop: &StopReason) -> Self {
        match stop {
            StopReason::ConditionMet => Self::ConditionMet,
            StopReason::FatalAlert => Self::FatalAlert,
            StopReason::Eof(EofKind::BeforeFirstByte) => Self::EofBeforeFirstByte,
            StopReason::Eof(EofKind::AtMessageBoundary) => Self::EofAtMessageBoundary,
            StopReason::Eof(EofKind::MidMessage) => Self::EofMidMessage,
            StopReason::Reset { .. } => Self::Reset,
            StopReason::HandshakeTimeout => Self::HandshakeTimeout,
            StopReason::ReadTimeout => Self::ReadTimeout,
            StopReason::Deadline => Self::Deadline,
            StopReason::NotTls { .. } => Self::NotTls,
            StopReason::Parse(_) => Self::Parse,
            StopReason::LimitExceeded(_) => Self::LimitExceeded,
            StopReason::WriteFailed(_) => Self::WriteFailed,
            StopReason::Io { .. } => Self::Io,
        }
    }

    /// Сигнал исхода; таблица и обоснование — в документации модуля.
    #[must_use]
    pub fn signal(self) -> Signal {
        match self {
            Self::ConditionMet => Signal::Success,
            Self::FatalAlert
            | Self::EofAtMessageBoundary
            | Self::Parse
            | Self::LimitExceeded
            | Self::Deadline => Signal::Neutral,
            Self::NotTls => Signal::NotTls,
            Self::EofBeforeFirstByte => Signal::AmbiguousEof,
            Self::EofMidMessage
            | Self::Reset
            | Self::HandshakeTimeout
            | Self::ReadTimeout
            | Self::WriteFailed
            | Self::Io
            | Self::ConnectReset
            | Self::ConnectTimeout
            | Self::ConnectUnreachable
            | Self::ConnectOther => Signal::Overload,
            Self::ConnectRefused => Signal::Refused,
            Self::ConnectUnresolved => Signal::Unresolved,
            Self::LocalExhaustion => Signal::Local,
        }
    }

    /// Короткая метка для журналов и вывода.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ConnectUnresolved => "connect_unresolved",
            Self::ConnectRefused => "connect_refused",
            Self::ConnectReset => "connect_reset",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectUnreachable => "connect_unreachable",
            Self::ConnectOther => "connect_other",
            Self::LocalExhaustion => "local_exhaustion",
            Self::ConditionMet => "condition",
            Self::FatalAlert => "fatal_alert",
            Self::EofBeforeFirstByte => "eof_before_first_byte",
            Self::EofAtMessageBoundary => "eof",
            Self::EofMidMessage => "eof_mid_message",
            Self::Reset => "reset",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::ReadTimeout => "read_timeout",
            Self::Deadline => "deadline",
            Self::NotTls => "not_tls",
            Self::Parse => "parse",
            Self::LimitExceeded => "limit",
            Self::WriteFailed => "write",
            Self::Io => "io",
        }
    }
}

/// Код ошибки «слишком много открытых файлов в процессе» (EMFILE) на Unix.
const UNIX_EMFILE: i32 = 24;
/// Код ошибки «слишком много открытых файлов в системе» (ENFILE) на Unix.
const UNIX_ENFILE: i32 = 23;
/// Код ошибки «слишком много открытых сокетов» (WSAEMFILE) на Windows.
const WINDOWS_WSAEMFILE: i32 = 10_024;
/// Код ошибки «нет места в буферах» (WSAENOBUFS) на Windows.
const WINDOWS_WSAENOBUFS: i32 = 10_055;

/// Истина, если ошибка означает нехватку ресурсов сканирующей машины:
/// дескрипторов (EMFILE, ENFILE), локальных портов (EADDRNOTAVAIL) или
/// памяти под сокет (ENOBUFS, ENOMEM).
///
/// У EMFILE и ENFILE нет стабильного `io::ErrorKind`, поэтому они
/// распознаются по коду ошибки ОС, если он известен; коды 23 и 24 совпадают
/// на Linux, macOS и BSD. Остальное — по виду ошибки.
#[must_use]
pub fn is_local_exhaustion(kind: io::ErrorKind, raw_os_error: Option<i32>) -> bool {
    if matches!(
        kind,
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::OutOfMemory
    ) {
        return true;
    }
    raw_os_error.is_some_and(|code| {
        if cfg!(unix) {
            code == UNIX_EMFILE || code == UNIX_ENFILE
        } else if cfg!(windows) {
            code == WINDOWS_WSAEMFILE || code == WINDOWS_WSAENOBUFS
        } else {
            false
        }
    })
}

/// Параметры AIMD; значения по умолчанию предварительные
/// (`docs/DECISIONS.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AimdConfig {
    /// Во сколько раз уменьшаются лимит соединений и скорость хоста при
    /// сигнале перегрузки; значение меньше 2 трактуется как 2.
    pub decrease_divisor: u32,
    /// Наименьшая скорость хоста; не выше настроенной скорости.
    pub min_rate: Rate,
    /// Сколько успехов подряд дают один шаг восстановления; ноль
    /// трактуется как 1.
    pub successes_per_step: u32,
    /// Шаг восстановления скорости, в тысячных соединения в секунду; ноль
    /// трактуется как 1.
    pub rate_step_milli: u64,
    /// Шаг восстановления лимита соединений; ноль трактуется как 1.
    pub connections_step: usize,
    /// Задержка между соединениями после первого сигнала перегрузки; ноль
    /// выключает задержку.
    pub delay_initial: Duration,
    /// Во сколько раз задержка растёт при каждом следующем сигнале и
    /// уменьшается при шаге восстановления; значение меньше 2 трактуется
    /// как 2.
    pub delay_multiplier: u32,
    /// Верхняя граница задержки.
    pub delay_max: Duration,
}

impl Default for AimdConfig {
    fn default() -> Self {
        Self {
            decrease_divisor: 2,
            min_rate: Rate::per_second(1),
            successes_per_step: 8,
            rate_step_milli: 1000,
            connections_step: 1,
            delay_initial: Duration::from_millis(250),
            delay_multiplier: 2,
            delay_max: Duration::from_secs(10),
        }
    }
}

/// Эффективные ограничения хоста: то, что действует сейчас.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective {
    /// Лимит одновременных соединений с хостом.
    pub connections: usize,
    /// Скорость соединений с хостом.
    pub rate: Rate,
    /// Задержка перед каждым соединением с хостом.
    pub delay: Duration,
}

/// Автомат AIMD одного хоста; описание — в документации модуля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aimd {
    config: AimdConfig,
    max_connections: usize,
    max_rate: Rate,
    current: Effective,
    successes: u32,
}

impl Aimd {
    /// Автомат с настроенными максимумами: лимитом соединений на хост и
    /// скоростью хоста. Начальное состояние — максимум, без задержки.
    #[must_use]
    pub fn new(config: AimdConfig, max_connections: usize, max_rate: Rate) -> Self {
        let max_connections = max_connections.max(1);
        Self {
            config,
            max_connections,
            max_rate,
            current: Effective {
                connections: max_connections,
                rate: max_rate,
                delay: Duration::ZERO,
            },
            successes: 0,
        }
    }

    /// Действующие ограничения.
    #[must_use]
    pub fn effective(&self) -> Effective {
        self.current
    }

    /// Истина, если действующие ограничения строже настроенных.
    #[must_use]
    pub fn is_reduced(&self) -> bool {
        self.current.connections < self.max_connections
            || self.current.rate != self.max_rate
            || !self.current.delay.is_zero()
    }

    /// Сигнал перегрузки: мультипликативное уменьшение. Возвращает новые
    /// ограничения.
    pub fn on_overload(&mut self) -> Effective {
        self.successes = 0;
        let divisor = self.config.decrease_divisor.max(2);

        let connection_divisor = usize::try_from(divisor).unwrap_or(2);
        self.current.connections = self
            .current
            .connections
            .checked_div(connection_divisor)
            .unwrap_or(1)
            .max(1);

        if let (Some(current), Some(max)) = (
            self.current.rate.milli_per_second(),
            self.max_rate.milli_per_second(),
        ) {
            let floor = self
                .config
                .min_rate
                .milli_per_second()
                .unwrap_or(1)
                .min(max);
            let reduced = current.checked_div(u64::from(divisor)).unwrap_or(floor);
            self.current.rate = Rate::MilliPerSecond(reduced.max(floor));
        }

        let grown = if self.current.delay.is_zero() {
            self.config.delay_initial
        } else {
            self.current
                .delay
                .saturating_mul(self.config.delay_multiplier.max(2))
        };
        self.current.delay = grown.min(self.config.delay_max);
        self.current
    }

    /// Успех: каждые [`AimdConfig::successes_per_step`] успехов подряд —
    /// один шаг аддитивного восстановления. Возвращает действующие
    /// ограничения.
    pub fn on_success(&mut self) -> Effective {
        if !self.is_reduced() {
            self.successes = 0;
            return self.current;
        }
        self.successes = self.successes.saturating_add(1);
        if self.successes < self.config.successes_per_step.max(1) {
            return self.current;
        }
        self.successes = 0;

        self.current.connections = self
            .current
            .connections
            .saturating_add(self.config.connections_step.max(1))
            .min(self.max_connections);

        self.current.rate = match (
            self.current.rate.milli_per_second(),
            self.max_rate.milli_per_second(),
        ) {
            (Some(current), Some(max)) => Rate::MilliPerSecond(
                current
                    .saturating_add(self.config.rate_step_milli.max(1))
                    .min(max),
            ),
            _ => self.max_rate,
        };

        let shrunk = self
            .current
            .delay
            .checked_div(self.config.delay_multiplier.max(2))
            .unwrap_or(Duration::ZERO);
        self.current.delay = if shrunk < self.config.delay_initial {
            Duration::ZERO
        } else {
            shrunk
        };
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::{ConnectAttempt, ConnectFailure, ConnectStage, Target, WriteFailure};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const MAX_CONNECTIONS: usize = 2;
    const MAX_RATE: Rate = Rate::MilliPerSecond(10_000);

    fn limits(connections: usize, milli: u64, delay_ms: u64) -> Effective {
        Effective {
            connections,
            rate: Rate::MilliPerSecond(milli),
            delay: Duration::from_millis(delay_ms),
        }
    }

    fn aimd() -> Aimd {
        Aimd::new(AimdConfig::default(), MAX_CONNECTIONS, MAX_RATE)
    }

    #[test]
    fn classification_table() {
        let table = [
            (Outcome::ConditionMet, Signal::Success),
            (Outcome::FatalAlert, Signal::Neutral),
            (Outcome::EofAtMessageBoundary, Signal::Neutral),
            (Outcome::Parse, Signal::Neutral),
            (Outcome::LimitExceeded, Signal::Neutral),
            (Outcome::Deadline, Signal::Neutral),
            (Outcome::NotTls, Signal::NotTls),
            (Outcome::EofBeforeFirstByte, Signal::AmbiguousEof),
            (Outcome::EofMidMessage, Signal::Overload),
            (Outcome::Reset, Signal::Overload),
            (Outcome::HandshakeTimeout, Signal::Overload),
            (Outcome::ReadTimeout, Signal::Overload),
            (Outcome::WriteFailed, Signal::Overload),
            (Outcome::Io, Signal::Overload),
            (Outcome::ConnectReset, Signal::Overload),
            (Outcome::ConnectTimeout, Signal::Overload),
            (Outcome::ConnectUnreachable, Signal::Overload),
            (Outcome::ConnectOther, Signal::Overload),
            (Outcome::ConnectRefused, Signal::Refused),
            (Outcome::ConnectUnresolved, Signal::Unresolved),
            (Outcome::LocalExhaustion, Signal::Local),
        ];
        assert_eq!(table.len(), OUTCOMES, "таблица покрывает все исходы");
        for (outcome, signal) in table {
            assert_eq!(outcome.signal(), signal, "{}", outcome.label());
        }
        // Каждый исход встречается в таблице ровно один раз.
        for outcome in Outcome::ALL {
            let rows = table.iter().filter(|(row, _)| *row == outcome).count();
            assert_eq!(rows, 1, "{}", outcome.label());
        }
    }

    #[test]
    fn labels_are_distinct() {
        let mut labels: Vec<&str> = Outcome::ALL.into_iter().map(Outcome::label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), OUTCOMES);
    }

    #[test]
    fn server_refusals_are_not_overload() {
        // Штатные ответы на неподдерживаемый протокол или шифр.
        let regular = [
            StopReason::FatalAlert,
            StopReason::Eof(EofKind::AtMessageBoundary),
            StopReason::ConditionMet,
        ];
        for stop in regular {
            let signal = Outcome::from_stop(&stop).signal();
            assert!(
                matches!(signal, Signal::Success | Signal::Neutral),
                "{}",
                stop.label()
            );
        }
    }

    #[test]
    fn stop_reasons_map_to_outcomes() {
        let reset_kind = io::ErrorKind::ConnectionReset;
        let cases = [
            (StopReason::ConditionMet, Outcome::ConditionMet),
            (StopReason::FatalAlert, Outcome::FatalAlert),
            (
                StopReason::Eof(EofKind::BeforeFirstByte),
                Outcome::EofBeforeFirstByte,
            ),
            (
                StopReason::Eof(EofKind::AtMessageBoundary),
                Outcome::EofAtMessageBoundary,
            ),
            (StopReason::Eof(EofKind::MidMessage), Outcome::EofMidMessage),
            (StopReason::Reset { kind: reset_kind }, Outcome::Reset),
            (StopReason::HandshakeTimeout, Outcome::HandshakeTimeout),
            (StopReason::ReadTimeout, Outcome::ReadTimeout),
            (StopReason::Deadline, Outcome::Deadline),
            (
                StopReason::NotTls {
                    first_bytes: Vec::new(),
                },
                Outcome::NotTls,
            ),
            (
                StopReason::WriteFailed(WriteFailure {
                    kind: io::ErrorKind::BrokenPipe,
                    written: 0,
                    total: 1,
                }),
                Outcome::WriteFailed,
            ),
            (
                StopReason::Io {
                    kind: io::ErrorKind::Other,
                },
                Outcome::Io,
            ),
        ];
        for (stop, outcome) in cases {
            assert_eq!(Outcome::from_stop(&stop), outcome, "{}", stop.label());
        }
    }

    #[test]
    fn connect_classes_map_to_outcomes() {
        let cases = [
            (ConnectErrorClass::Unresolved, Outcome::ConnectUnresolved),
            (ConnectErrorClass::Refused, Outcome::ConnectRefused),
            (ConnectErrorClass::Reset, Outcome::ConnectReset),
            (ConnectErrorClass::Timeout, Outcome::ConnectTimeout),
            (ConnectErrorClass::Unreachable, Outcome::ConnectUnreachable),
            (ConnectErrorClass::Other, Outcome::ConnectOther),
        ];
        for (class, outcome) in cases {
            assert_eq!(Outcome::from_class(class), outcome);
        }
    }

    fn connect_error(kind: io::ErrorKind) -> ConnectError {
        connect_error_with_code(kind, None)
    }

    fn connect_error_with_code(kind: io::ErrorKind, raw_os_error: Option<i32>) -> ConnectError {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        ConnectError::Connect {
            target: Target::new("192.0.2.1", 443),
            attempts: vec![ConnectAttempt {
                addr,
                stage: ConnectStage::Connect,
                failure: ConnectFailure::from_io_kind(kind),
                io_kind: kind,
                raw_os_error,
                message: String::from("test"),
                elapsed: Duration::ZERO,
            }],
        }
    }

    #[test]
    fn connect_errors_map_to_outcomes() {
        assert_eq!(
            Outcome::from_connect_error(&connect_error(io::ErrorKind::ConnectionRefused)),
            Outcome::ConnectRefused
        );
        assert_eq!(
            Outcome::from_connect_error(&connect_error(io::ErrorKind::TimedOut)),
            Outcome::ConnectTimeout
        );
        assert_eq!(
            Outcome::from_connect_error(&connect_error(io::ErrorKind::ConnectionReset)),
            Outcome::ConnectReset
        );
        // Нехватка локальных портов — не вина хоста.
        assert_eq!(
            Outcome::from_connect_error(&connect_error(io::ErrorKind::AddrNotAvailable)),
            Outcome::LocalExhaustion
        );
        // Нехватка дескрипторов распознаётся по коду ошибки ОС и имеет
        // приоритет над классом ошибки.
        if cfg!(unix) {
            for code in [UNIX_EMFILE, UNIX_ENFILE] {
                assert_eq!(
                    Outcome::from_connect_error(&connect_error_with_code(
                        io::ErrorKind::Other,
                        Some(code)
                    )),
                    Outcome::LocalExhaustion
                );
            }
        }
        // Код ошибки ОС, не относящийся к нехватке ресурсов, класс не меняет.
        assert_eq!(
            Outcome::from_connect_error(&connect_error_with_code(
                io::ErrorKind::ConnectionRefused,
                Some(UNIX_EMFILE + UNIX_ENFILE)
            )),
            Outcome::ConnectRefused
        );
    }

    #[test]
    fn local_exhaustion_is_recognised_by_kind_and_os_code() {
        assert!(is_local_exhaustion(io::ErrorKind::AddrNotAvailable, None));
        assert!(is_local_exhaustion(io::ErrorKind::OutOfMemory, None));
        assert!(!is_local_exhaustion(io::ErrorKind::ConnectionReset, None));
        assert!(!is_local_exhaustion(io::ErrorKind::Other, None));
        if cfg!(unix) {
            assert!(is_local_exhaustion(io::ErrorKind::Other, Some(UNIX_EMFILE)));
            assert!(is_local_exhaustion(io::ErrorKind::Other, Some(UNIX_ENFILE)));
            // ECONNRESET (54 на macOS, 104 на Linux) сюда не относится.
            assert!(!is_local_exhaustion(io::ErrorKind::Other, Some(54)));
            assert!(!is_local_exhaustion(io::ErrorKind::Other, Some(104)));
        }
    }

    #[test]
    fn initial_state_is_the_configured_maximum() {
        let aimd = aimd();
        assert_eq!(aimd.effective(), limits(2, 10_000, 0));
        assert!(!aimd.is_reduced());
    }

    #[test]
    fn overload_halves_rate_and_connections_and_doubles_delay() {
        let mut aimd = aimd();
        assert_eq!(aimd.on_overload(), limits(1, 5000, 250));
        assert!(aimd.is_reduced());
        assert_eq!(aimd.on_overload(), limits(1, 2500, 500));
        assert_eq!(aimd.on_overload(), limits(1, 1250, 1000));
        // Скорость упирается в минимум 1 соединение в секунду.
        assert_eq!(aimd.on_overload(), limits(1, 1000, 2000));
        assert_eq!(aimd.on_overload(), limits(1, 1000, 4000));
        assert_eq!(aimd.on_overload(), limits(1, 1000, 8000));
        // Задержка упирается в потолок 10 с.
        assert_eq!(aimd.on_overload(), limits(1, 1000, 10_000));
        assert_eq!(aimd.on_overload(), limits(1, 1000, 10_000));
    }

    #[test]
    fn successes_restore_additively_step_by_step() {
        let mut aimd = aimd();
        aimd.on_overload();
        aimd.on_overload();
        assert_eq!(aimd.effective(), limits(1, 2500, 500));

        // Семь успехов — ещё не шаг.
        for _ in 0..7 {
            assert_eq!(aimd.on_success(), limits(1, 2500, 500));
        }
        // Восьмой: +1 соединение, +1 соединение в секунду, задержка вдвое
        // меньше.
        assert_eq!(aimd.on_success(), limits(2, 3500, 250));

        for _ in 0..7 {
            assert_eq!(aimd.on_success(), limits(2, 3500, 250));
        }
        // Задержка 125 мс меньше начальной — обнуляется.
        assert_eq!(aimd.on_success(), limits(2, 4500, 0));

        // Ещё шесть шагов: 5500, 6500, 7500, 8500, 9500 и максимум 10000.
        let mut expected_milli = 4500_u64;
        for _ in 0..6 {
            for _ in 0..8 {
                aimd.on_success();
            }
            expected_milli = (expected_milli + 1000).min(10_000);
            assert_eq!(aimd.effective(), limits(2, expected_milli, 0));
        }
        assert_eq!(aimd.effective(), limits(2, 10_000, 0));
        assert!(!aimd.is_reduced());

        // На максимуме успехи ничего не меняют.
        for _ in 0..100 {
            assert_eq!(aimd.on_success(), limits(2, 10_000, 0));
        }
    }

    #[test]
    fn overload_resets_the_success_streak() {
        let mut aimd = aimd();
        aimd.on_overload();
        for _ in 0..7 {
            aimd.on_success();
        }
        assert_eq!(aimd.on_overload(), limits(1, 2500, 500));
        for _ in 0..7 {
            assert_eq!(aimd.on_success(), limits(1, 2500, 500));
        }
        assert_eq!(aimd.on_success(), limits(2, 3500, 250));
    }

    #[test]
    fn connections_never_drop_below_one_and_floor_never_exceeds_maximum() {
        let config = AimdConfig {
            min_rate: Rate::per_second(5),
            ..AimdConfig::default()
        };
        // Настроенная скорость ниже минимума: минимум не поднимает её.
        let mut slow = Aimd::new(config, 1, Rate::per_second(2));
        assert_eq!(slow.on_overload(), limits(1, 2000, 250));

        let mut wide = Aimd::new(AimdConfig::default(), 8, MAX_RATE);
        assert_eq!(wide.on_overload().connections, 4);
        assert_eq!(wide.on_overload().connections, 2);
        assert_eq!(wide.on_overload().connections, 1);
        assert_eq!(wide.on_overload().connections, 1);

        // Нулевой лимит трактуется как 1.
        let zero = Aimd::new(AimdConfig::default(), 0, MAX_RATE);
        assert_eq!(zero.effective().connections, 1);
    }

    #[test]
    fn unlimited_rate_is_left_alone() {
        let mut aimd = Aimd::new(AimdConfig::default(), 4, Rate::Unlimited);
        let reduced = aimd.on_overload();
        assert_eq!(reduced.rate, Rate::Unlimited);
        assert_eq!(reduced.connections, 2);
        assert_eq!(reduced.delay, Duration::from_millis(250));
        for _ in 0..16 {
            aimd.on_success();
        }
        assert_eq!(
            aimd.effective(),
            Effective {
                connections: 4,
                rate: Rate::Unlimited,
                delay: Duration::ZERO,
            }
        );
        assert!(!aimd.is_reduced());
    }

    #[test]
    fn degenerate_parameters_are_clamped() {
        let config = AimdConfig {
            decrease_divisor: 0,
            successes_per_step: 0,
            rate_step_milli: 0,
            connections_step: 0,
            delay_initial: Duration::ZERO,
            delay_multiplier: 0,
            ..AimdConfig::default()
        };
        let mut aimd = Aimd::new(config, 4, MAX_RATE);
        // Делитель 0 трактуется как 2; нулевая начальная задержка выключает
        // задержку.
        assert_eq!(aimd.on_overload(), limits(2, 5000, 0));
        // Каждый успех — шаг: +1 соединение, +1 тысячная.
        assert_eq!(aimd.on_success(), limits(3, 5001, 0));
    }
}
