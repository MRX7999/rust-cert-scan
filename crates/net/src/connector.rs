//! [`Connector`] — единственная точка открытия соединений.
//!
//! # Что делает `connect`
//!
//! 1. Получает адреса цели через [`DnsCache::resolve_target`]: IP override,
//!    IP-литерал, режим `--dns none`, семейство адресов.
//! 2. Перебирает адреса последовательно, в порядке резолвера, не более
//!    [`ConnectorConfig::max_addresses`] штук; на каждый адрес — отдельный
//!    таймаут [`Timeouts::connect`]. Первое открытое соединение возвращается,
//!    остальные адреса не пробуются. Параллельных попыток (Happy Eyeballs)
//!    нет: сканер не должен открывать соединений больше, чем учтено.
//! 3. Включает `TCP_NODELAY`: пробник — один небольшой ClientHello, задержка
//!    Нейгла только искажает измерение времени.
//! 4. Учитывает каждую попытку в переданной области [`ConnStats`].
//!
//! # Чего `connect` не делает
//!
//! Семафоры, rate limit, jitter и backoff — задачи движка (P1-12, P1-13).
//! `Connector` разрешений не запрашивает и не ждёт: вызывающий код получает
//! разрешение на соединение до вызова [`Connector::connect`]. Чтобы движок
//! мог учесть в лимитах каждую попытку, а не только вызов `connect`, число
//! адресов на вызов ограничено [`ConnectorConfig::max_addresses`], а все
//! попытки видны в [`ConnStats`] и в [`ConnectError::attempts`].
//!
//! # Точка расширения транспорта
//!
//! Proxy (HTTP CONNECT, SOCKS) и преамбулы STARTTLS — задачи Фазы 3, здесь
//! их нет. [`Conn`] обобщён по транспорту: слой прокси или STARTTLS получит
//! `Conn<TcpStream>`, выполнит свой обмен и вернёт соединение дальше — тем же
//! типом либо обёрнутым через [`Conn::map_stream`]. Обмен пробником
//! ([`probe_io`](crate::probe_io)) работает с любым `AsyncRead + AsyncWrite`.
//!
//! # Ошибки
//!
//! [`ConnectError`] сохраняет этап (резолв, connect, настройка сокета),
//! адрес каждой попытки и исходный [`io::ErrorKind`]. Для решений о раннем
//! выходе и backoff движку достаточно [`ConnectError::class`].

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::dns::{DnsCache, DnsError, ResolveOptions, parse_ip_literal};
use crate::stats::ConnStats;
use crate::timeouts::Timeouts;

/// Сколько адресов цели пробует один вызов [`Connector::connect`] по
/// умолчанию (предварительное значение, `docs/DECISIONS.md`, D-17).
pub const DEFAULT_MAX_ADDRESSES: usize = 4;

/// Цель соединения: имя или IP-литерал и порт.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// Имя хоста либо IP-литерал (`192.0.2.1`, `2001:db8::1`,
    /// `[2001:db8::1]`).
    pub host: String,
    /// TCP-порт.
    pub port: u16,
}

impl Target {
    /// Цель из имени (или IP-литерала) и порта.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Имя для SNI: исходное имя цели; `None`, если цель — IP-литерал
    /// (RFC 6066, раздел 3: литералы в SNI не передаются). IP override на
    /// это значение не влияет.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        if parse_ip_literal(&self.host).is_some() {
            None
        } else {
            Some(&self.host)
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bare_v6 = !self.host.starts_with('[')
            && parse_ip_literal(&self.host).is_some_and(|ip| ip.is_ipv6());
        if bare_v6 {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Настройки [`Connector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorConfig {
    /// Таймауты; `connect` применяется здесь, остальные передаются в
    /// [`Conn`] для обмена пробником.
    pub timeouts: Timeouts,
    /// Параметры разрешения имён: семейство адресов, `--dns none`, `--ip`.
    pub resolve: ResolveOptions,
    /// Сколько адресов цели пробовать за один вызов `connect`; 0 трактуется
    /// как 1.
    pub max_addresses: usize,
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            resolve: ResolveOptions::default(),
            max_addresses: DEFAULT_MAX_ADDRESSES,
        }
    }
}

/// Этап, на котором не удалась попытка соединения с адресом.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectStage {
    /// Установление TCP-соединения.
    Connect,
    /// Настройка открытого сокета (`TCP_NODELAY`).
    Configure,
}

impl fmt::Display for ConnectStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connect => "connect",
            Self::Configure => "настройка сокета",
        })
    }
}

/// Вид отказа одной попытки соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectFailure {
    /// Отказ в соединении: порт закрыт (RST в ответ на SYN).
    Refused,
    /// Соединение сброшено или оборвано в момент установления.
    Reset,
    /// Нет ответа за [`Timeouts::connect`] либо таймаут ядра.
    Timeout,
    /// Сеть недостижима или сетевой интерфейс выключен.
    NetworkUnreachable,
    /// Хост недостижим.
    HostUnreachable,
    /// Прочее; подробности — в [`ConnectAttempt::io_kind`].
    Other,
}

impl ConnectFailure {
    /// Классифицирует вид ошибки ввода-вывода, полученной при connect.
    #[must_use]
    pub fn from_io_kind(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::ConnectionRefused => Self::Refused,
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => Self::Reset,
            io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::NetworkDown => {
                Self::NetworkUnreachable
            }
            io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            _ => Self::Other,
        }
    }
}

impl fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Refused => "отказ в соединении",
            Self::Reset => "соединение сброшено",
            Self::Timeout => "таймаут",
            Self::NetworkUnreachable => "сеть недостижима",
            Self::HostUnreachable => "хост недостижим",
            Self::Other => "ошибка",
        })
    }
}

/// Неудачная попытка соединения с одним адресом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectAttempt {
    /// Адрес, с которым устанавливалось соединение.
    pub addr: SocketAddr,
    /// Этап, на котором произошёл отказ.
    pub stage: ConnectStage,
    /// Вид отказа.
    pub failure: ConnectFailure,
    /// Исходный вид ошибки ввода-вывода; для истёкшего
    /// [`Timeouts::connect`] — [`io::ErrorKind::TimedOut`].
    pub io_kind: io::ErrorKind,
    /// Текст исходной ошибки.
    pub message: String,
    /// Сколько длилась попытка.
    pub elapsed: Duration,
}

impl ConnectAttempt {
    fn from_io(
        addr: SocketAddr,
        stage: ConnectStage,
        error: &io::Error,
        elapsed: Duration,
    ) -> Self {
        Self {
            addr,
            stage,
            failure: ConnectFailure::from_io_kind(error.kind()),
            io_kind: error.kind(),
            message: error.to_string(),
            elapsed,
        }
    }
}

impl fmt::Display for ConnectAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} к {}: {} ({:?}) через {} мс: {}",
            self.stage,
            self.addr,
            self.failure,
            self.io_kind,
            self.elapsed.as_millis(),
            self.message
        )
    }
}

/// Класс ошибки соединения для решений движка (ранний выход, backoff).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectErrorClass {
    /// Имя не разрешилось (включая отключённый резолв и несовпадение
    /// семейства адресов).
    Unresolved,
    /// Отказ в соединении.
    Refused,
    /// Соединение сброшено.
    Reset,
    /// Таймаут.
    Timeout,
    /// Сеть или хост недостижимы.
    Unreachable,
    /// Прочее.
    Other,
}

/// Ошибка [`Connector::connect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// Не удалось получить адреса цели; соединений не открывалось.
    Resolve {
        /// Цель.
        target: Target,
        /// Причина.
        error: DnsError,
    },
    /// Ни с одним из опробованных адресов соединиться не удалось.
    Connect {
        /// Цель.
        target: Target,
        /// Попытки в порядке выполнения.
        attempts: Vec<ConnectAttempt>,
    },
}

impl ConnectError {
    /// Цель, к которой относится ошибка.
    #[must_use]
    pub fn target(&self) -> &Target {
        match self {
            Self::Resolve { target, .. } | Self::Connect { target, .. } => target,
        }
    }

    /// Неудачные попытки соединения; пусто для ошибки резолва.
    #[must_use]
    pub fn attempts(&self) -> &[ConnectAttempt] {
        match self {
            Self::Resolve { .. } => &[],
            Self::Connect { attempts, .. } => attempts,
        }
    }

    /// Класс ошибки. Для нескольких попыток — класс последней: она сделана
    /// позже всех и отражает самое свежее состояние цели.
    #[must_use]
    pub fn class(&self) -> ConnectErrorClass {
        match self {
            Self::Resolve { .. } => ConnectErrorClass::Unresolved,
            Self::Connect { attempts, .. } => {
                match attempts.last().map(|attempt| attempt.failure) {
                    Some(ConnectFailure::Refused) => ConnectErrorClass::Refused,
                    Some(ConnectFailure::Reset) => ConnectErrorClass::Reset,
                    Some(ConnectFailure::Timeout) => ConnectErrorClass::Timeout,
                    Some(ConnectFailure::NetworkUnreachable | ConnectFailure::HostUnreachable) => {
                        ConnectErrorClass::Unreachable
                    }
                    Some(ConnectFailure::Other) | None => ConnectErrorClass::Other,
                }
            }
        }
    }

    /// Исходный вид ошибки ввода-вывода последней попытки; для ошибки
    /// резолва — вид ошибки резолвера, если она была.
    #[must_use]
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Resolve { error, .. } => match error {
                DnsError::LookupFailed { kind, .. } => Some(*kind),
                DnsError::TimedOut { .. } => Some(io::ErrorKind::TimedOut),
                DnsError::NoAddresses { .. }
                | DnsError::FamilyMismatch { .. }
                | DnsError::ResolutionDisabled { .. } => None,
            },
            Self::Connect { attempts, .. } => attempts.last().map(|attempt| attempt.io_kind),
        }
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve { target, error } => write!(f, "цель {target}: {error}"),
            Self::Connect { target, attempts } => {
                write!(f, "цель {target}: соединение не установлено")?;
                for (index, attempt) in attempts.iter().enumerate() {
                    let separator = if index == 0 { ": " } else { "; " };
                    write!(f, "{separator}{attempt}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve { error, .. } => Some(error),
            Self::Connect { .. } => None,
        }
    }
}

/// Открытое соединение с целью и сведения о нём.
///
/// Параметр `S` — транспорт: [`TcpStream`] от [`Connector`], любой
/// `AsyncRead + AsyncWrite` в тестах и у будущих слоёв proxy и STARTTLS.
#[derive(Debug)]
pub struct Conn<S = TcpStream> {
    stream: S,
    peer: SocketAddr,
    server_name: Option<String>,
    timeouts: Timeouts,
    connect_time: Duration,
}

impl<S> Conn<S> {
    /// Соединение поверх готового транспорта: для тестов и для слоёв,
    /// которые открывают транспорт в обход [`Connector`]. Время connect
    /// считается нулевым.
    #[must_use]
    pub fn from_stream(
        stream: S,
        peer: SocketAddr,
        server_name: Option<String>,
        timeouts: Timeouts,
    ) -> Self {
        Self {
            stream,
            peer,
            server_name,
            timeouts,
            connect_time: Duration::ZERO,
        }
    }

    /// Заменяет транспорт, сохраняя сведения о соединении: так слой proxy
    /// или STARTTLS оборачивает поток.
    #[must_use]
    pub fn map_stream<T>(self, wrap: impl FnOnce(S) -> T) -> Conn<T> {
        Conn {
            stream: wrap(self.stream),
            peer: self.peer,
            server_name: self.server_name,
            timeouts: self.timeouts,
            connect_time: self.connect_time,
        }
    }

    /// Адрес, с которым установлено соединение.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Имя для SNI: исходное имя цели; `None` для IP-литерала.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Таймауты, с которыми открыто соединение.
    #[must_use]
    pub fn timeouts(&self) -> &Timeouts {
        &self.timeouts
    }

    /// Сколько длился успешный connect.
    #[must_use]
    pub fn connect_time(&self) -> Duration {
        self.connect_time
    }

    /// Транспорт.
    #[must_use]
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Транспорт для чтения и записи.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Забирает транспорт.
    #[must_use]
    pub fn into_stream(self) -> S {
        self.stream
    }
}

/// Открывает TCP-соединения; описание — в документации модуля.
///
/// Клонирование дёшево: клоны делят DNS-кэш и счётчики.
#[derive(Debug, Clone)]
pub struct Connector {
    dns: Arc<DnsCache>,
    config: ConnectorConfig,
    stats: ConnStats,
}

impl Connector {
    /// `Connector` с заданным DNS-кэшем и настройками.
    #[must_use]
    pub fn new(dns: Arc<DnsCache>, config: ConnectorConfig) -> Self {
        Self {
            dns,
            config,
            stats: ConnStats::new(),
        }
    }

    /// `Connector` с системным резолвером и настройками по умолчанию.
    #[must_use]
    pub fn system() -> Self {
        Self::new(Arc::new(DnsCache::system()), ConnectorConfig::default())
    }

    /// Настройки.
    #[must_use]
    pub fn config(&self) -> &ConnectorConfig {
        &self.config
    }

    /// DNS-кэш.
    #[must_use]
    pub fn dns(&self) -> &Arc<DnsCache> {
        &self.dns
    }

    /// Корневая область счётчиков: итог по всем соединениям, учтённым в её
    /// потомках. Область цели создаётся как `connector.stats().child()`,
    /// область проверки — как потомок области цели.
    #[must_use]
    pub fn stats(&self) -> &ConnStats {
        &self.stats
    }

    /// Адреса цели, которые будет пробовать [`Connector::connect`], в
    /// порядке перебора.
    ///
    /// # Errors
    ///
    /// [`ConnectError::Resolve`], если адреса получить не удалось.
    pub async fn resolve(&self, target: &Target) -> Result<Vec<SocketAddr>, ConnectError> {
        let ips = self
            .dns
            .resolve_target(&target.host, &self.config.resolve)
            .await
            .map_err(|error| ConnectError::Resolve {
                target: target.clone(),
                error,
            })?;
        Ok(ips
            .into_iter()
            .take(self.config.max_addresses.max(1))
            .map(|ip| SocketAddr::new(ip, target.port))
            .collect())
    }

    /// Открывает соединение с целью и учитывает каждую попытку в `scope`.
    ///
    /// Разрешение на соединение (семафоры, rate limit) вызывающий код
    /// получает до вызова. Чтобы итог попал в [`Connector::stats`], `scope`
    /// должна быть потомком этой области.
    ///
    /// # Errors
    ///
    /// - [`ConnectError::Resolve`] — адреса цели получить не удалось;
    /// - [`ConnectError::Connect`] — ни одна попытка не удалась.
    pub async fn connect(&self, target: &Target, scope: &ConnStats) -> Result<Conn, ConnectError> {
        let addrs = self.resolve(target).await?;
        let timeout = self.config.timeouts.connect;
        let mut attempts = Vec::new();
        for addr in addrs {
            let (result, elapsed) = timed_connect(addr, timeout, TcpStream::connect(addr)).await;
            let result = result.and_then(|stream| match stream.set_nodelay(true) {
                Ok(()) => Ok(stream),
                Err(error) => Err(ConnectAttempt::from_io(
                    addr,
                    ConnectStage::Configure,
                    &error,
                    elapsed,
                )),
            });
            scope.record_connect(elapsed, result.is_ok());
            match result {
                Ok(stream) => {
                    return Ok(Conn {
                        stream,
                        peer: addr,
                        server_name: target.server_name().map(str::to_owned),
                        timeouts: self.config.timeouts,
                        connect_time: elapsed,
                    });
                }
                Err(attempt) => attempts.push(attempt),
            }
        }
        Err(ConnectError::Connect {
            target: target.clone(),
            attempts,
        })
    }
}

/// Одна попытка соединения с таймаутом. Возвращает результат и длительность
/// попытки. Операция connect передаётся будущим, чтобы таймаут проверялся
/// тестом на приостановленных часах.
async fn timed_connect<S, F>(
    addr: SocketAddr,
    timeout: Duration,
    connect: F,
) -> (Result<S, ConnectAttempt>, Duration)
where
    F: Future<Output = io::Result<S>>,
{
    let started = Instant::now();
    let outcome = tokio::time::timeout(timeout, connect).await;
    let elapsed = started.elapsed();
    let result = match outcome {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(ConnectAttempt::from_io(
            addr,
            ConnectStage::Connect,
            &error,
            elapsed,
        )),
        Err(_elapsed) => Err(ConnectAttempt {
            addr,
            stage: ConnectStage::Connect,
            failure: ConnectFailure::Timeout,
            io_kind: io::ErrorKind::TimedOut,
            message: format!("нет ответа за {} мс", timeout.as_millis()),
            elapsed,
        }),
    };
    (result, elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{AddressFamily, DnsCacheConfig, DnsMode, ResolveFuture, Resolver};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    const LOOPBACK_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const LOOPBACK_V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    /// Резолвер с одним ответом на любое имя; пустой ответ — ошибка.
    #[derive(Debug, Default)]
    struct StaticResolver {
        addrs: Vec<IpAddr>,
        calls: AtomicUsize,
    }

    impl Resolver for StaticResolver {
        fn resolve<'a>(&'a self, _host: &'a str) -> ResolveFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.addrs.is_empty() {
                    Err(io::Error::new(io::ErrorKind::NotFound, "нет такого имени"))
                } else {
                    Ok(self.addrs.clone())
                }
            })
        }
    }

    fn connector(addrs: &[IpAddr], config: ConnectorConfig) -> (Arc<StaticResolver>, Connector) {
        let resolver = Arc::new(StaticResolver {
            addrs: addrs.to_vec(),
            calls: AtomicUsize::new(0),
        });
        let shared: Arc<dyn Resolver> = resolver.clone();
        let dns = Arc::new(DnsCache::new(shared, DnsCacheConfig::default()));
        (resolver, Connector::new(dns, config))
    }

    fn fast_config() -> ConnectorConfig {
        ConnectorConfig {
            timeouts: Timeouts {
                connect: Duration::from_secs(3),
                ..Timeouts::default()
            },
            ..ConnectorConfig::default()
        }
    }

    /// Порт на 127.0.0.1, на котором никто не слушает.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn defaults() {
        let config = ConnectorConfig::default();
        assert_eq!(config.max_addresses, 4);
        assert_eq!(config.timeouts, Timeouts::default());
        assert_eq!(config.resolve.family, AddressFamily::Any);
        assert_eq!(config.resolve.mode, DnsMode::System);
        assert_eq!(config.resolve.ip_override, None);
    }

    #[test]
    fn target_server_name_and_display() {
        let named = Target::new("example.test", 443);
        assert_eq!(named.server_name(), Some("example.test"));
        assert_eq!(named.to_string(), "example.test:443");

        let v4 = Target::new("192.0.2.1", 8443);
        assert_eq!(v4.server_name(), None);
        assert_eq!(v4.to_string(), "192.0.2.1:8443");

        let v6 = Target::new("2001:db8::1", 443);
        assert_eq!(v6.server_name(), None);
        assert_eq!(v6.to_string(), "[2001:db8::1]:443");

        let bracketed = Target::new("[2001:db8::1]", 443);
        assert_eq!(bracketed.server_name(), None);
        assert_eq!(bracketed.to_string(), "[2001:db8::1]:443");
    }

    #[test]
    fn io_error_kinds_are_classified() {
        use io::ErrorKind as K;
        let table = [
            (K::ConnectionRefused, ConnectFailure::Refused),
            (K::ConnectionReset, ConnectFailure::Reset),
            (K::ConnectionAborted, ConnectFailure::Reset),
            (K::TimedOut, ConnectFailure::Timeout),
            (K::NetworkUnreachable, ConnectFailure::NetworkUnreachable),
            (K::NetworkDown, ConnectFailure::NetworkUnreachable),
            (K::HostUnreachable, ConnectFailure::HostUnreachable),
            (K::AddrNotAvailable, ConnectFailure::Other),
            (K::PermissionDenied, ConnectFailure::Other),
        ];
        for (kind, expected) in table {
            assert_eq!(ConnectFailure::from_io_kind(kind), expected, "{kind:?}");
        }
    }

    #[test]
    fn error_class_follows_the_last_attempt() {
        let addr = SocketAddr::new(LOOPBACK_V4, 1);
        let attempt = |failure, io_kind| ConnectAttempt {
            addr,
            stage: ConnectStage::Connect,
            failure,
            io_kind,
            message: "тест".to_owned(),
            elapsed: Duration::from_millis(7),
        };
        let error = |attempts| ConnectError::Connect {
            target: Target::new("example.test", 1),
            attempts,
        };
        let table = [
            (ConnectFailure::Refused, ConnectErrorClass::Refused),
            (ConnectFailure::Reset, ConnectErrorClass::Reset),
            (ConnectFailure::Timeout, ConnectErrorClass::Timeout),
            (
                ConnectFailure::NetworkUnreachable,
                ConnectErrorClass::Unreachable,
            ),
            (
                ConnectFailure::HostUnreachable,
                ConnectErrorClass::Unreachable,
            ),
            (ConnectFailure::Other, ConnectErrorClass::Other),
        ];
        for (failure, class) in table {
            let first = attempt(ConnectFailure::Timeout, io::ErrorKind::TimedOut);
            let last = attempt(failure, io::ErrorKind::Other);
            assert_eq!(error(vec![first, last]).class(), class, "{failure:?}");
        }
        assert_eq!(error(Vec::new()).class(), ConnectErrorClass::Other);
        assert_eq!(error(Vec::new()).io_kind(), None);

        let refused = error(vec![attempt(
            ConnectFailure::Refused,
            io::ErrorKind::ConnectionRefused,
        )]);
        assert_eq!(refused.io_kind(), Some(io::ErrorKind::ConnectionRefused));
        let text = refused.to_string();
        // Сообщение не теряет цель, этап, адрес и исходный вид ошибки.
        for part in [
            "example.test:1",
            "connect",
            "127.0.0.1:1",
            "отказ в соединении",
            "ConnectionRefused",
            "7 мс",
        ] {
            assert!(text.contains(part), "нет `{part}` в `{text}`");
        }
    }

    #[tokio::test]
    async fn connects_to_local_listener_and_counts_the_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (resolver, connector) = connector(&[], fast_config());
        let target_scope = connector.stats().child();
        let check_scope = target_scope.child();

        let target = Target::new("127.0.0.1", addr.port());
        let conn = connector.connect(&target, &check_scope).await.unwrap();
        let (_accepted, client_addr) = listener.accept().await.unwrap();

        assert_eq!(conn.peer_addr(), addr);
        assert_eq!(conn.server_name(), None);
        assert_eq!(conn.timeouts(), &fast_config().timeouts);
        assert!(conn.stream().nodelay().unwrap(), "TCP_NODELAY включён");
        assert_eq!(conn.stream().local_addr().unwrap(), client_addr);
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            0,
            "литерал не резолвится"
        );

        for scope in [&check_scope, &target_scope, connector.stats()] {
            let snapshot = scope.snapshot();
            assert_eq!(snapshot.attempts, 1);
            assert_eq!(snapshot.connections, 1);
            assert_eq!(snapshot.connect_time, conn.connect_time());
        }
    }

    #[tokio::test]
    async fn name_is_resolved_once_and_kept_for_sni() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (resolver, connector) = connector(&[LOOPBACK_V4], fast_config());
        let scope = connector.stats().child();
        let target = Target::new("stand.test", port);

        let first = connector.connect(&target, &scope).await.unwrap();
        let second = connector.connect(&target, &scope).await.unwrap();
        assert_eq!(first.server_name(), Some("stand.test"));
        assert_eq!(second.peer_addr(), SocketAddr::new(LOOPBACK_V4, port));
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            1,
            "повторный connect берёт адрес из кэша"
        );
        assert_eq!(scope.snapshot().connections, 2);
    }

    #[tokio::test]
    async fn ip_override_connects_to_the_given_address_and_keeps_the_name() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = ConnectorConfig {
            resolve: ResolveOptions {
                ip_override: Some(LOOPBACK_V4),
                mode: DnsMode::Disabled,
                ..ResolveOptions::default()
            },
            ..fast_config()
        };
        let (resolver, connector) = connector(&[], config);
        let scope = connector.stats().child();

        let conn = connector
            .connect(&Target::new("real-name.test", port), &scope)
            .await
            .unwrap();
        assert_eq!(conn.peer_addr(), SocketAddr::new(LOOPBACK_V4, port));
        assert_eq!(conn.server_name(), Some("real-name.test"));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn closed_port_is_refused_with_one_attempt() {
        let port = closed_port();
        let (_resolver, connector) = connector(&[], fast_config());
        let scope = connector.stats().child();

        let error = connector
            .connect(&Target::new("127.0.0.1", port), &scope)
            .await
            .unwrap_err();
        assert_eq!(error.class(), ConnectErrorClass::Refused);
        assert_eq!(error.io_kind(), Some(io::ErrorKind::ConnectionRefused));
        assert_eq!(error.attempts().len(), 1);
        let attempt = error.attempts().first().unwrap();
        assert_eq!(attempt.addr, SocketAddr::new(LOOPBACK_V4, port));
        assert_eq!(attempt.stage, ConnectStage::Connect);
        assert_eq!(attempt.failure, ConnectFailure::Refused);
        let text = error.to_string();
        assert!(text.contains(&format!("127.0.0.1:{port}")), "{text}");
        assert!(text.contains("connect"), "{text}");

        let snapshot = scope.snapshot();
        assert_eq!(snapshot.attempts, 1);
        assert_eq!(snapshot.connections, 0);
        assert_eq!(connector.stats().snapshot().attempts, 1);
    }

    #[tokio::test]
    async fn next_address_is_tried_after_a_failed_one() {
        // Слушаем только на IPv4; резолвер первым отдаёт IPv6-loopback, где
        // этот порт закрыт (или IPv6 недоступен вовсе) — попытка неудачна.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (_resolver, connector) = connector(&[LOOPBACK_V6, LOOPBACK_V4], fast_config());
        let scope = connector.stats().child();

        let conn = connector
            .connect(&Target::new("dual.test", port), &scope)
            .await
            .unwrap();
        assert_eq!(conn.peer_addr(), SocketAddr::new(LOOPBACK_V4, port));
        let snapshot = scope.snapshot();
        assert_eq!(snapshot.attempts, 2);
        assert_eq!(snapshot.connections, 1);
    }

    #[tokio::test]
    async fn address_family_and_max_addresses_limit_the_attempts() {
        let port = closed_port();

        // Только IPv4: IPv6-адрес не пробуется.
        let v4_only = ConnectorConfig {
            resolve: ResolveOptions {
                family: AddressFamily::V4Only,
                ..ResolveOptions::default()
            },
            ..fast_config()
        };
        let (_resolver, connector_v4) = connector(&[LOOPBACK_V6, LOOPBACK_V4], v4_only);
        let target = Target::new("dual.test", port);
        assert_eq!(
            connector_v4.resolve(&target).await.unwrap(),
            vec![SocketAddr::new(LOOPBACK_V4, port)]
        );
        let scope = connector_v4.stats().child();
        let error = connector_v4.connect(&target, &scope).await.unwrap_err();
        assert_eq!(error.attempts().len(), 1);
        assert_eq!(error.class(), ConnectErrorClass::Refused);

        // Не более одного адреса на вызов: пробуется только первый.
        let single = ConnectorConfig {
            max_addresses: 1,
            ..fast_config()
        };
        let (_resolver, connector_one) = connector(&[LOOPBACK_V4, LOOPBACK_V6], single);
        let scope = connector_one.stats().child();
        let error = connector_one.connect(&target, &scope).await.unwrap_err();
        assert_eq!(error.attempts().len(), 1);
        assert_eq!(scope.snapshot().attempts, 1);

        // Ноль трактуется как один.
        let zero = ConnectorConfig {
            max_addresses: 0,
            ..fast_config()
        };
        let (_resolver, connector_zero) = connector(&[LOOPBACK_V4, LOOPBACK_V6], zero);
        assert_eq!(connector_zero.resolve(&target).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unresolved_name_opens_no_connections() {
        let (resolver, connector) = connector(&[], fast_config());
        let scope = connector.stats().child();
        let target = Target::new("missing.test", 443);

        let error = connector.connect(&target, &scope).await.unwrap_err();
        assert_eq!(error.class(), ConnectErrorClass::Unresolved);
        assert_eq!(error.io_kind(), Some(io::ErrorKind::NotFound));
        assert_eq!(error.target(), &target);
        assert!(error.attempts().is_empty());
        assert!(error.to_string().contains("missing.test:443"), "{error}");
        assert!(error.to_string().contains("резолв"), "{error}");
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(scope.snapshot().attempts, 0);

        // Отказ резолвера закэширован: второго обращения нет.
        connector.connect(&target, &scope).await.unwrap_err();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn connect_timeout_is_reported_as_timeout() {
        let addr = SocketAddr::new(LOOPBACK_V4, 9);
        let never = std::future::pending::<io::Result<()>>();
        let (result, elapsed) = timed_connect(addr, Duration::from_secs(3), never).await;

        assert_eq!(elapsed, Duration::from_secs(3));
        let attempt = result.unwrap_err();
        assert_eq!(attempt.addr, addr);
        assert_eq!(attempt.stage, ConnectStage::Connect);
        assert_eq!(attempt.failure, ConnectFailure::Timeout);
        assert_eq!(attempt.io_kind, io::ErrorKind::TimedOut);
        assert_eq!(attempt.elapsed, Duration::from_secs(3));
        assert!(attempt.to_string().contains("3000"), "{attempt}");
    }

    #[tokio::test(start_paused = true)]
    async fn connect_error_from_the_kernel_keeps_its_kind() {
        let addr = SocketAddr::new(LOOPBACK_V4, 9);
        let failing =
            async { Err::<(), _>(io::Error::new(io::ErrorKind::ConnectionReset, "сброс")) };
        let (result, elapsed) = timed_connect(addr, Duration::from_secs(3), failing).await;

        assert_eq!(elapsed, Duration::ZERO);
        let attempt = result.unwrap_err();
        assert_eq!(attempt.failure, ConnectFailure::Reset);
        assert_eq!(attempt.io_kind, io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn conn_wraps_any_transport() {
        let (client, _server) = tokio::io::duplex(64);
        let peer = SocketAddr::new(LOOPBACK_V4, 4433);
        let conn = Conn::from_stream(
            client,
            peer,
            Some("stand.test".to_owned()),
            Timeouts::default(),
        );
        assert_eq!(conn.connect_time(), Duration::ZERO);

        let mut wrapped = conn.map_stream(tokio::io::BufReader::new);
        assert_eq!(wrapped.peer_addr(), peer);
        assert_eq!(wrapped.server_name(), Some("stand.test"));
        let _stream: &mut tokio::io::BufReader<tokio::io::DuplexStream> = wrapped.stream_mut();
        let _inner = wrapped.into_stream();
    }
}
