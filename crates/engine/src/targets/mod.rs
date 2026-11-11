//! Разбор и поток целей.
//!
//! Состав:
//!
//! - [`parse`] — разбор одной записи: имя, адрес, URL, сеть;
//! - [`cidr`] — ленивое разворачивание сети;
//! - [`file`] — потоковое чтение файла целей;
//! - [`TargetStream`] — поток целей из аргументов, файлов и сетей.
//!
//! # Обратное давление и память
//!
//! Цели готовит отдельная задача-производитель и передаёт потребителю
//! через ограниченный канал. Перед каждой целью производитель резервирует
//! место в канале и, пока его нет, не читает следующую строку файла и не
//! берёт следующий адрес сети. Поэтому число подготовленных, но ещё не
//! забранных целей не превышает [`TargetOptions::buffer`], а память не
//! зависит ни от размера файла, ни от размера сети: в ней буфер канала,
//! буфер чтения файла, одна строка и счётчик адресов.
//!
//! Сброс [`TargetStream`] останавливает производителя.
//!
//! # Ошибки
//!
//! Некорректная запись, слишком длинная строка, слишком большая сеть и
//! ошибка чтения приходят потребителю элементом `Err` с файлом и номером
//! строки. Что дальше — задаёт [`TargetOptions::on_error`]: продолжить со
//! следующей записи ([`OnError::Skip`], потребитель выводит
//! предупреждение) либо закончить поток ([`OnError::Stop`]).
//!
//! # Чего здесь нет
//!
//! Порядок целей — порядок источников, адреса сети идут по возрастанию;
//! дедупликации и перемешивания нет: план их не требует. Реализации trait
//! `Stream` тоже нет — она потребовала бы внешней зависимости; потребитель
//! вызывает [`TargetStream::next`].

pub mod cidr;
pub mod file;
pub mod parse;

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncBufRead, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub use cidr::{Cidr, CidrAddresses, DEFAULT_MAX_CIDR_ADDRESSES, NetworkTooLarge};
pub use file::{DEFAULT_MAX_LINE_LEN, Line, LineError, LineErrorKind, LineReader, OnError};
pub use parse::{
    DEFAULT_PORT, ScanTarget, TargetError, TargetErrorKind, TargetHost, TargetSpec, parse_target,
};

/// Размер буфера потока целей по умолчанию.
pub const DEFAULT_STREAM_BUFFER: usize = 64;

/// Параметры потока целей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetOptions {
    /// Порт для записей без порта.
    pub default_port: u16,
    /// Имя для SNI для всех целей (`--sni`).
    pub sni: Option<String>,
    /// Адрес соединения для всех целей (`--ip`).
    pub ip_override: Option<IpAddr>,
    /// Предел числа адресов одной сети.
    pub max_cidr_addresses: u64,
    /// Предел длины строки файла целей, в байтах.
    pub max_line_len: usize,
    /// Что делать после ошибочной записи.
    pub on_error: OnError,
    /// Сколько подготовленных целей может ждать потребителя; ноль
    /// трактуется как 1.
    pub buffer: usize,
}

impl Default for TargetOptions {
    fn default() -> Self {
        Self {
            default_port: DEFAULT_PORT,
            sni: None,
            ip_override: None,
            max_cidr_addresses: DEFAULT_MAX_CIDR_ADDRESSES,
            max_line_len: DEFAULT_MAX_LINE_LEN,
            on_error: OnError::default(),
            buffer: DEFAULT_STREAM_BUFFER,
        }
    }
}

/// Источник целей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSource {
    /// Запись из командной строки: цель или сеть.
    Spec(String),
    /// Файл целей.
    File(PathBuf),
}

/// Вид ошибки потока целей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetStreamErrorKind {
    /// Некорректная запись цели.
    Target(TargetError),
    /// Ошибка чтения строки файла.
    Line(LineErrorKind),
    /// Файл целей не открылся.
    Open {
        /// Вид ошибки.
        kind: io::ErrorKind,
        /// Текст ошибки.
        message: String,
    },
}

/// Ошибка потока целей с указанием места.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetStreamError {
    /// Файл целей, если запись из файла.
    pub file: Option<PathBuf>,
    /// Номер строки, с единицы, если запись из файла или читателя.
    pub line: Option<u64>,
    /// Вид ошибки.
    pub kind: TargetStreamErrorKind,
}

impl fmt::Display for TargetStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(file) = &self.file {
            write!(f, "{}: ", file.display())?;
        }
        if let Some(line) = self.line {
            write!(f, "строка {line}: ")?;
        }
        match &self.kind {
            TargetStreamErrorKind::Target(error) => write!(f, "{error}"),
            TargetStreamErrorKind::Line(kind) => write!(f, "{kind}"),
            TargetStreamErrorKind::Open { message, .. } => {
                write!(f, "файл целей не открылся: {message}")
            }
        }
    }
}

impl std::error::Error for TargetStreamError {}

/// Элемент потока: цель либо ошибка записи.
pub type TargetItem = Result<ScanTarget, TargetStreamError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

/// Производитель целей: пишет в канал, соблюдая обратное давление.
#[derive(Debug)]
struct Producer {
    tx: mpsc::Sender<TargetItem>,
    options: TargetOptions,
    produced: Arc<AtomicU64>,
}

impl Producer {
    /// Ждёт место в канале и отдаёт элемент; `Stop`, если потребителя нет.
    async fn emit(&self, item: TargetItem) -> Flow {
        let Ok(permit) = self.tx.reserve().await else {
            return Flow::Stop;
        };
        self.produced.fetch_add(1, Ordering::Relaxed);
        permit.send(item);
        Flow::Continue
    }

    /// Отдаёт ошибку и решает, продолжать ли.
    async fn fail(&self, error: TargetStreamError) -> Flow {
        if self.emit(Err(error)).await == Flow::Stop {
            return Flow::Stop;
        }
        match self.options.on_error {
            OnError::Skip => Flow::Continue,
            OnError::Stop => Flow::Stop,
        }
    }

    fn target(&self, host: TargetHost, port: u16, path: Option<String>) -> ScanTarget {
        ScanTarget {
            host,
            port,
            sni: self.options.sni.clone(),
            ip_override: self.options.ip_override,
            path,
        }
    }

    /// Одна запись: цель либо сеть.
    async fn spec(&self, text: &str, file: Option<&Path>, line: Option<u64>) -> Flow {
        let located = |error: TargetError| TargetStreamError {
            file: file.map(Path::to_path_buf),
            line,
            kind: TargetStreamErrorKind::Target(error),
        };
        match parse_target(text, self.options.default_port) {
            Ok(TargetSpec::Single(target)) => {
                let target = self.target(target.host, target.port, target.path);
                self.emit(Ok(target)).await
            }
            Ok(TargetSpec::Network { cidr, port }) => {
                match cidr.addresses(self.options.max_cidr_addresses) {
                    Ok(addresses) => {
                        for addr in addresses {
                            let target = self.target(TargetHost::Ip(addr), port, None);
                            if self.emit(Ok(target)).await == Flow::Stop {
                                return Flow::Stop;
                            }
                        }
                        Flow::Continue
                    }
                    Err(too_large) => {
                        let error = TargetError {
                            input: text.to_owned(),
                            kind: TargetErrorKind::NetworkTooLarge {
                                host_bits: too_large.host_bits,
                                limit: too_large.limit,
                            },
                        };
                        self.fail(located(error)).await
                    }
                }
            }
            Err(error) => self.fail(located(error)).await,
        }
    }

    /// Строки читателя: по записи на строку.
    async fn reader<R>(&self, reader: R, file: Option<&Path>) -> Flow
    where
        R: AsyncBufRead + Unpin,
    {
        let mut lines = LineReader::new(reader, self.options.max_line_len);
        while let Some(entry) = lines.next_entry().await {
            let flow = match entry {
                Ok(line) => self.spec(&line.text, file, Some(line.number)).await,
                Err(error) => {
                    self.fail(TargetStreamError {
                        file: file.map(Path::to_path_buf),
                        line: Some(error.line),
                        kind: TargetStreamErrorKind::Line(error.kind),
                    })
                    .await
                }
            };
            if flow == Flow::Stop {
                return Flow::Stop;
            }
        }
        Flow::Continue
    }

    async fn source(&self, source: &TargetSource) -> Flow {
        match source {
            TargetSource::Spec(text) => self.spec(text, None, None).await,
            TargetSource::File(path) => match tokio::fs::File::open(path).await {
                Ok(file) => self.reader(BufReader::new(file), Some(path)).await,
                Err(error) => {
                    self.fail(TargetStreamError {
                        file: Some(path.clone()),
                        line: None,
                        kind: TargetStreamErrorKind::Open {
                            kind: error.kind(),
                            message: error.to_string(),
                        },
                    })
                    .await
                }
            },
        }
    }
}

/// Поток целей с обратным давлением; описание — в документации модуля.
#[derive(Debug)]
pub struct TargetStream {
    rx: mpsc::Receiver<TargetItem>,
    produced: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl TargetStream {
    /// Поток из источников в заданном порядке. Вызывать внутри runtime
    /// tokio: производитель — отдельная задача.
    #[must_use]
    pub fn new(sources: Vec<TargetSource>, options: TargetOptions) -> Self {
        Self::spawn(options, move |producer| async move {
            for source in &sources {
                if producer.source(source).await == Flow::Stop {
                    break;
                }
            }
        })
    }

    /// Поток из читателя в формате файла целей (например, stdin). Вызывать
    /// внутри runtime tokio.
    #[must_use]
    pub fn from_reader<R>(reader: R, options: TargetOptions) -> Self
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        Self::spawn(options, move |producer| async move {
            producer.reader(reader, None).await;
        })
    }

    fn spawn<F, Fut>(options: TargetOptions, run: F) -> Self
    where
        F: FnOnce(Producer) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(options.buffer.max(1));
        let produced = Arc::new(AtomicU64::new(0));
        let producer = Producer {
            tx,
            options,
            produced: Arc::clone(&produced),
        };
        Self {
            rx,
            produced,
            task: tokio::spawn(run(producer)),
        }
    }

    /// Следующая цель либо ошибка записи; `None`, когда источники
    /// исчерпаны или поток остановлен ошибкой.
    pub async fn next(&mut self) -> Option<TargetItem> {
        self.rx.recv().await
    }

    /// Сколько элементов производитель подготовил с начала работы:
    /// забранные потребителем плюс ждущие в буфере.
    #[must_use]
    pub fn produced(&self) -> u64 {
        self.produced.load(Ordering::Relaxed)
    }
}

impl Drop for TargetStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, ReadBuf};
    use tokio::task::yield_now;

    use super::*;

    const BUFFER: usize = 8;
    const BUFFER_U64: u64 = 8;

    fn specs(list: &[&str]) -> Vec<TargetSource> {
        list.iter()
            .map(|text| TargetSource::Spec((*text).to_owned()))
            .collect()
    }

    fn reader(text: &str) -> Cursor<Vec<u8>> {
        Cursor::new(text.as_bytes().to_vec())
    }

    async fn collect(mut stream: TargetStream) -> Vec<TargetItem> {
        let mut items = Vec::new();
        while let Some(item) = stream.next().await {
            items.push(item);
        }
        items
    }

    fn rendered(items: &[TargetItem]) -> Vec<String> {
        items
            .iter()
            .map(|item| match item {
                Ok(target) => target.to_string(),
                Err(error) => format!("ошибка: {error}"),
            })
            .collect()
    }

    /// Даёт производителю поработать, пока он не упрётся в буфер.
    async fn settle() {
        for _ in 0..100 {
            yield_now().await;
        }
    }

    #[tokio::test]
    async fn specs_and_networks_come_in_order() {
        let stream = TargetStream::new(
            specs(&[
                "example.com",
                "10.0.0.0/30:8443",
                "[2001:db8::1]:8443",
                "https://example.org/status",
            ]),
            TargetOptions::default(),
        );
        let items = collect(stream).await;
        assert_eq!(
            rendered(&items),
            vec![
                "example.com:443",
                "10.0.0.0:8443",
                "10.0.0.1:8443",
                "10.0.0.2:8443",
                "10.0.0.3:8443",
                "[2001:db8::1]:8443",
                "example.org:443/status",
            ]
        );
    }

    #[tokio::test]
    async fn sni_ip_and_default_port_apply_to_every_target() {
        let addr: IpAddr = "198.51.100.7".parse().unwrap();
        let options = TargetOptions {
            default_port: 8443,
            sni: Some("front.example".to_owned()),
            ip_override: Some(addr),
            ..TargetOptions::default()
        };
        let stream = TargetStream::new(specs(&["example.com", "10.0.0.0/31"]), options);
        let items = collect(stream).await;
        assert_eq!(items.len(), 3);
        for item in items {
            let target = item.unwrap();
            assert_eq!(target.port, 8443);
            assert_eq!(target.server_name(), Some("front.example"));
            assert_eq!(target.connect_ip(), Some(addr));
        }
    }

    #[tokio::test]
    async fn oversized_network_is_an_error_and_the_stream_goes_on() {
        let options = TargetOptions {
            max_cidr_addresses: 256,
            ..TargetOptions::default()
        };
        let stream = TargetStream::new(
            specs(&["10.0.0.0/8", "2001:db8::/64", "example.com"]),
            options,
        );
        let items = collect(stream).await;
        assert_eq!(items.len(), 3);
        let first = items.first().unwrap().as_ref().unwrap_err();
        assert_eq!(first.file, None);
        assert_eq!(first.line, None);
        assert_eq!(
            first.kind,
            TargetStreamErrorKind::Target(TargetError {
                input: "10.0.0.0/8".to_owned(),
                kind: TargetErrorKind::NetworkTooLarge {
                    host_bits: 24,
                    limit: 256,
                },
            })
        );
        assert_eq!(
            first.to_string(),
            "некорректная цель «10.0.0.0/8»: в сети 2^24 адресов, предел — 256"
        );
        assert!(items.get(1).unwrap().is_err());
        assert_eq!(
            items.last().unwrap().as_ref().unwrap().to_string(),
            "example.com:443"
        );
    }

    const FILE: &str = "# цели\nexample.com\nexample.com:99999\n\n10.0.0.0/31 # сеть\nhttp://example.org\r\nexample.net:8443";

    #[tokio::test]
    async fn bad_lines_are_skipped_with_their_numbers() {
        let stream = TargetStream::from_reader(reader(FILE), TargetOptions::default());
        let items = collect(stream).await;
        assert_eq!(
            rendered(&items),
            vec![
                "example.com:443",
                "ошибка: строка 3: некорректная цель «example.com:99999»: порт должен быть числом от 1 до 65535",
                "10.0.0.0:443",
                "10.0.0.1:443",
                "ошибка: строка 6: некорректная цель «http://example.org»: поддерживается только схема https",
                "example.net:8443",
            ]
        );
        let error = items.get(1).unwrap().as_ref().unwrap_err();
        assert_eq!(error.line, Some(3));
        assert_eq!(error.file, None);
    }

    #[tokio::test]
    async fn first_bad_line_stops_the_stream_in_stop_mode() {
        let options = TargetOptions {
            on_error: OnError::Stop,
            ..TargetOptions::default()
        };
        let stream = TargetStream::from_reader(reader(FILE), options);
        let items = collect(stream).await;
        assert_eq!(items.len(), 2);
        assert!(items.first().unwrap().is_ok());
        assert_eq!(items.last().unwrap().as_ref().unwrap_err().line, Some(3));
    }

    #[tokio::test]
    async fn stop_mode_also_ends_the_remaining_sources() {
        let options = TargetOptions {
            on_error: OnError::Stop,
            ..TargetOptions::default()
        };
        let stream = TargetStream::new(specs(&["example.com", "bad:port", "example.org"]), options);
        let items = collect(stream).await;
        assert_eq!(items.len(), 2);
        assert!(items.last().unwrap().is_err());
    }

    #[tokio::test]
    async fn too_long_line_is_reported_through_the_stream() {
        let options = TargetOptions {
            max_line_len: 16,
            ..TargetOptions::default()
        };
        let text = format!("example.com\n{}\nexample.org\n", "a".repeat(500));
        let stream = TargetStream::from_reader(reader(&text), options);
        let items = collect(stream).await;
        assert_eq!(items.len(), 3);
        let error = items.get(1).unwrap().as_ref().unwrap_err();
        assert_eq!(error.line, Some(2));
        assert_eq!(
            error.kind,
            TargetStreamErrorKind::Line(LineErrorKind::TooLong { limit: 16 })
        );
        assert_eq!(error.to_string(), "строка 2: строка длиннее 16 байт");
    }

    #[tokio::test]
    async fn file_source_is_read_and_a_missing_file_is_an_error() {
        let path =
            std::env::temp_dir().join(format!("certscan-targets-{}.txt", std::process::id()));
        std::fs::write(&path, "example.com\nbad:port\n192.0.2.1:8443\n").unwrap();
        let missing = path.with_extension("missing");

        let sources = vec![
            TargetSource::File(missing.clone()),
            TargetSource::File(path.clone()),
            TargetSource::Spec("example.org".to_owned()),
        ];
        let items = collect(TargetStream::new(sources, TargetOptions::default())).await;
        std::fs::remove_file(&path).unwrap();

        assert_eq!(items.len(), 5);
        let open = items.first().unwrap().as_ref().unwrap_err();
        assert_eq!(open.file.as_deref(), Some(missing.as_path()));
        assert_eq!(open.line, None);
        assert!(matches!(
            open.kind,
            TargetStreamErrorKind::Open {
                kind: io::ErrorKind::NotFound,
                ..
            }
        ));
        let bad = items.get(2).unwrap().as_ref().unwrap_err();
        assert_eq!(bad.file.as_deref(), Some(path.as_path()));
        assert_eq!(bad.line, Some(2));
        assert!(
            bad.to_string()
                .starts_with(&format!("{}: строка 2: ", path.display()))
        );
        assert_eq!(
            items.last().unwrap().as_ref().unwrap().to_string(),
            "example.org:443"
        );
    }

    #[tokio::test]
    async fn producer_never_runs_ahead_of_the_buffer() {
        let options = TargetOptions {
            buffer: BUFFER,
            ..TargetOptions::default()
        };
        let mut stream = TargetStream::new(specs(&["10.0.0.0/16"]), options);
        settle().await;
        assert_eq!(stream.produced(), BUFFER_U64);

        let mut consumed: u64 = 0;
        for _ in 0..10 {
            assert!(stream.next().await.is_some());
            consumed = consumed.saturating_add(1);
        }
        settle().await;
        assert_eq!(stream.produced(), consumed.saturating_add(BUFFER_U64));

        let mut last = None;
        while let Some(item) = stream.next().await {
            consumed = consumed.saturating_add(1);
            assert!(stream.produced() <= consumed.saturating_add(BUFFER_U64));
            last = Some(item);
        }
        assert_eq!(consumed, 65_536);
        assert_eq!(stream.produced(), 65_536);
        assert_eq!(last.unwrap().unwrap().to_string(), "10.0.255.255:443");
    }

    #[tokio::test]
    async fn zero_buffer_is_treated_as_one() {
        let options = TargetOptions {
            buffer: 0,
            ..TargetOptions::default()
        };
        let mut stream = TargetStream::new(specs(&["10.0.0.0/24"]), options);
        settle().await;
        assert_eq!(stream.produced(), 1);
        let mut count = 0;
        while stream.next().await.is_some() {
            count += 1;
        }
        assert_eq!(count, 256);
    }

    #[tokio::test]
    async fn dropping_the_stream_stops_the_producer() {
        let options = TargetOptions {
            buffer: BUFFER,
            ..TargetOptions::default()
        };
        let mut stream = TargetStream::new(specs(&["10.0.0.0/16"]), options);
        assert!(stream.next().await.is_some());
        settle().await;
        let produced = Arc::clone(&stream.produced);
        let before = produced.load(Ordering::Relaxed);
        drop(stream);
        settle().await;
        assert_eq!(produced.load(Ordering::Relaxed), before);
        // Задача завершена: счётчик больше никто не держит.
        assert_eq!(Arc::strong_count(&produced), 1);
    }

    /// Источник, порождающий строки на лету: файл любого размера без памяти
    /// под него.
    struct Generated {
        next: u32,
        total: u32,
        pending: Vec<u8>,
        offset: usize,
    }

    impl AsyncRead for Generated {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = &mut *self;
            while buf.remaining() > 0 {
                if this.offset >= this.pending.len() {
                    if this.next >= this.total {
                        break;
                    }
                    this.pending.clear();
                    this.offset = 0;
                    writeln!(this.pending, "h{}.example", this.next)?;
                    this.next += 1;
                }
                let rest = this.pending.get(this.offset..).unwrap_or_default();
                let take = rest.len().min(buf.remaining());
                buf.put_slice(rest.get(..take).unwrap_or_default());
                this.offset += take;
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn million_lines_are_read_with_constant_memory() {
        const LINES: u32 = 1_000_000;
        let source = BufReader::new(Generated {
            next: 0,
            total: LINES,
            pending: Vec::new(),
            offset: 0,
        });
        let options = TargetOptions::default();
        let buffer = u64::try_from(options.buffer).unwrap();
        let mut stream = TargetStream::from_reader(source, options);
        let mut consumed: u64 = 0;
        let mut max_ahead: u64 = 0;
        let mut last = None;
        while let Some(item) = stream.next().await {
            consumed = consumed.saturating_add(1);
            max_ahead = max_ahead.max(stream.produced().saturating_sub(consumed));
            last = Some(item);
        }
        assert_eq!(consumed, u64::from(LINES));
        // Подготовленных, но не забранных целей — не больше буфера.
        assert!(max_ahead <= buffer, "{max_ahead}");
        assert_eq!(last.unwrap().unwrap().to_string(), "h999999.example:443");
    }
}
