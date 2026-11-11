//! Файл целей: потоковое чтение по строкам.
//!
//! # Формат
//!
//! - одна запись на строку; формы записи — те же, что у аргумента командной
//!   строки (`crate::targets::parse`), включая сети;
//! - пустые строки и строки из одних пробелов пропускаются;
//! - комментарий начинается с `#` в начале строки либо после пробела и
//!   идёт до конца строки (`#` внутри записи, например фрагмент URL,
//!   комментарием не считается);
//! - перевод строки — LF или CRLF; последняя строка может не заканчиваться
//!   переводом строки; BOM в начале файла отбрасывается;
//! - кодировка — UTF-8.
//!
//! # Память
//!
//! [`LineReader`] читает из буфера источника и хранит не больше одной
//! строки, а строка ограничена [`LineReader::new`]`(_, max_line_len)`:
//! хвост слишком длинной строки пропускается без накопления. Память не
//! зависит ни от размера файла, ни от длины мусорной строки.
//!
//! Номер строки в [`Line`] и [`LineError`] — номер физической строки файла
//! с единицы, с учётом пропущенных.

use std::fmt;
use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Наибольшая длина строки файла целей по умолчанию, в байтах без перевода
/// строки. Самая длинная осмысленная запись — URL с путём; 4096 байт хватает
/// с запасом.
pub const DEFAULT_MAX_LINE_LEN: usize = 4096;

/// Что делать с ошибочной строкой файла целей.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OnError {
    /// Сообщить об ошибке и продолжить со следующей строки.
    #[default]
    Skip,
    /// Сообщить об ошибке и прекратить чтение.
    Stop,
}

/// Содержательная строка файла: запись цели без комментария и пробелов по
/// краям.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Номер строки в файле, с единицы.
    pub number: u64,
    /// Текст записи.
    pub text: String,
}

/// Вид ошибки чтения строки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineErrorKind {
    /// Ошибка ввода-вывода; чтение после неё прекращается.
    Io {
        /// Вид ошибки.
        kind: io::ErrorKind,
        /// Текст ошибки.
        message: String,
    },
    /// Строка длиннее предела.
    TooLong {
        /// Действующий предел, в байтах.
        limit: usize,
    },
    /// Строка не в UTF-8.
    InvalidUtf8,
}

impl fmt::Display for LineErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { message, .. } => write!(f, "ошибка чтения: {message}"),
            Self::TooLong { limit } => write!(f, "строка длиннее {limit} байт"),
            Self::InvalidUtf8 => f.write_str("строка не в UTF-8"),
        }
    }
}

/// Ошибка чтения строки файла целей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineError {
    /// Номер строки в файле, с единицы.
    pub line: u64,
    /// Вид ошибки.
    pub kind: LineErrorKind,
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "строка {}: {}", self.line, self.kind)
    }
}

impl std::error::Error for LineError {}

/// Построчный читатель файла целей; описание — в документации модуля.
#[derive(Debug)]
pub struct LineReader<R> {
    reader: R,
    max_line_len: usize,
    line: u64,
    buf: Vec<u8>,
    done: bool,
}

/// Отбрасывает комментарий: `#` в начале строки либо после пробела.
fn strip_comment(text: &str) -> &str {
    let mut after_space = true;
    for (index, symbol) in text.char_indices() {
        if symbol == '#' && after_space {
            return text.get(..index).unwrap_or(text);
        }
        after_space = symbol.is_whitespace();
    }
    text
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    /// Читатель поверх буферизованного источника. `max_line_len` — предел
    /// длины строки в байтах без перевода строки; ноль трактуется как 1.
    #[must_use]
    pub fn new(reader: R, max_line_len: usize) -> Self {
        Self {
            reader,
            max_line_len: max_line_len.max(1),
            line: 0,
            buf: Vec::new(),
            done: false,
        }
    }

    /// Номер последней прочитанной строки; ноль, если чтение не начато.
    #[must_use]
    pub fn line_number(&self) -> u64 {
        self.line
    }

    /// Следующая содержательная строка либо ошибка; `None` в конце файла и
    /// после ошибки ввода-вывода. Пустые строки и комментарии пропускаются.
    pub async fn next_entry(&mut self) -> Option<Result<Line, LineError>> {
        loop {
            if self.done {
                return None;
            }
            let overflow = match self.read_raw().await {
                Ok(Some(overflow)) => overflow,
                Ok(None) => {
                    self.done = true;
                    return None;
                }
                Err(error) => {
                    self.done = true;
                    return Some(Err(LineError {
                        line: self.line.saturating_add(1),
                        kind: LineErrorKind::Io {
                            kind: error.kind(),
                            message: error.to_string(),
                        },
                    }));
                }
            };
            self.line = self.line.saturating_add(1);
            let number = self.line;
            let fail = |kind| Some(Err(LineError { line: number, kind }));

            let bytes = self.buf.strip_suffix(b"\r").unwrap_or(&self.buf);
            if overflow || bytes.len() > self.max_line_len {
                return fail(LineErrorKind::TooLong {
                    limit: self.max_line_len,
                });
            }
            let Ok(text) = std::str::from_utf8(bytes) else {
                return fail(LineErrorKind::InvalidUtf8);
            };
            let text = if number == 1 {
                text.strip_prefix('\u{feff}').unwrap_or(text)
            } else {
                text
            };
            let text = strip_comment(text).trim();
            if !text.is_empty() {
                return Some(Ok(Line {
                    number,
                    text: text.to_owned(),
                }));
            }
        }
    }

    /// Читает физическую строку в буфер, не накапливая больше предела.
    /// `Ok(None)` — конец файла; `Ok(Some(overflow))` — строка прочитана,
    /// `overflow` истинно, если она не поместилась в буфер.
    async fn read_raw(&mut self) -> io::Result<Option<bool>> {
        self.buf.clear();
        // Один байт сверх предела — под `\r` строки предельной длины.
        let capacity = self.max_line_len.saturating_add(1);
        let mut overflow = false;
        let mut any = false;
        loop {
            let (consumed, newline) = {
                let available = self.reader.fill_buf().await?;
                if available.is_empty() {
                    return Ok(any.then_some(overflow));
                }
                let (chunk, newline) = match available.iter().position(|byte| *byte == b'\n') {
                    Some(end) => (available.get(..end).unwrap_or(available), true),
                    None => (available, false),
                };
                let room = capacity.saturating_sub(self.buf.len());
                match chunk.get(..room) {
                    Some(head) if chunk.len() > room => {
                        overflow = true;
                        self.buf.extend_from_slice(head);
                    }
                    _ => self.buf.extend_from_slice(chunk),
                }
                (chunk.len().saturating_add(usize::from(newline)), newline)
            };
            self.reader.consume(consumed);
            any = true;
            if newline {
                return Ok(Some(overflow));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, BufReader, ReadBuf};

    use super::*;

    async fn read_all(input: &[u8], max_line_len: usize) -> Vec<Result<Line, LineError>> {
        let mut reader = LineReader::new(input, max_line_len);
        let mut entries = Vec::new();
        while let Some(entry) = reader.next_entry().await {
            entries.push(entry);
        }
        entries
    }

    fn line(number: u64, text: &str) -> Result<Line, LineError> {
        Ok(Line {
            number,
            text: text.to_owned(),
        })
    }

    #[tokio::test]
    async fn comments_and_blank_lines_are_skipped() {
        let input = "# список целей\n\nexample.com\n   \n  # отступ\nexample.org:8443 # почта\n\t192.0.2.1\t\n";
        let entries = read_all(input.as_bytes(), DEFAULT_MAX_LINE_LEN).await;
        assert_eq!(
            entries,
            vec![
                line(3, "example.com"),
                line(6, "example.org:8443"),
                line(7, "192.0.2.1"),
            ]
        );
    }

    #[tokio::test]
    async fn hash_inside_an_entry_is_not_a_comment() {
        let input = "https://example.com/a#frag\nexample.com#x # настоящий комментарий\n";
        let entries = read_all(input.as_bytes(), DEFAULT_MAX_LINE_LEN).await;
        assert_eq!(
            entries,
            vec![
                line(1, "https://example.com/a#frag"),
                line(2, "example.com#x"),
            ]
        );
    }

    #[tokio::test]
    async fn crlf_and_bom_are_handled() {
        let input = "\u{feff}example.com\r\n\r\n# комментарий\r\nexample.org\r\n";
        let entries = read_all(input.as_bytes(), DEFAULT_MAX_LINE_LEN).await;
        assert_eq!(
            entries,
            vec![line(1, "example.com"), line(4, "example.org")]
        );
    }

    #[tokio::test]
    async fn last_line_without_a_newline_is_read() {
        let entries = read_all(b"example.com\nexample.org", DEFAULT_MAX_LINE_LEN).await;
        assert_eq!(
            entries,
            vec![line(1, "example.com"), line(2, "example.org")]
        );

        let entries = read_all(b"example.com", DEFAULT_MAX_LINE_LEN).await;
        assert_eq!(entries, vec![line(1, "example.com")]);
    }

    #[tokio::test]
    async fn empty_input_has_no_entries() {
        assert!(read_all(b"", DEFAULT_MAX_LINE_LEN).await.is_empty());
        assert!(read_all(b"\n\n", DEFAULT_MAX_LINE_LEN).await.is_empty());
        assert!(
            read_all("# только комментарий".as_bytes(), DEFAULT_MAX_LINE_LEN)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn too_long_line_is_reported_and_reading_continues() {
        const LIMIT: usize = 16;
        let long = "a".repeat(1000);
        let input = format!("example.com\n{long}\nexample.org\n");
        let entries = read_all(input.as_bytes(), LIMIT).await;
        assert_eq!(
            entries,
            vec![
                line(1, "example.com"),
                Err(LineError {
                    line: 2,
                    kind: LineErrorKind::TooLong { limit: LIMIT },
                }),
                line(3, "example.org"),
            ]
        );
        let error = LineError {
            line: 2,
            kind: LineErrorKind::TooLong { limit: LIMIT },
        };
        assert_eq!(error.to_string(), "строка 2: строка длиннее 16 байт");
    }

    #[tokio::test]
    async fn line_of_exactly_the_limit_is_accepted() {
        const LIMIT: usize = 11;
        let entries = read_all(b"example.com\nexample.com\r\nexample.com", LIMIT).await;
        assert_eq!(
            entries,
            vec![
                line(1, "example.com"),
                line(2, "example.com"),
                line(3, "example.com"),
            ]
        );
        let entries = read_all(b"example.comm\n", LIMIT).await;
        assert!(matches!(
            entries.first(),
            Some(Err(LineError {
                line: 1,
                kind: LineErrorKind::TooLong { limit: LIMIT },
            }))
        ));
    }

    #[tokio::test]
    async fn too_long_line_does_not_grow_the_buffer() {
        const LIMIT: usize = 16;
        let long = "a".repeat(100_000);
        let input = format!("{long}\nexample.com\n");
        let mut reader = LineReader::new(input.as_bytes(), LIMIT);
        assert!(
            reader
                .next_entry()
                .await
                .is_some_and(|entry| entry.is_err())
        );
        assert!(reader.buf.capacity() <= 64);
        assert_eq!(reader.next_entry().await, Some(line(2, "example.com")));
        assert_eq!(reader.line_number(), 2);
    }

    #[tokio::test]
    async fn invalid_utf8_is_reported_with_the_line_number() {
        let mut input = b"example.com\n".to_vec();
        input.extend_from_slice(b"\xff\xfe\n");
        input.extend_from_slice(b"example.org\n");
        let entries = read_all(&input, DEFAULT_MAX_LINE_LEN).await;
        assert_eq!(
            entries,
            vec![
                line(1, "example.com"),
                Err(LineError {
                    line: 2,
                    kind: LineErrorKind::InvalidUtf8,
                }),
                line(3, "example.org"),
            ]
        );
    }

    #[tokio::test]
    async fn result_does_not_depend_on_the_source_buffer_size() {
        let input = "# c\nexample.com\r\n\r\nexample.org:8443 # x\nочень-длинная-строка-с-мусором\n192.0.2.1";
        let expected = read_all(input.as_bytes(), 20).await;
        assert_eq!(expected.len(), 4);
        for capacity in 1..=8 {
            let source = BufReader::with_capacity(capacity, input.as_bytes());
            let mut reader = LineReader::new(source, 20);
            let mut entries = Vec::new();
            while let Some(entry) = reader.next_entry().await {
                entries.push(entry);
            }
            assert_eq!(entries, expected, "capacity {capacity}");
        }
    }

    /// Источник, который отдаёт одну строку, а затем ошибку.
    struct Failing {
        served: bool,
    }

    impl AsyncRead for Failing {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.served {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "нет доступа",
                )));
            }
            self.served = true;
            buf.put_slice(b"example.com\n");
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn io_error_is_reported_once_and_ends_the_reading() {
        let source = BufReader::new(Failing { served: false });
        let mut reader = LineReader::new(source, DEFAULT_MAX_LINE_LEN);
        assert_eq!(reader.next_entry().await, Some(line(1, "example.com")));
        let error = reader.next_entry().await.unwrap().unwrap_err();
        assert_eq!(error.line, 2);
        assert!(matches!(
            error.kind,
            LineErrorKind::Io {
                kind: io::ErrorKind::PermissionDenied,
                ..
            }
        ));
        assert_eq!(reader.next_entry().await, None);
    }
}
