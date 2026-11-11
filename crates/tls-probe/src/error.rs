//! Ошибки кодека: [`ParseError`] для разбора и [`EncodeError`] для сборки.
//!
//! Любая ошибка — значение, паник в кодеке нет. Позиция в [`ParseError`] —
//! смещение от начала исходного буфера, в том числе во вложенных читателях.

use std::fmt;

/// Сколько первых байтов ответа сохраняется в [`ParseError::NotTls`].
pub const NOT_TLS_PREFIX_LEN: usize = 16;

/// Ошибка разбора входных данных.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Данные закончились раньше, чем прочитано требуемое число байтов.
    UnexpectedEof {
        /// Смещение, с которого выполнялось чтение.
        position: usize,
        /// Сколько байтов требовалось.
        needed: usize,
        /// Сколько байтов было доступно.
        available: usize,
    },
    /// После разбора остались непрочитанные байты.
    TrailingBytes {
        /// Смещение первого лишнего байта.
        position: usize,
        /// Число лишних байтов.
        remaining: usize,
    },
    /// Длина из входных данных превышает лимит разбора.
    LimitExceeded {
        /// Смещение элемента, длина которого проверялась.
        position: usize,
        /// Название лимита.
        limit: &'static str,
        /// Значение лимита.
        max: usize,
        /// Фактическая длина.
        actual: usize,
    },
    /// Поле содержит значение, недопустимое в этом месте.
    InvalidValue {
        /// Смещение поля.
        position: usize,
        /// Что именно недопустимо.
        what: &'static str,
    },
    /// Данные не похожи на TLS: первый байт — не известный тип записи либо
    /// старший байт версии записи не равен 3. Так выглядят HTTP-текст,
    /// баннер SMTP и ответ SSLv2.
    NotTls {
        /// Смещение начала данных, обычно 0.
        position: usize,
        /// Первые байты ответа, дополненные нулями до размера массива.
        prefix: [u8; NOT_TLS_PREFIX_LEN],
        /// Сколько байтов `prefix` значимы.
        prefix_len: usize,
    },
    /// Нарушен внутренний инвариант разбора. Это дефект `tls-probe`, а не
    /// свойство входных данных: на корректно работающем коде ошибка не
    /// возникает. Возвращается вместо паники.
    Internal {
        /// Смещение в потоке на момент обнаружения.
        position: usize,
        /// Какой инвариант нарушен.
        what: &'static str,
    },
}

impl ParseError {
    /// Смещение от начала исходного буфера, к которому относится ошибка.
    #[must_use]
    pub fn position(&self) -> usize {
        match *self {
            Self::UnexpectedEof { position, .. }
            | Self::TrailingBytes { position, .. }
            | Self::LimitExceeded { position, .. }
            | Self::InvalidValue { position, .. }
            | Self::NotTls { position, .. }
            | Self::Internal { position, .. } => position,
        }
    }

    /// Первые байты ответа, если ошибка — [`ParseError::NotTls`].
    #[must_use]
    pub fn not_tls_prefix(&self) -> Option<&[u8]> {
        match self {
            Self::NotTls {
                prefix, prefix_len, ..
            } => Some(prefix.get(..*prefix_len).unwrap_or(prefix)),
            _ => None,
        }
    }

    /// Та же ошибка с позицией, сдвинутой на `base`: переводит смещение
    /// внутри буфера декодера в смещение в потоке.
    #[must_use]
    pub(crate) fn offset_by(self, base: usize) -> Self {
        match self {
            Self::UnexpectedEof {
                position,
                needed,
                available,
            } => Self::UnexpectedEof {
                position: position.saturating_add(base),
                needed,
                available,
            },
            Self::TrailingBytes {
                position,
                remaining,
            } => Self::TrailingBytes {
                position: position.saturating_add(base),
                remaining,
            },
            Self::LimitExceeded {
                position,
                limit,
                max,
                actual,
            } => Self::LimitExceeded {
                position: position.saturating_add(base),
                limit,
                max,
                actual,
            },
            Self::InvalidValue { position, what } => Self::InvalidValue {
                position: position.saturating_add(base),
                what,
            },
            Self::NotTls {
                position,
                prefix,
                prefix_len,
            } => Self::NotTls {
                position: position.saturating_add(base),
                prefix,
                prefix_len,
            },
            Self::Internal { position, what } => Self::Internal {
                position: position.saturating_add(base),
                what,
            },
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UnexpectedEof {
                position,
                needed,
                available,
            } => write!(
                f,
                "неожиданный конец данных на смещении {position}: требовалось байтов: {needed}, доступно: {available}"
            ),
            Self::TrailingBytes {
                position,
                remaining,
            } => write!(
                f,
                "лишние байты на смещении {position}: осталось непрочитанных: {remaining}"
            ),
            Self::LimitExceeded {
                position,
                limit,
                max,
                actual,
            } => write!(
                f,
                "превышен лимит `{limit}` на смещении {position}: допустимо {max}, получено {actual}"
            ),
            Self::InvalidValue { position, what } => {
                write!(f, "недопустимое значение на смещении {position}: {what}")
            }
            Self::NotTls {
                position,
                prefix,
                prefix_len,
            } => {
                write!(
                    f,
                    "данные на смещении {position} не похожи на TLS, первые байты:"
                )?;
                for byte in prefix.iter().take(prefix_len) {
                    write!(f, " {byte:02x}")?;
                }
                Ok(())
            }
            Self::Internal { position, what } => write!(
                f,
                "внутренняя ошибка разбора на смещении {position}: {what}"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Ошибка сборки выходных данных.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// Длина тела вектора не помещается в префикс длины.
    LengthOverflow {
        /// Размер префикса в байтах: 1, 2 или 3.
        prefix_bytes: usize,
        /// Наибольшая длина, представимая префиксом.
        max: u32,
        /// Фактическая длина тела.
        actual: usize,
    },
    /// Значение не помещается в поле фиксированного размера.
    ValueOverflow {
        /// Наибольшее представимое значение.
        max: u32,
        /// Фактическое значение.
        actual: u32,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::LengthOverflow {
                prefix_bytes,
                max,
                actual,
            } => write!(
                f,
                "длина вектора {actual} не помещается в префикс из {prefix_bytes} байт (максимум {max})"
            ),
            Self::ValueOverflow { max, actual } => {
                write!(f, "значение {actual} не помещается в поле (максимум {max})")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_position_and_display() {
        let errors = [
            ParseError::UnexpectedEof {
                position: 7,
                needed: 4,
                available: 1,
            },
            ParseError::TrailingBytes {
                position: 7,
                remaining: 3,
            },
            ParseError::LimitExceeded {
                position: 7,
                limit: "max_record_len",
                max: 10,
                actual: 11,
            },
            ParseError::InvalidValue {
                position: 7,
                what: "тест",
            },
            ParseError::NotTls {
                position: 7,
                prefix: [0x48; NOT_TLS_PREFIX_LEN],
                prefix_len: 4,
            },
            ParseError::Internal {
                position: 7,
                what: "тест",
            },
        ];
        for error in errors {
            assert_eq!(error.offset_by(3).position(), 10);
            assert_eq!(error.position(), 7);
            let text = error.to_string();
            assert!(text.contains('7'), "{text}");
            let source: &dyn std::error::Error = &error;
            assert!(source.source().is_none());
        }
        assert!(
            errors
                .iter()
                .any(|error| error.to_string().contains("max_record_len"))
        );
    }

    #[test]
    fn not_tls_prefix_and_display() {
        let mut prefix = [0_u8; NOT_TLS_PREFIX_LEN];
        prefix[..4].copy_from_slice(b"HTTP");
        let error = ParseError::NotTls {
            position: 0,
            prefix,
            prefix_len: 4,
        };
        assert_eq!(error.not_tls_prefix(), Some(&b"HTTP"[..]));
        assert!(error.to_string().ends_with("48 54 54 50"), "{error}");

        // Длина больше массива не приводит к панике: возвращается весь массив.
        let oversized = ParseError::NotTls {
            position: 0,
            prefix,
            prefix_len: NOT_TLS_PREFIX_LEN + 1,
        };
        assert_eq!(
            oversized.not_tls_prefix().map(<[u8]>::len),
            Some(NOT_TLS_PREFIX_LEN)
        );

        let other = ParseError::InvalidValue {
            position: 1,
            what: "версия записи",
        };
        assert_eq!(other.not_tls_prefix(), None);
        assert!(other.to_string().contains("версия записи"));
    }

    #[test]
    fn encode_error_display() {
        let overflow = EncodeError::LengthOverflow {
            prefix_bytes: 2,
            max: 0xFFFF,
            actual: 70_000,
        };
        let text = overflow.to_string();
        assert!(text.contains("70000") && text.contains("65535"), "{text}");

        let value = EncodeError::ValueOverflow {
            max: 0x00FF_FFFF,
            actual: 0x0100_0000,
        };
        assert!(value.to_string().contains("16777216"));
        assert_ne!(overflow, value);
    }
}
