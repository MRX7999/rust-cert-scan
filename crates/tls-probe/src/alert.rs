//! Разбор сообщения Alert.
//!
//! Сообщение alert — два байта: уровень и описание. Неизвестные значения
//! обоих полей сохраняются как числа; имя описания берётся из реестра IANA
//! в `tls-data`.
//!
//! Границы сообщений в потоке записей определяет декодер, а не этот модуль:
//! [`Event::Alert`](crate::decoder::Event::Alert) всегда несёт ровно два
//! байта, в том числе когда alert разбит на две записи или в одной записи
//! их несколько (в TLS 1.2 и ниже это допустимо, RFC 5246, раздел 6.2.1; в
//! TLS 1.3 запись alert содержит ровно одно сообщение, RFC 8446, раздел
//! 5.1). Пустую запись alert декодер отвергает.

use tls_data::AlertDescription;

use crate::codec::Reader;
use crate::error::ParseError;

/// Уровень alert (`AlertLevel`). Неизвестное значение сохраняется как есть.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AlertLevel(pub u8);

impl AlertLevel {
    /// `warning` (1).
    pub const WARNING: Self = Self(1);
    /// `fatal` (2).
    pub const FATAL: Self = Self(2);

    /// Имя уровня; `None` для неизвестного значения.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::WARNING => Some("warning"),
            Self::FATAL => Some("fatal"),
            _ => None,
        }
    }
}

/// Сообщение Alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    /// Уровень.
    pub level: AlertLevel,
    /// Описание; имя — [`AlertDescription::name`].
    pub description: AlertDescription,
}

impl Alert {
    /// Разбирает одно сообщение alert — два байта из
    /// [`Event::Alert`](crate::decoder::Event::Alert).
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если байтов меньше двух;
    /// [`ParseError::TrailingBytes`], если больше. На данных из декодера
    /// эти ошибки не возникают: он выдаёт ровно два байта.
    pub fn parse(fragment: &[u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(fragment);
        let level = AlertLevel(reader.u8()?);
        let description = AlertDescription(reader.u8()?);
        reader.finish()?;
        Ok(Self { level, description })
    }

    /// Истина, если уровень — `fatal`.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        self.level == AlertLevel::FATAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_alerts() {
        let cases = [
            (0x28_u8, "handshake_failure"),
            (0x46, "protocol_version"),
            (0x00, "close_notify"),
            (0x0A, "unexpected_message"),
            (0x2F, "illegal_parameter"),
        ];
        for (code, name) in cases {
            let alert = Alert::parse(&[0x02, code]).unwrap();
            assert_eq!(alert.level, AlertLevel::FATAL);
            assert!(alert.is_fatal());
            assert_eq!(alert.description, AlertDescription(code));
            assert_eq!(alert.description.name(), Some(name));
        }
    }

    #[test]
    fn warning_level() {
        let alert = Alert::parse(&[0x01, 0x00]).unwrap();
        assert_eq!(alert.level, AlertLevel::WARNING);
        assert_eq!(alert.level.name(), Some("warning"));
        assert_eq!(AlertLevel::FATAL.name(), Some("fatal"));
        assert!(!alert.is_fatal());
    }

    #[test]
    fn unknown_values_are_kept() {
        let alert = Alert::parse(&[0x07, 0xFE]).unwrap();
        assert_eq!(alert.level, AlertLevel(0x07));
        assert_eq!(alert.level.name(), None);
        assert!(!alert.is_fatal());
        assert_eq!(alert.description, AlertDescription(0xFE));
        assert_eq!(alert.description.name(), None);
    }

    #[test]
    fn wrong_length() {
        assert_eq!(
            Alert::parse(&[]),
            Err(ParseError::UnexpectedEof {
                position: 0,
                needed: 1,
                available: 0,
            })
        );
        assert_eq!(
            Alert::parse(&[0x02]),
            Err(ParseError::UnexpectedEof {
                position: 1,
                needed: 1,
                available: 0,
            })
        );
        assert_eq!(
            Alert::parse(&[0x02, 0x28, 0x00]),
            Err(ParseError::TrailingBytes {
                position: 2,
                remaining: 1,
            })
        );
    }
}
