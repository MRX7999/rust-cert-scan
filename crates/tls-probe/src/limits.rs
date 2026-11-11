//! Лимиты разбора для враждебного ввода.
//!
//! Значения по умолчанию для длины record (16384 + 2048 байтов) и размера
//! handshake-сообщения (64 КиБ) взяты из `docs/ARCHITECTURE.md`, раздел 5.
//! Общий объём чтения на соединение в том же разделе назван без числа:
//! значение 1 МиБ и предел в 16 подряд идущих пустых записей — предварительные
//! и зафиксированы в `docs/DECISIONS.md`, D-13. Число сертификатов в цепочке
//! в разделе 5 тоже названо без числа: значения 32 сертификата и 32 КиБ на
//! один сертификат — предварительные, `docs/DECISIONS.md`, D-15. Лимит на
//! число расширений численного значения в документах не имеет и добавляется
//! задачей, которой он понадобится.
//!
//! Проверка выполняется над длиной, прочитанной из данных, до чтения тела:
//! память под заявленную длину не выделяется.

use crate::error::ParseError;

/// Наибольшая длина record по умолчанию: 16384 + 2048 байтов.
pub const DEFAULT_MAX_RECORD_LEN: usize = 16_384 + 2_048;

/// Наибольший размер handshake-сообщения по умолчанию: 64 КиБ.
pub const DEFAULT_MAX_HANDSHAKE_LEN: usize = 64 * 1024;

/// Наибольший общий объём потока по умолчанию: 1 МиБ (предварительное
/// значение, `docs/DECISIONS.md`, D-13).
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 1024 * 1024;

/// Наибольшее число подряд идущих пустых записей по умолчанию: 16
/// (предварительное значение, `docs/DECISIONS.md`, D-13).
pub const DEFAULT_MAX_EMPTY_RECORDS: usize = 16;

/// Наибольшее число сертификатов в сообщении Certificate по умолчанию: 32
/// (предварительное значение, `docs/DECISIONS.md`, D-15).
pub const DEFAULT_MAX_CERTIFICATES: usize = 32;

/// Наибольшая длина одного сертификата по умолчанию: 32 КиБ
/// (предварительное значение, `docs/DECISIONS.md`, D-15).
pub const DEFAULT_MAX_CERTIFICATE_LEN: usize = 32 * 1024;

/// Лимиты разбора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    /// Наибольшая длина тела record.
    pub max_record_len: usize,
    /// Наибольший суммарный размер одного handshake-сообщения.
    pub max_handshake_len: usize,
    /// Наибольший общий объём потока в байтах, считая заголовки записей.
    /// Декодер сравнивает с ним смещение конца текущей записи.
    pub max_total_bytes: usize,
    /// Наибольшее число подряд идущих записей с пустым телом, для которых
    /// пустое тело не является ошибкой само по себе (`application_data`,
    /// `heartbeat`, неизвестный тип содержимого). Счётчик сбрасывается
    /// любой непустой записью.
    pub max_empty_records: usize,
    /// Наибольшее число сертификатов в одном сообщении Certificate
    /// ([`CertificateList`](crate::certificate::CertificateList)).
    pub max_certificates: usize,
    /// Наибольшая длина одного сертификата (DER) в сообщении Certificate.
    /// Сертификат длиннее `max_handshake_len` до этой проверки не доходит:
    /// декодер раньше отвергает само сообщение.
    pub max_certificate_len: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_record_len: DEFAULT_MAX_RECORD_LEN,
            max_handshake_len: DEFAULT_MAX_HANDSHAKE_LEN,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_empty_records: DEFAULT_MAX_EMPTY_RECORDS,
            max_certificates: DEFAULT_MAX_CERTIFICATES,
            max_certificate_len: DEFAULT_MAX_CERTIFICATE_LEN,
        }
    }
}

impl ParseLimits {
    /// Проверяет заявленную длину record.
    ///
    /// # Errors
    ///
    /// [`ParseError::LimitExceeded`], если длина больше `max_record_len`.
    pub fn check_record_len(&self, len: usize, position: usize) -> Result<(), ParseError> {
        check("max_record_len", self.max_record_len, len, position)
    }

    /// Проверяет заявленный размер handshake-сообщения.
    ///
    /// # Errors
    ///
    /// [`ParseError::LimitExceeded`], если размер больше `max_handshake_len`.
    pub fn check_handshake_len(&self, len: usize, position: usize) -> Result<(), ParseError> {
        check("max_handshake_len", self.max_handshake_len, len, position)
    }

    /// Проверяет общий объём потока: `total` — число байтов от начала
    /// потока до конца текущей записи.
    ///
    /// # Errors
    ///
    /// [`ParseError::LimitExceeded`], если объём больше `max_total_bytes`.
    pub fn check_total_bytes(&self, total: usize, position: usize) -> Result<(), ParseError> {
        check("max_total_bytes", self.max_total_bytes, total, position)
    }

    /// Проверяет число подряд идущих пустых записей.
    ///
    /// # Errors
    ///
    /// [`ParseError::LimitExceeded`], если число больше `max_empty_records`.
    pub fn check_empty_records(&self, count: usize, position: usize) -> Result<(), ParseError> {
        check("max_empty_records", self.max_empty_records, count, position)
    }

    /// Проверяет число сертификатов в сообщении Certificate.
    ///
    /// # Errors
    ///
    /// [`ParseError::LimitExceeded`], если число больше `max_certificates`.
    pub fn check_certificates(&self, count: usize, position: usize) -> Result<(), ParseError> {
        check("max_certificates", self.max_certificates, count, position)
    }

    /// Проверяет заявленную длину одного сертификата.
    ///
    /// # Errors
    ///
    /// [`ParseError::LimitExceeded`], если длина больше
    /// `max_certificate_len`.
    pub fn check_certificate_len(&self, len: usize, position: usize) -> Result<(), ParseError> {
        check(
            "max_certificate_len",
            self.max_certificate_len,
            len,
            position,
        )
    }
}

fn check(
    limit: &'static str,
    max: usize,
    actual: usize,
    position: usize,
) -> Result<(), ParseError> {
    if actual > max {
        return Err(ParseError::LimitExceeded {
            position,
            limit,
            max,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Reader;

    #[test]
    fn defaults_follow_architecture() {
        let limits = ParseLimits::default();
        assert_eq!(limits.max_record_len, 18_432);
        assert_eq!(limits.max_handshake_len, 65_536);
        // Предварительные значения из DECISIONS.md, D-13.
        assert_eq!(limits.max_total_bytes, 1_048_576);
        assert_eq!(limits.max_empty_records, 16);
        // Предварительные значения из DECISIONS.md, D-15.
        assert_eq!(limits.max_certificates, 32);
        assert_eq!(limits.max_certificate_len, 32_768);
    }

    #[test]
    fn certificate_limits() {
        let limits = ParseLimits::default();
        assert_eq!(limits.check_certificates(0, 0), Ok(()));
        assert_eq!(limits.check_certificates(32, 7), Ok(()));
        assert_eq!(
            limits.check_certificates(33, 7),
            Err(ParseError::LimitExceeded {
                position: 7,
                limit: "max_certificates",
                max: 32,
                actual: 33,
            })
        );

        assert_eq!(limits.check_certificate_len(32_768, 3), Ok(()));
        assert_eq!(
            limits.check_certificate_len(32_769, 3),
            Err(ParseError::LimitExceeded {
                position: 3,
                limit: "max_certificate_len",
                max: 32_768,
                actual: 32_769,
            })
        );
    }

    #[test]
    fn length_at_limit_passes_and_above_fails() {
        let limits = ParseLimits::default();
        assert_eq!(limits.check_record_len(0, 0), Ok(()));
        assert_eq!(limits.check_record_len(limits.max_record_len, 5), Ok(()));
        assert_eq!(
            limits.check_record_len(limits.max_record_len + 1, 5),
            Err(ParseError::LimitExceeded {
                position: 5,
                limit: "max_record_len",
                max: 18_432,
                actual: 18_433,
            })
        );

        assert_eq!(
            limits.check_handshake_len(limits.max_handshake_len, 9),
            Ok(())
        );
        assert_eq!(
            limits.check_handshake_len(limits.max_handshake_len + 1, 9),
            Err(ParseError::LimitExceeded {
                position: 9,
                limit: "max_handshake_len",
                max: 65_536,
                actual: 65_537,
            })
        );
    }

    #[test]
    fn total_bytes_and_empty_records_limits() {
        let limits = ParseLimits::default();
        assert_eq!(limits.check_total_bytes(0, 0), Ok(()));
        assert_eq!(limits.check_total_bytes(limits.max_total_bytes, 3), Ok(()));
        assert_eq!(
            limits.check_total_bytes(limits.max_total_bytes + 1, 3),
            Err(ParseError::LimitExceeded {
                position: 3,
                limit: "max_total_bytes",
                max: 1_048_576,
                actual: 1_048_577,
            })
        );

        assert_eq!(limits.check_empty_records(0, 0), Ok(()));
        assert_eq!(limits.check_empty_records(16, 80), Ok(()));
        assert_eq!(
            limits.check_empty_records(17, 80),
            Err(ParseError::LimitExceeded {
                position: 80,
                limit: "max_empty_records",
                max: 16,
                actual: 17,
            })
        );
    }

    #[test]
    fn custom_limits() {
        let limits = ParseLimits {
            max_record_len: 4,
            max_handshake_len: 8,
            max_total_bytes: 32,
            max_empty_records: 0,
            max_certificates: 1,
            max_certificate_len: 16,
        };
        assert!(limits.check_certificates(1, 0).is_ok());
        assert!(limits.check_certificates(2, 0).is_err());
        assert!(limits.check_certificate_len(16, 0).is_ok());
        assert!(limits.check_certificate_len(17, 0).is_err());
        assert!(limits.check_record_len(4, 0).is_ok());
        assert!(limits.check_record_len(5, 0).is_err());
        assert!(limits.check_handshake_len(8, 0).is_ok());
        assert!(limits.check_handshake_len(9, 0).is_err());
        assert!(limits.check_total_bytes(32, 0).is_ok());
        assert!(limits.check_total_bytes(33, 0).is_err());
        assert!(limits.check_empty_records(0, 0).is_ok());
        assert!(limits.check_empty_records(1, 0).is_err());
    }

    #[test]
    fn hostile_length_is_rejected_before_body_is_read() {
        // Заголовок заявляет 16 МиБ, тела нет: лимит срабатывает по длине из
        // данных, тело не читается и память под него не выделяется.
        let data = [0x0B, 0xFF, 0xFF, 0xFF];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.u8(), Ok(0x0B));
        let position = reader.position();
        let declared = usize::try_from(reader.u24().unwrap()).unwrap();
        let error = ParseLimits::default()
            .check_handshake_len(declared, position)
            .unwrap_err();
        assert_eq!(error.position(), 1);
        assert_eq!(
            error,
            ParseError::LimitExceeded {
                position: 1,
                limit: "max_handshake_len",
                max: 65_536,
                actual: 0x00FF_FFFF,
            }
        );
    }
}
