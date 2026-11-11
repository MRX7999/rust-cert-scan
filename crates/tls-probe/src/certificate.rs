//! Разбор сообщения Certificate в формате TLS до 1.2 включительно.
//!
//! Тело сообщения (RFC 5246, раздел 7.4.2; тот же формат в SSLv3, TLS 1.0 и
//! TLS 1.1):
//!
//! ```text
//! opaque ASN.1Cert<1..2^24-1>;
//! struct { ASN.1Cert certificate_list<0..2^24-1>; } Certificate;
//! ```
//!
//! [`CertificateList::parse`] проверяет все длины и лимиты один раз и
//! возвращает список, который заимствует тело сообщения: сертификаты
//! отдаются срезами DER без копирования, в порядке, в котором их прислал
//! сервер. Сам X.509 здесь не разбирается: это задача крейта `x509-check`
//! (P1-22).
//!
//! Пустой список — корректный результат, а не ошибка: так отвечает клиент
//! без сертификата, а сервер с таким ответом — аномалия, которую оценивает
//! проверка, а не парсер. Сертификат нулевой длины формат запрещает, это
//! [`ParseError::InvalidValue`].
//!
//! Формат TLS 1.3 (`certificate_request_context` и расширения у каждой
//! записи, RFC 8446, раздел 4.4.2) здесь не разбирается: такое сообщение
//! приходит зашифрованным, его разбор относится к слою `tls-session`
//! (P1-21). Отличить формат по телу нельзя, поэтому версию учитывает
//! вызывающий код.
//!
//! Лимиты: [`ParseLimits::max_certificates`] и
//! [`ParseLimits::max_certificate_len`]. Проверка выполняется над длиной из
//! данных до чтения тела, память по ней не выделяется.

use crate::codec::Reader;
use crate::error::ParseError;
use crate::limits::ParseLimits;

/// Список сертификатов из сообщения Certificate (TLS до 1.2 включительно).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateList<'a> {
    /// Содержимое `certificate_list` без трёхбайтового префикса длины.
    entries: &'a [u8],
    /// Число сертификатов, подсчитанное при разборе.
    count: usize,
}

impl<'a> CertificateList<'a> {
    /// Разбирает тело сообщения Certificate.
    ///
    /// # Errors
    ///
    /// - [`ParseError::UnexpectedEof`], если тело оборвано или заявленная
    ///   длина списка либо сертификата больше остатка;
    /// - [`ParseError::TrailingBytes`], если после списка остались байты;
    /// - [`ParseError::LimitExceeded`], если сертификатов больше
    ///   `max_certificates` или сертификат длиннее `max_certificate_len`;
    /// - [`ParseError::InvalidValue`], если сертификат имеет нулевую длину.
    pub fn parse(body: &'a [u8], limits: &ParseLimits) -> Result<Self, ParseError> {
        let mut reader = Reader::new(body);
        let mut list = reader.sub_u24()?;
        reader.finish()?;

        let entries = list.as_slice();
        let mut count = 0_usize;
        while !list.is_empty() {
            let position = list.position();
            count = count.saturating_add(1);
            limits.check_certificates(count, position)?;

            let declared = declared_len(list.u24()?, position)?;
            limits.check_certificate_len(declared, position)?;
            if declared == 0 {
                return Err(ParseError::InvalidValue {
                    position,
                    what: "сертификат нулевой длины в certificate_list",
                });
            }
            list.skip(declared)?;
        }

        Ok(Self { entries, count })
    }

    /// Число сертификатов в списке.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Истина, если список пуст.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Итератор по сертификатам: срезы DER в порядке передачи.
    #[must_use]
    pub fn iter(&self) -> CertificateIter<'a> {
        CertificateIter {
            reader: Reader::new(self.entries),
            remaining: self.count,
        }
    }

    /// Первый сертификат списка — сертификат сервера; `None` для пустого
    /// списка.
    #[must_use]
    pub fn first(&self) -> Option<&'a [u8]> {
        self.iter().next()
    }

    /// Содержимое `certificate_list` без префикса длины: записи
    /// «трёхбайтовая длина и DER» подряд.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.entries
    }
}

impl<'a> IntoIterator for CertificateList<'a> {
    type Item = &'a [u8];
    type IntoIter = CertificateIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &CertificateList<'a> {
    type Item = &'a [u8];
    type IntoIter = CertificateIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Итератор по сертификатам [`CertificateList`].
///
/// Длины проверены при разборе списка, поэтому итератор не возвращает
/// ошибок. Если внутренний инвариант всё же нарушен, обход заканчивается, а
/// не паникует.
#[derive(Debug, Clone)]
pub struct CertificateIter<'a> {
    reader: Reader<'a>,
    remaining: usize,
}

impl<'a> Iterator for CertificateIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if let Ok(der) = self.reader.vec_u24() {
            self.remaining = self.remaining.saturating_sub(1);
            Some(der)
        } else {
            self.remaining = 0;
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for CertificateIter<'_> {}

impl std::iter::FusedIterator for CertificateIter<'_> {}

/// Длина из трёхбайтового поля как `usize`.
fn declared_len(value: u32, position: usize) -> Result<usize, ParseError> {
    usize::try_from(value).map_err(|_| ParseError::Internal {
        position,
        what: "длина из u24 не помещается в usize",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает тело Certificate из сертификатов. Синтетические данные:
    /// содержимое «сертификатов» — произвольные байты, не DER.
    fn body(certs: &[&[u8]]) -> Vec<u8> {
        let mut entries = Vec::new();
        for cert in certs {
            let len = u32::try_from(cert.len()).unwrap();
            entries.extend_from_slice(&len.to_be_bytes()[1..]);
            entries.extend_from_slice(cert);
        }
        let total = u32::try_from(entries.len()).unwrap();
        let mut out = total.to_be_bytes()[1..].to_vec();
        out.extend(entries);
        out
    }

    #[test]
    fn single_certificate() {
        let der = [0x30_u8, 0x03, 0x02, 0x01, 0x05];
        let bytes = body(&[&der]);
        let list = CertificateList::parse(&bytes, &ParseLimits::default()).unwrap();
        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
        assert_eq!(list.first(), Some(&der[..]));
        assert_eq!(list.iter().collect::<Vec<_>>(), vec![&der[..]]);
        assert_eq!(list.as_bytes(), &bytes[3..]);
    }

    #[test]
    fn chain_of_three_keeps_order_and_borrows_input() {
        let first = [0xA1_u8; 7];
        let second = [0xB2_u8; 1];
        let third = [0xC3_u8; 300];
        let bytes = body(&[&first, &second, &third]);
        let list = CertificateList::parse(&bytes, &ParseLimits::default()).unwrap();
        assert_eq!(list.len(), 3);

        let mut iter = list.iter();
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.next(), Some(&first[..]));
        assert_eq!(iter.size_hint(), (2, Some(2)));
        assert_eq!(iter.next(), Some(&second[..]));
        assert_eq!(iter.next(), Some(&third[..]));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);

        // Срезы указывают в исходный буфер, а не в копию.
        let der = list.first().unwrap();
        let start = bytes.as_ptr() as usize;
        let inside = der.as_ptr() as usize;
        assert_eq!(inside - start, 6);

        let mut total = 0;
        for der in &list {
            total += der.len();
        }
        assert_eq!(total, 308);
        assert_eq!(list.into_iter().count(), 3);
    }

    #[test]
    fn empty_list_is_valid() {
        let list = CertificateList::parse(&[0x00, 0x00, 0x00], &ParseLimits::default()).unwrap();
        assert_eq!(list.len(), 0);
        assert!(list.is_empty());
        assert_eq!(list.first(), None);
        assert_eq!(list.iter().next(), None);
        assert!(list.as_bytes().is_empty());
    }

    #[test]
    fn truncated_at_every_field() {
        let limits = ParseLimits::default();
        // Пустое тело и оборванный префикс длины списка.
        for len in 0..3 {
            let bytes = [0x00_u8; 3];
            let error = CertificateList::parse(&bytes[..len], &limits).unwrap_err();
            assert!(matches!(error, ParseError::UnexpectedEof { .. }), "{error}");
        }

        let full = body(&[&[0x11; 4], &[0x22; 4]]);
        // Любой обрыв полного тела — ошибка: длина списка больше остатка.
        for len in 3..full.len() {
            let error = CertificateList::parse(&full[..len], &limits).unwrap_err();
            assert!(
                matches!(error, ParseError::UnexpectedEof { .. }),
                "длина {len}: {error}"
            );
        }

        // Список заявлен короче: обрыв внутри префикса длины сертификата.
        for list_len in 1..3_u8 {
            let mut bytes = vec![0x00, 0x00, list_len];
            bytes.extend(std::iter::repeat_n(0x00, usize::from(list_len)));
            let error = CertificateList::parse(&bytes, &limits).unwrap_err();
            assert!(
                matches!(error, ParseError::UnexpectedEof { position: 3, .. }),
                "{error}"
            );
        }

        // Обрыв внутри тела сертификата: заявлено 4 байта, в списке 2.
        let bytes = [0x00, 0x00, 0x05, 0x00, 0x00, 0x04, 0xAA, 0xBB];
        let error = CertificateList::parse(&bytes, &limits).unwrap_err();
        assert!(matches!(error, ParseError::UnexpectedEof { .. }), "{error}");
    }

    #[test]
    fn list_length_larger_than_body() {
        let bytes = [0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0xAA];
        let error = CertificateList::parse(&bytes, &ParseLimits::default()).unwrap_err();
        assert!(matches!(error, ParseError::UnexpectedEof { .. }), "{error}");
    }

    #[test]
    fn trailing_bytes_after_list() {
        let mut bytes = body(&[&[0x11; 2]]);
        bytes.push(0xEE);
        assert_eq!(
            CertificateList::parse(&bytes, &ParseLimits::default()).unwrap_err(),
            ParseError::TrailingBytes {
                position: 8,
                remaining: 1,
            }
        );

        assert_eq!(
            CertificateList::parse(&[0x00, 0x00, 0x00, 0xEE], &ParseLimits::default()).unwrap_err(),
            ParseError::TrailingBytes {
                position: 3,
                remaining: 1,
            }
        );
    }

    #[test]
    fn zero_length_certificate_is_invalid() {
        let bytes = [0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
        assert_eq!(
            CertificateList::parse(&bytes, &ParseLimits::default()).unwrap_err(),
            ParseError::InvalidValue {
                position: 3,
                what: "сертификат нулевой длины в certificate_list",
            }
        );
    }

    #[test]
    fn certificate_count_limit() {
        let limits = ParseLimits {
            max_certificates: 2,
            ..ParseLimits::default()
        };
        let two = body(&[&[0x01], &[0x02]]);
        assert_eq!(CertificateList::parse(&two, &limits).unwrap().len(), 2);

        let three = body(&[&[0x01], &[0x02], &[0x03]]);
        assert_eq!(
            CertificateList::parse(&three, &limits).unwrap_err(),
            ParseError::LimitExceeded {
                position: 11,
                limit: "max_certificates",
                max: 2,
                actual: 3,
            }
        );

        let none = ParseLimits {
            max_certificates: 0,
            ..ParseLimits::default()
        };
        assert!(CertificateList::parse(&[0x00, 0x00, 0x00], &none).is_ok());
        assert!(CertificateList::parse(&two, &none).is_err());
    }

    #[test]
    fn certificate_length_limit() {
        let limits = ParseLimits {
            max_certificate_len: 4,
            ..ParseLimits::default()
        };
        let at_limit = body(&[&[0x11; 4]]);
        assert_eq!(CertificateList::parse(&at_limit, &limits).unwrap().len(), 1);

        let above = body(&[&[0x11; 4], &[0x22; 5]]);
        assert_eq!(
            CertificateList::parse(&above, &limits).unwrap_err(),
            ParseError::LimitExceeded {
                position: 10,
                limit: "max_certificate_len",
                max: 4,
                actual: 5,
            }
        );
    }

    #[test]
    fn hostile_certificate_length_is_rejected_before_body() {
        // Сертификат заявлен на 16 МиБ без тела: лимит срабатывает по длине
        // из данных раньше, чем проверяется остаток.
        let bytes = [0x00, 0x00, 0x03, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            CertificateList::parse(&bytes, &ParseLimits::default()).unwrap_err(),
            ParseError::LimitExceeded {
                position: 3,
                limit: "max_certificate_len",
                max: ParseLimits::default().max_certificate_len,
                actual: 0x00FF_FFFF,
            }
        );
    }
}
