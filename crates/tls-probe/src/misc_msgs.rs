//! Разбор сообщений CertificateStatus и NewSessionTicket (TLS до 1.2).
//!
//! - CertificateStatus (RFC 6066, раздел 8): тип статуса и ответ. Для типа
//!   `ocsp` ответ — `OCSPResponse` в DER, он отдаётся срезом без разбора:
//!   ASN.1 относится к крейту `x509-check`. Для любого другого типа формат
//!   тела этим модулем не определяется, и срезом отдаётся весь остаток тела.
//! - NewSessionTicket (RFC 5077, раздел 3.3): `ticket_lifetime_hint` и тикет
//!   срезом. Формат TLS 1.3 (RFC 8446, раздел 4.6.1) другой, приходит
//!   зашифрованным и здесь не разбирается (P1-21).
//!
//! CertificateRequest не разбирается: план (P1-07) требует только факт
//! сообщения, тело доступно срезом через
//! [`ServerMessage::CertificateRequest`](crate::handshake::ServerMessage).

use crate::codec::Reader;
use crate::error::ParseError;

/// Тип статуса сертификата (`CertificateStatusType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertificateStatusType(pub u8);

impl CertificateStatusType {
    /// `ocsp` (1).
    pub const OCSP: Self = Self(1);
    /// `ocsp_multi` (2), RFC 6961.
    pub const OCSP_MULTI: Self = Self(2);
}

/// Сообщение CertificateStatus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateStatus<'a> {
    /// Тип статуса.
    pub status_type: CertificateStatusType,
    /// Для [`CertificateStatusType::OCSP`] — `OCSPResponse` в DER без
    /// префикса длины; для другого типа — остаток тела после байта типа.
    pub response: &'a [u8],
}

impl<'a> CertificateStatus<'a> {
    /// Разбирает тело CertificateStatus.
    ///
    /// # Errors
    ///
    /// - [`ParseError::UnexpectedEof`], если тело оборвано или длина ответа
    ///   больше остатка;
    /// - [`ParseError::InvalidValue`], если ответ типа `ocsp` пустой;
    /// - [`ParseError::TrailingBytes`], если после ответа типа `ocsp`
    ///   остались байты.
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(body);
        let status_type = CertificateStatusType(reader.u8()?);
        if status_type != CertificateStatusType::OCSP {
            return Ok(Self {
                status_type,
                response: reader.rest(),
            });
        }

        let position = reader.position();
        let response = reader.vec_u24()?;
        if response.is_empty() {
            return Err(ParseError::InvalidValue {
                position,
                what: "пустой OCSPResponse в CertificateStatus",
            });
        }
        reader.finish()?;
        Ok(Self {
            status_type,
            response,
        })
    }

    /// Истина, если тип статуса — `ocsp` и `response` содержит
    /// `OCSPResponse`.
    #[must_use]
    pub fn is_ocsp(&self) -> bool {
        self.status_type == CertificateStatusType::OCSP
    }
}

/// Сообщение NewSessionTicket в формате TLS до 1.2 включительно.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewSessionTicket<'a> {
    /// `ticket_lifetime_hint` в секундах; 0 — срок не указан.
    pub lifetime_hint: u32,
    /// Тикет; может быть пустым (RFC 5077, раздел 3.3).
    pub ticket: &'a [u8],
}

impl<'a> NewSessionTicket<'a> {
    /// Разбирает тело NewSessionTicket.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если тело оборвано или длина тикета
    /// больше остатка; [`ParseError::TrailingBytes`], если после тикета
    /// остались байты.
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(body);
        let lifetime_hint = reader.u32()?;
        let ticket = reader.vec_u16()?;
        reader.finish()?;
        Ok(Self {
            lifetime_hint,
            ticket,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Синтетические тесты: байты составлены вручную по RFC 6066 (раздел 8)
    //! и RFC 5077 (раздел 3.3), это не записи серверов.

    use super::*;

    #[test]
    fn certificate_status_ocsp() {
        let body = [0x01, 0x00, 0x00, 0x04, 0x30, 0x03, 0x0A, 0x01];
        let status = CertificateStatus::parse(&body).unwrap();
        assert_eq!(status.status_type, CertificateStatusType::OCSP);
        assert!(status.is_ocsp());
        assert_eq!(status.response, &[0x30, 0x03, 0x0A, 0x01][..]);
    }

    #[test]
    fn certificate_status_other_type_keeps_rest() {
        let body = [0x02, 0x00, 0x00, 0x01, 0xAA];
        let status = CertificateStatus::parse(&body).unwrap();
        assert_eq!(status.status_type, CertificateStatusType::OCSP_MULTI);
        assert!(!status.is_ocsp());
        assert_eq!(status.response, &body[1..]);

        let status = CertificateStatus::parse(&[0x7F]).unwrap();
        assert_eq!(status.status_type, CertificateStatusType(0x7F));
        assert!(status.response.is_empty());
    }

    #[test]
    fn certificate_status_errors() {
        let body = [0x01, 0x00, 0x00, 0x04, 0x30, 0x03, 0x0A, 0x01];
        for len in 0..body.len() {
            let error = CertificateStatus::parse(&body[..len]).unwrap_err();
            assert!(
                matches!(error, ParseError::UnexpectedEof { .. }),
                "длина {len}: {error}"
            );
        }

        assert_eq!(
            CertificateStatus::parse(&[0x01, 0x00, 0x00, 0x00]).unwrap_err(),
            ParseError::InvalidValue {
                position: 1,
                what: "пустой OCSPResponse в CertificateStatus",
            }
        );

        assert_eq!(
            CertificateStatus::parse(&[0x01, 0x00, 0x00, 0x01, 0x30, 0xEE, 0xEE]).unwrap_err(),
            ParseError::TrailingBytes {
                position: 5,
                remaining: 2,
            }
        );

        // Ответ заявлен на 16 МиБ: ошибка по остатку, память не выделяется.
        let error = CertificateStatus::parse(&[0x01, 0xFF, 0xFF, 0xFF, 0x30]).unwrap_err();
        assert!(matches!(error, ParseError::UnexpectedEof { .. }), "{error}");
    }

    #[test]
    fn new_session_ticket() {
        let body = [0x00, 0x00, 0x1C, 0x20, 0x00, 0x03, 0xA1, 0xA2, 0xA3];
        let ticket = NewSessionTicket::parse(&body).unwrap();
        assert_eq!(ticket.lifetime_hint, 7200);
        assert_eq!(ticket.ticket, &[0xA1, 0xA2, 0xA3][..]);

        // Пустой тикет допустим.
        let empty = NewSessionTicket::parse(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(empty.lifetime_hint, 0);
        assert!(empty.ticket.is_empty());

        let max = NewSessionTicket::parse(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00]).unwrap();
        assert_eq!(max.lifetime_hint, u32::MAX);
    }

    #[test]
    fn new_session_ticket_errors() {
        let body = [0x00, 0x00, 0x1C, 0x20, 0x00, 0x03, 0xA1, 0xA2, 0xA3];
        for len in 0..body.len() {
            let error = NewSessionTicket::parse(&body[..len]).unwrap_err();
            assert!(
                matches!(error, ParseError::UnexpectedEof { .. }),
                "длина {len}: {error}"
            );
        }

        let mut extra = body.to_vec();
        extra.push(0xEE);
        assert_eq!(
            NewSessionTicket::parse(&extra).unwrap_err(),
            ParseError::TrailingBytes {
                position: 9,
                remaining: 1,
            }
        );

        let error = NewSessionTicket::parse(&[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF]).unwrap_err();
        assert!(matches!(error, ParseError::UnexpectedEof { .. }), "{error}");
    }
}
