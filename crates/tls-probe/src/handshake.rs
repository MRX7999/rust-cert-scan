//! Диспетчер handshake-сообщений сервера по типу.
//!
//! [`ServerMessage::parse`] принимает тип и тело сообщения, собранного
//! декодером ([`HandshakeMessage`]). ServerHello и HelloRetryRequest
//! разбираются полностью, ServerHelloDone распознаётся. Certificate,
//! ServerKeyExchange, CertificateRequest, CertificateStatus и
//! NewSessionTicket диспетчер возвращает как срез тела: их разбор зависит
//! от того, чего в самом сообщении нет (лимиты, согласованная версия, вид
//! key exchange шифра), поэтому выполняется отдельным вызовом:
//!
//! | Вариант | Метод разбора | Результат |
//! |---|---|---|
//! | `Certificate` | [`ServerMessage::certificates`] | [`CertificateList`] |
//! | `ServerKeyExchange` | [`ServerMessage::server_key_exchange`] | [`ServerKeyExchange`] |
//! | `CertificateStatus` | [`ServerMessage::certificate_status`] | [`CertificateStatus`] |
//! | `NewSessionTicket` | [`ServerMessage::new_session_ticket`] | [`NewSessionTicket`] |
//!
//! Методы возвращают `None`, если сообщение другого типа. CertificateRequest
//! не разбирается: нужен только факт сообщения. Сообщение любого другого
//! типа — [`ServerMessage::Other`].
//!
//! Форматы Certificate и NewSessionTicket относятся к TLS до 1.2
//! включительно. В TLS 1.3 эти сообщения зашифрованы, их разбор — задача
//! `tls-session` (P1-21).

use crate::certificate::CertificateList;
use crate::codec::Reader;
use crate::decoder::HandshakeMessage;
use crate::error::ParseError;
use crate::limits::ParseLimits;
use crate::misc_msgs::{CertificateStatus, NewSessionTicket};
use crate::record::{HandshakeType, ProtocolVersion};
use crate::server_hello::ServerHello;
use crate::server_kx::{KeyExchangeKind, ServerKeyExchange};

/// Handshake-сообщение сервера.
#[derive(Debug, Clone)]
pub enum ServerMessage<'a> {
    /// ServerHello.
    ServerHello(ServerHello<'a>),
    /// HelloRetryRequest: `server_hello` со специальным `random`.
    HelloRetryRequest(ServerHello<'a>),
    /// ServerHelloDone.
    ServerHelloDone,
    /// Certificate: тело без разбора.
    Certificate(&'a [u8]),
    /// ServerKeyExchange: тело без разбора.
    ServerKeyExchange(&'a [u8]),
    /// CertificateRequest: тело без разбора.
    CertificateRequest(&'a [u8]),
    /// CertificateStatus: тело без разбора.
    CertificateStatus(&'a [u8]),
    /// NewSessionTicket: тело без разбора.
    NewSessionTicket(&'a [u8]),
    /// Сообщение другого типа.
    Other {
        /// Тип сообщения.
        msg_type: HandshakeType,
        /// Тело.
        body: &'a [u8],
    },
}

impl<'a> ServerMessage<'a> {
    /// Разбирает сообщение по его типу.
    ///
    /// # Errors
    ///
    /// Ошибка [`ServerHello::parse`] для `server_hello`;
    /// [`ParseError::TrailingBytes`], если тело ServerHelloDone не пустое.
    pub fn parse(msg_type: HandshakeType, body: &'a [u8]) -> Result<Self, ParseError> {
        Ok(match msg_type {
            HandshakeType::SERVER_HELLO => {
                let hello = ServerHello::parse(body)?;
                if hello.is_hello_retry_request() {
                    Self::HelloRetryRequest(hello)
                } else {
                    Self::ServerHello(hello)
                }
            }
            HandshakeType::SERVER_HELLO_DONE => {
                Reader::new(body).finish()?;
                Self::ServerHelloDone
            }
            HandshakeType::CERTIFICATE => Self::Certificate(body),
            HandshakeType::SERVER_KEY_EXCHANGE => Self::ServerKeyExchange(body),
            HandshakeType::CERTIFICATE_REQUEST => Self::CertificateRequest(body),
            HandshakeType::CERTIFICATE_STATUS => Self::CertificateStatus(body),
            HandshakeType::NEW_SESSION_TICKET => Self::NewSessionTicket(body),
            _ => Self::Other { msg_type, body },
        })
    }

    /// Разбирает сообщение, собранное декодером.
    ///
    /// # Errors
    ///
    /// Как у [`ServerMessage::parse`].
    pub fn from_message(message: &HandshakeMessage<'a>) -> Result<Self, ParseError> {
        Self::parse(message.msg_type, message.body)
    }

    /// Список сертификатов сообщения Certificate (формат TLS до 1.2);
    /// `None`, если сообщение другого типа.
    #[must_use]
    pub fn certificates(
        &self,
        limits: &ParseLimits,
    ) -> Option<Result<CertificateList<'a>, ParseError>> {
        match *self {
            Self::Certificate(body) => Some(CertificateList::parse(body, limits)),
            _ => None,
        }
    }

    /// Разбор ServerKeyExchange для согласованной версии и вида key
    /// exchange ([`KeyExchangeKind::from_cipher_info`]); `None`, если
    /// сообщение другого типа.
    #[must_use]
    pub fn server_key_exchange(
        &self,
        version: ProtocolVersion,
        kind: KeyExchangeKind,
    ) -> Option<Result<ServerKeyExchange<'a>, ParseError>> {
        match *self {
            Self::ServerKeyExchange(body) => Some(ServerKeyExchange::parse(body, version, kind)),
            _ => None,
        }
    }

    /// Разбор CertificateStatus; `None`, если сообщение другого типа.
    #[must_use]
    pub fn certificate_status(&self) -> Option<Result<CertificateStatus<'a>, ParseError>> {
        match *self {
            Self::CertificateStatus(body) => Some(CertificateStatus::parse(body)),
            _ => None,
        }
    }

    /// Разбор NewSessionTicket (формат TLS до 1.2); `None`, если сообщение
    /// другого типа.
    #[must_use]
    pub fn new_session_ticket(&self) -> Option<Result<NewSessionTicket<'a>, ParseError>> {
        match *self {
            Self::NewSessionTicket(body) => Some(NewSessionTicket::parse(body)),
            _ => None,
        }
    }

    /// Тип сообщения.
    #[must_use]
    pub fn msg_type(&self) -> HandshakeType {
        match self {
            Self::ServerHello(_) | Self::HelloRetryRequest(_) => HandshakeType::SERVER_HELLO,
            Self::ServerHelloDone => HandshakeType::SERVER_HELLO_DONE,
            Self::Certificate(_) => HandshakeType::CERTIFICATE,
            Self::ServerKeyExchange(_) => HandshakeType::SERVER_KEY_EXCHANGE,
            Self::CertificateRequest(_) => HandshakeType::CERTIFICATE_REQUEST,
            Self::CertificateStatus(_) => HandshakeType::CERTIFICATE_STATUS,
            Self::NewSessionTicket(_) => HandshakeType::NEW_SESSION_TICKET,
            Self::Other { msg_type, .. } => *msg_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::ProtocolVersion;
    use crate::server_hello::{HELLO_RETRY_REQUEST_RANDOM, RANDOM_LEN};

    fn hello_body(random: [u8; RANDOM_LEN]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend(random);
        body.extend([0x00, 0x13, 0x01, 0x00]);
        body
    }

    #[test]
    fn dispatches_server_hello_and_hello_retry_request() {
        let body = hello_body([0x5A; RANDOM_LEN]);
        match ServerMessage::parse(HandshakeType::SERVER_HELLO, &body).unwrap() {
            ServerMessage::ServerHello(hello) => {
                assert_eq!(hello.version(), ProtocolVersion::TLS1_2);
            }
            other => panic!("ожидался ServerHello, получено {other:?}"),
        }

        let body = hello_body(HELLO_RETRY_REQUEST_RANDOM);
        let message = ServerMessage::parse(HandshakeType::SERVER_HELLO, &body).unwrap();
        assert!(matches!(message, ServerMessage::HelloRetryRequest(_)));
        assert_eq!(message.msg_type(), HandshakeType::SERVER_HELLO);
    }

    #[test]
    fn server_hello_error_is_propagated() {
        let body = hello_body([0x5A; RANDOM_LEN]);
        let error = ServerMessage::parse(HandshakeType::SERVER_HELLO, &body[..10]).unwrap_err();
        assert!(matches!(error, ParseError::UnexpectedEof { .. }));
    }

    #[test]
    fn server_hello_done() {
        let message = ServerMessage::parse(HandshakeType::SERVER_HELLO_DONE, &[]).unwrap();
        assert!(matches!(message, ServerMessage::ServerHelloDone));
        assert_eq!(message.msg_type(), HandshakeType::SERVER_HELLO_DONE);

        assert_eq!(
            ServerMessage::parse(HandshakeType::SERVER_HELLO_DONE, &[0x00]).unwrap_err(),
            ParseError::TrailingBytes {
                position: 0,
                remaining: 1,
            }
        );
    }

    #[test]
    fn later_messages_are_returned_as_bodies() {
        let body = [0xDE_u8, 0xAD, 0xBE, 0xEF];
        let types = [
            HandshakeType::CERTIFICATE,
            HandshakeType::SERVER_KEY_EXCHANGE,
            HandshakeType::CERTIFICATE_REQUEST,
            HandshakeType::CERTIFICATE_STATUS,
            HandshakeType::NEW_SESSION_TICKET,
        ];
        for msg_type in types {
            let message = ServerMessage::parse(msg_type, &body).unwrap();
            assert_eq!(message.msg_type(), msg_type);
            let kept = match message {
                ServerMessage::Certificate(kept)
                | ServerMessage::ServerKeyExchange(kept)
                | ServerMessage::CertificateRequest(kept)
                | ServerMessage::CertificateStatus(kept)
                | ServerMessage::NewSessionTicket(kept) => kept,
                other => panic!("тип {msg_type:?}: получено {other:?}"),
            };
            assert_eq!(kept, &body[..]);
        }
    }

    /// Синтетические тела: составлены вручную, не записи серверов.
    #[test]
    fn typed_accessors_parse_matching_messages_only() {
        let limits = ParseLimits::default();
        let ecdhe = KeyExchangeKind::Ecdhe { signed: false };

        // Certificate: один «сертификат» из двух байтов.
        let body = [0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0x30, 0x00];
        let message = ServerMessage::parse(HandshakeType::CERTIFICATE, &body).unwrap();
        let list = message.certificates(&limits).unwrap().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list.first(), Some(&[0x30, 0x00][..]));
        assert!(
            message
                .server_key_exchange(ProtocolVersion::TLS1_2, ecdhe)
                .is_none()
        );
        assert!(message.certificate_status().is_none());
        assert!(message.new_session_ticket().is_none());

        // ServerKeyExchange: анонимный ECDHE, secp256r1, точка из трёх байтов.
        let body = [0x03, 0x00, 0x17, 0x03, 0x04, 0x01, 0x02];
        let message = ServerMessage::parse(HandshakeType::SERVER_KEY_EXCHANGE, &body).unwrap();
        let parsed = message
            .server_key_exchange(ProtocolVersion::TLS1_2, ecdhe)
            .unwrap()
            .unwrap();
        assert!(matches!(parsed, ServerKeyExchange::Ecdhe { .. }));
        assert!(message.certificates(&limits).is_none());

        // CertificateStatus: ocsp, ответ из одного байта.
        let body = [0x01, 0x00, 0x00, 0x01, 0x30];
        let message = ServerMessage::parse(HandshakeType::CERTIFICATE_STATUS, &body).unwrap();
        let status = message.certificate_status().unwrap().unwrap();
        assert_eq!(status.response, &[0x30][..]);
        assert!(message.new_session_ticket().is_none());

        // NewSessionTicket: lifetime 300 секунд, тикет из двух байтов.
        let body = [0x00, 0x00, 0x01, 0x2C, 0x00, 0x02, 0xAA, 0xBB];
        let message = ServerMessage::parse(HandshakeType::NEW_SESSION_TICKET, &body).unwrap();
        let ticket = message.new_session_ticket().unwrap().unwrap();
        assert_eq!(ticket.lifetime_hint, 300);
        assert_eq!(ticket.ticket, &[0xAA, 0xBB][..]);
        assert!(message.certificate_status().is_none());

        // Ошибка разбора тела возвращается из метода, а не из диспетчера.
        let message = ServerMessage::parse(HandshakeType::CERTIFICATE, &[0x00]).unwrap();
        assert!(matches!(
            message.certificates(&limits),
            Some(Err(ParseError::UnexpectedEof { .. }))
        ));

        // Сообщения без типизированного разбора.
        let done = ServerMessage::parse(HandshakeType::SERVER_HELLO_DONE, &[]).unwrap();
        assert!(done.certificates(&limits).is_none());
        let request = ServerMessage::parse(HandshakeType::CERTIFICATE_REQUEST, &[0x00]).unwrap();
        assert!(matches!(
            request,
            ServerMessage::CertificateRequest(&[0x00])
        ));
        assert!(request.certificate_status().is_none());
    }

    #[test]
    fn other_types_and_decoder_message() {
        let raw = [0x08_u8, 0x00, 0x00, 0x02, 0x00, 0x00];
        let message = HandshakeMessage {
            msg_type: HandshakeType::ENCRYPTED_EXTENSIONS,
            body: &raw[4..],
            raw: &raw,
        };
        match ServerMessage::from_message(&message).unwrap() {
            ServerMessage::Other { msg_type, body } => {
                assert_eq!(msg_type, HandshakeType::ENCRYPTED_EXTENSIONS);
                assert_eq!(body, &[0x00, 0x00][..]);
            }
            other => panic!("ожидался Other, получено {other:?}"),
        }

        let unknown = ServerMessage::parse(HandshakeType(0xEE), &[]).unwrap();
        assert_eq!(unknown.msg_type(), HandshakeType(0xEE));
    }
}
