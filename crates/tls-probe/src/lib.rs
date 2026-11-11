//! Низкоуровневый TLS-пробник: wire-формат без I/O.
//!
//! Назначение: сборка произвольных ClientHello (включая SSLv2 CLIENT-HELLO),
//! разбор record layer и ответов сервера до конца открытой части handshake
//! (ServerHello, HelloRetryRequest, Certificate, ServerKeyExchange, Alert),
//! инкрементальный декодер.
//!
//! Границы ответственности: крейт не открывает соединений и не выполняет I/O,
//! байты подаёт и забирает вызывающий код. Криптографии здесь нет: всё, что
//! требует ключей, относится к `tls-session`. Все длины проверяются, лимиты
//! разбора задаются явно; входные данные считаются враждебными.
//!
//! Состояние: выполнены P1-03 — примитивы кодека ([`codec`]), ошибки
//! ([`error`]) и лимиты ([`limits`]); P1-04 — record layer ([`record`]) и
//! инкрементальный декодер ([`decoder`]); P1-05 — сборка ClientHello
//! ([`client_hello`], [`ext`]); P1-06 — разбор ServerHello и
//! HelloRetryRequest ([`server_hello`]), Alert ([`alert`]) и диспетчер
//! handshake-сообщений ([`handshake`]); P1-07 — Certificate в формате TLS
//! до 1.2 ([`certificate`]), ServerKeyExchange ([`server_kx`]),
//! CertificateStatus и NewSessionTicket ([`misc_msgs`]); P1-08 — SSLv2:
//! сборка CLIENT-HELLO, разбор SERVER-HELLO и ERROR, отдельный декодер
//! ответа ([`sslv2`]).

#![forbid(unsafe_code)]

pub mod alert;
pub mod certificate;
pub mod client_hello;
pub mod codec;
pub mod decoder;
pub mod error;
pub mod ext;
pub mod handshake;
pub mod limits;
pub mod misc_msgs;
pub mod record;
pub mod server_hello;
pub mod server_kx;
pub mod sslv2;

pub use alert::{Alert, AlertLevel};
pub use certificate::{CertificateIter, CertificateList};
pub use client_hello::{ClientHello, ClientHelloView};
pub use codec::{Reader, Writer};
pub use decoder::{Decoder, Event, HandshakeMessage};
pub use error::{EncodeError, NOT_TLS_PREFIX_LEN, ParseError};
pub use ext::{Extension, KeyShareEntry, RawExtension, RawExtensions};
pub use handshake::ServerMessage;
pub use limits::ParseLimits;
pub use misc_msgs::{CertificateStatus, CertificateStatusType, NewSessionTicket};
pub use record::{ContentType, HandshakeType, ProtocolVersion, Record, RecordHeader};
pub use server_hello::{
    DowngradeMarker, ServerExtension, ServerHello, ServerHelloAnomaly, ServerKeyShare,
};
pub use server_kx::{
    DheParams, EcCurveType, EcdheParams, KeyExchangeKind, KxSignature, RsaExportParams,
    ServerKeyExchange, UnparsedReason,
};
pub use sslv2::{
    Sslv2CertificateType, Sslv2ClientHello, Sslv2ClientHelloView, Sslv2Decoder, Sslv2ErrorCode,
    Sslv2Event, Sslv2RecordHeader, Sslv2ServerHello,
};

#[cfg(test)]
mod fixture_tests;
