//! «Сырое» расширение и расширения с простым телом: `renegotiation_info`
//! (RFC 5746), `session_ticket` (RFC 5077), `extended_master_secret`
//! (RFC 7627), `encrypt_then_mac` (RFC 7366), `heartbeat` (RFC 6520),
//! `padding` (RFC 7685), `signed_certificate_timestamp` (RFC 6962).

use tls_data::ExtensionType;

use super::{Extension, kind};
use crate::error::EncodeError;

impl Extension {
    /// Расширение с произвольным кодом типа и телом: для всего, у чего нет
    /// типизированного конструктора, и для намеренно некорректных тел.
    ///
    /// Длина тела проверяется при кодировании, см. [`Extension::encode`].
    #[must_use]
    pub fn raw(ext_type: u16, data: &[u8]) -> Self {
        Self::from_parts(ExtensionType(ext_type), data.to_vec())
    }

    /// `renegotiation_info` с заданным `renegotiated_connection`; для
    /// первого handshake значение пустое.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если значение длиннее 255 байтов.
    pub fn renegotiation_info(renegotiated_connection: &[u8]) -> Result<Self, EncodeError> {
        Self::build(kind::RENEGOTIATION_INFO, |writer| {
            writer.put_vec_u8(renegotiated_connection)
        })
    }

    /// `session_ticket`: тело — сам ticket; пустое тело означает «клиент
    /// поддерживает tickets и просит новый».
    #[must_use]
    pub fn session_ticket(ticket: &[u8]) -> Self {
        Self::from_parts(kind::SESSION_TICKET, ticket.to_vec())
    }

    /// `extended_master_secret`: пустое тело. Снимок IANA называет код 23
    /// `extended_main_secret`; имя IANA доступно через `tls-data`
    /// (`docs/DECISIONS.md`, D-12).
    #[must_use]
    pub fn extended_master_secret() -> Self {
        Self::from_parts(kind::EXTENDED_MASTER_SECRET, Vec::new())
    }

    /// `encrypt_then_mac`: пустое тело.
    #[must_use]
    pub fn encrypt_then_mac() -> Self {
        Self::from_parts(kind::ENCRYPT_THEN_MAC, Vec::new())
    }

    /// `heartbeat` с заданным режимом: `peer_allowed_to_send` (1) или
    /// `peer_not_allowed_to_send` (2).
    #[must_use]
    pub fn heartbeat(mode: u8) -> Self {
        Self::from_parts(kind::HEARTBEAT, vec![mode])
    }

    /// `padding`: тело из `len` нулевых байтов.
    ///
    /// Длина проверяется при кодировании, см. [`Extension::encode`].
    #[must_use]
    pub fn padding(len: usize) -> Self {
        Self::from_parts(kind::PADDING, vec![0_u8; len])
    }

    /// `signed_certificate_timestamp` в форме ClientHello: пустое тело.
    #[must_use]
    pub fn signed_certificate_timestamp() -> Self {
        Self::from_parts(kind::SIGNED_CERTIFICATE_TIMESTAMP, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;

    #[test]
    fn raw_keeps_type_and_bytes() {
        let extension = Extension::raw(0xFAFA, &[0xDE, 0xAD]);
        assert_eq!(extension.ext_type(), ExtensionType(0xFAFA));
        assert_eq!(extension.data(), &[0xDE, 0xAD][..]);

        // Сырое расширение может повторять код типизированного.
        let malformed = Extension::raw(kind::SERVER_NAME.0, &[0xFF]);
        assert_eq!(malformed.ext_type(), kind::SERVER_NAME);
    }

    #[test]
    fn renegotiation_info_body() {
        let initial = Extension::renegotiation_info(&[]).unwrap();
        assert_eq!(initial.ext_type(), kind::RENEGOTIATION_INFO);
        assert_eq!(initial.data(), &[0x00_u8][..]);

        let renegotiation = Extension::renegotiation_info(&[0xAA; 12]).unwrap();
        assert_eq!(renegotiation.data().len(), 13);
        assert_eq!(renegotiation.data().first(), Some(&0x0C));

        assert!(Extension::renegotiation_info(&[0_u8; 256]).is_err());
    }

    #[test]
    fn session_ticket_body() {
        assert!(Extension::session_ticket(&[]).data().is_empty());
        let extension = Extension::session_ticket(&[0x01, 0x02]);
        assert_eq!(extension.ext_type(), kind::SESSION_TICKET);
        assert_eq!(extension.data(), &[0x01, 0x02][..]);
    }

    #[test]
    fn empty_body_extensions() {
        let cases = [
            (
                Extension::extended_master_secret(),
                kind::EXTENDED_MASTER_SECRET,
            ),
            (Extension::encrypt_then_mac(), kind::ENCRYPT_THEN_MAC),
            (
                Extension::signed_certificate_timestamp(),
                kind::SIGNED_CERTIFICATE_TIMESTAMP,
            ),
        ];
        for (extension, expected) in cases {
            assert_eq!(extension.ext_type(), expected);
            assert!(extension.data().is_empty());
        }
    }

    #[test]
    fn heartbeat_mode() {
        let extension = Extension::heartbeat(0x01);
        assert_eq!(extension.ext_type(), kind::HEARTBEAT);
        assert_eq!(extension.data(), &[0x01_u8][..]);
        assert_eq!(Extension::heartbeat(0x7F).data(), &[0x7F_u8][..]);
    }

    #[test]
    fn padding_is_zero_filled_and_checked_on_encode() {
        let extension = Extension::padding(5);
        assert_eq!(extension.ext_type(), kind::PADDING);
        assert_eq!(extension.data(), &[0_u8; 5][..]);
        assert!(Extension::padding(0).data().is_empty());

        let mut writer = Writer::new();
        assert!(Extension::padding(0x1_0000).encode(&mut writer).is_err());
        assert!(writer.is_empty());
    }
}
