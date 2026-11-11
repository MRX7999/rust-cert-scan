//! Расширение `status_request` в форме ClientHello (RFC 6066, раздел 8).

use super::{Extension, kind};

/// Тип статуса `ocsp` в `CertificateStatusRequest`.
const STATUS_TYPE_OCSP: u8 = 1;

impl Extension {
    /// `status_request` с типом `ocsp`, пустым списком `responder_id_list`
    /// и пустым `request_extensions` — запрос OCSP stapling в том виде, в
    /// каком его шлют обычные клиенты. Иные варианты тела собираются через
    /// [`Extension::raw`].
    #[must_use]
    pub fn status_request() -> Self {
        Self::from_parts(
            kind::STATUS_REQUEST,
            vec![STATUS_TYPE_OCSP, 0x00, 0x00, 0x00, 0x00],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ocsp_request_with_empty_lists() {
        let extension = Extension::status_request();
        assert_eq!(extension.ext_type(), kind::STATUS_REQUEST);
        assert_eq!(extension.data(), &[0x01, 0x00, 0x00, 0x00, 0x00][..]);
    }
}
