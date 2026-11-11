//! Расширение `signature_algorithms` (RFC 8446, раздел 4.2.3; RFC 5246,
//! раздел 7.4.1.4.1).

use tls_data::SignatureScheme;

use super::{Extension, kind};
use crate::error::EncodeError;

impl Extension {
    /// `signature_algorithms`: список схем подписи в заданном порядке.
    ///
    /// Коды не проверяются: допустимы пары hash/signature из TLS 1.2,
    /// неизвестные значения, GREASE, повторы и пустой список.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если схем больше 32767.
    pub fn signature_algorithms(schemes: &[SignatureScheme]) -> Result<Self, EncodeError> {
        Self::build(kind::SIGNATURE_ALGORITHMS, |writer| {
            writer.nested_u16(|list| {
                for scheme in schemes {
                    list.put_u16(scheme.0);
                }
                Ok(())
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_schemes_in_given_order() {
        let schemes = [
            SignatureScheme(0x0403),
            SignatureScheme(0x0804),
            SignatureScheme(0x0201),
        ];
        let extension = Extension::signature_algorithms(&schemes).unwrap();
        assert_eq!(extension.ext_type(), kind::SIGNATURE_ALGORITHMS);
        assert_eq!(
            extension.data(),
            &[0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x02, 0x01][..]
        );
    }

    #[test]
    fn empty_and_overflowing_lists() {
        let extension = Extension::signature_algorithms(&[]).unwrap();
        assert_eq!(extension.data(), &[0x00, 0x00][..]);

        assert!(Extension::signature_algorithms(&vec![SignatureScheme(0x0403); 0x7FFF]).is_ok());
        assert!(matches!(
            Extension::signature_algorithms(&vec![SignatureScheme(0x0403); 0x8000]),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                ..
            })
        ));
    }
}
