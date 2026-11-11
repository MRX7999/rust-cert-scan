//! Расширения `supported_versions` (RFC 8446, раздел 4.2.1) и
//! `psk_key_exchange_modes` (RFC 8446, раздел 4.2.9).

use super::{Extension, kind};
use crate::error::EncodeError;
use crate::record::ProtocolVersion;

impl Extension {
    /// `supported_versions` в форме ClientHello: список версий в заданном
    /// порядке.
    ///
    /// Значения не проверяются: допустимы версии драфтов, GREASE, повторы и
    /// пустой список.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если версий больше 127.
    pub fn supported_versions(versions: &[ProtocolVersion]) -> Result<Self, EncodeError> {
        Self::build(kind::SUPPORTED_VERSIONS, |writer| {
            writer.nested_u8(|list| {
                for version in versions {
                    list.put_u16(version.0);
                }
                Ok(())
            })
        })
    }

    /// `psk_key_exchange_modes`: список режимов, `psk_ke` (0) и
    /// `psk_dhe_ke` (1).
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если режимов больше 255.
    pub fn psk_key_exchange_modes(modes: &[u8]) -> Result<Self, EncodeError> {
        Self::build(kind::PSK_KEY_EXCHANGE_MODES, |writer| {
            writer.put_vec_u8(modes)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_versions_in_given_order() {
        let extension =
            Extension::supported_versions(&[ProtocolVersion::TLS1_3, ProtocolVersion::TLS1_2])
                .unwrap();
        assert_eq!(extension.ext_type(), kind::SUPPORTED_VERSIONS);
        assert_eq!(extension.data(), &[0x04, 0x03, 0x04, 0x03, 0x03][..]);

        let grease = Extension::supported_versions(&[ProtocolVersion(0x7A7A)]).unwrap();
        assert_eq!(grease.data(), &[0x02, 0x7A, 0x7A][..]);
    }

    #[test]
    fn version_list_boundaries() {
        assert_eq!(
            Extension::supported_versions(&[]).unwrap().data(),
            &[0x00_u8][..]
        );
        assert!(Extension::supported_versions(&[ProtocolVersion::TLS1_3; 127]).is_ok());
        assert_eq!(
            Extension::supported_versions(&[ProtocolVersion::TLS1_3; 128]),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 1,
                max: 0xFF,
                actual: 256,
            })
        );
    }

    #[test]
    fn encodes_psk_modes() {
        let extension = Extension::psk_key_exchange_modes(&[0x01]).unwrap();
        assert_eq!(extension.ext_type(), kind::PSK_KEY_EXCHANGE_MODES);
        assert_eq!(extension.data(), &[0x01, 0x01][..]);

        let both = Extension::psk_key_exchange_modes(&[0x00, 0x01]).unwrap();
        assert_eq!(both.data(), &[0x02, 0x00, 0x01][..]);
        assert!(Extension::psk_key_exchange_modes(&[0_u8; 256]).is_err());
    }
}
