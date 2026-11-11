//! Расширения `supported_groups` и `ec_point_formats` (RFC 8422, разделы
//! 5.1.1 и 5.1.2; RFC 8446, раздел 4.2.7).

use tls_data::NamedGroup;

use super::{Extension, kind};
use crate::error::EncodeError;

impl Extension {
    /// `supported_groups`: список групп в заданном порядке.
    ///
    /// Коды не проверяются: допустимы неизвестные таблицам значения,
    /// GREASE, повторы и пустой список.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если групп больше 32767.
    pub fn supported_groups(groups: &[NamedGroup]) -> Result<Self, EncodeError> {
        Self::build(kind::SUPPORTED_GROUPS, |writer| {
            writer.nested_u16(|list| {
                for group in groups {
                    list.put_u16(group.0);
                }
                Ok(())
            })
        })
    }

    /// `ec_point_formats`: список форматов точек, обычно один
    /// `uncompressed` (0).
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если форматов больше 255.
    pub fn ec_point_formats(formats: &[u8]) -> Result<Self, EncodeError> {
        Self::build(kind::EC_POINT_FORMATS, |writer| writer.put_vec_u8(formats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_groups_in_given_order() {
        let groups = [NamedGroup(0x001D), NamedGroup(0x0017), NamedGroup(0x0A0A)];
        let extension = Extension::supported_groups(&groups).unwrap();
        assert_eq!(extension.ext_type(), kind::SUPPORTED_GROUPS);
        assert_eq!(
            extension.data(),
            &[0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x0A, 0x0A][..]
        );
    }

    #[test]
    fn empty_group_list_is_allowed() {
        let extension = Extension::supported_groups(&[]).unwrap();
        assert_eq!(extension.data(), &[0x00, 0x00][..]);
    }

    #[test]
    fn group_list_overflow() {
        assert!(Extension::supported_groups(&vec![NamedGroup(0x001D); 0x7FFF]).is_ok());
        assert_eq!(
            Extension::supported_groups(&vec![NamedGroup(0x001D); 0x8000]),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                max: 0xFFFF,
                actual: 0x1_0000,
            })
        );
    }

    #[test]
    fn encodes_point_formats() {
        let extension = Extension::ec_point_formats(&[0x00]).unwrap();
        assert_eq!(extension.ext_type(), kind::EC_POINT_FORMATS);
        assert_eq!(extension.data(), &[0x01, 0x00][..]);

        let extension = Extension::ec_point_formats(&[0x00, 0x01, 0x02]).unwrap();
        assert_eq!(extension.data(), &[0x03, 0x00, 0x01, 0x02][..]);

        assert!(Extension::ec_point_formats(&[0_u8; 256]).is_err());
    }
}
