//! Расширение `server_name` (RFC 6066, раздел 3).

use super::{Extension, kind};
use crate::error::EncodeError;

/// Тип имени `host_name` в списке `ServerNameList`.
const NAME_TYPE_HOST_NAME: u8 = 0;

impl Extension {
    /// `server_name` с одним именем типа `host_name`.
    ///
    /// Имя передаётся байтами и не проверяется: допустимы пустое имя,
    /// IP-адрес и не-ASCII, если проверке нужен нестандартный SNI.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если имя не помещается в список с
    /// 16-битной длиной (длиннее 65532 байтов).
    pub fn server_name(host_name: &[u8]) -> Result<Self, EncodeError> {
        Self::build(kind::SERVER_NAME, |writer| {
            writer.nested_u16(|list| {
                list.put_u8(NAME_TYPE_HOST_NAME);
                list.put_vec_u16(host_name)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_host_name() {
        let extension = Extension::server_name(b"localhost").unwrap();
        assert_eq!(extension.ext_type(), kind::SERVER_NAME);
        let mut expected = vec![0x00, 0x0C, 0x00, 0x00, 0x09];
        expected.extend_from_slice(b"localhost");
        assert_eq!(extension.data(), expected.as_slice());
    }

    #[test]
    fn empty_name_is_allowed() {
        let extension = Extension::server_name(b"").unwrap();
        assert_eq!(extension.data(), &[0x00, 0x03, 0x00, 0x00, 0x00][..]);
    }

    #[test]
    fn name_length_boundary() {
        assert!(Extension::server_name(&vec![b'a'; 0xFFFC]).is_ok());
        assert_eq!(
            Extension::server_name(&vec![b'a'; 0xFFFD]),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                max: 0xFFFF,
                actual: 0x1_0000,
            })
        );
    }
}
