//! Расширение `key_share` в форме ClientHello (RFC 8446, раздел 4.2.8).
//!
//! Криптографии здесь нет: публичное значение передаёт вызывающий код как
//! готовые байты. Для проб, которым не нужно продолжать handshake, подходят
//! любые байты подходящей длины (например, 32 байта для x25519).

use tls_data::NamedGroup;

use super::{Extension, kind};
use crate::error::EncodeError;

/// Запись `KeyShareEntry`: группа и публичное значение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyShareEntry<'a> {
    /// Группа.
    pub group: NamedGroup,
    /// Публичное значение в кодировке группы.
    pub key_exchange: &'a [u8],
}

impl Extension {
    /// `key_share`: список записей в заданном порядке.
    ///
    /// Содержимое не проверяется: допустимы ключ любой длины, неизвестная
    /// группа, повторы. Пустой список допустим и по RFC: так клиент
    /// запрашивает HelloRetryRequest.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если публичное значение или весь
    /// список длиннее 65535 байтов.
    pub fn key_share(entries: &[KeyShareEntry<'_>]) -> Result<Self, EncodeError> {
        Self::build(kind::KEY_SHARE, |writer| {
            writer.nested_u16(|list| {
                for entry in entries {
                    list.put_u16(entry.group.0);
                    list.put_vec_u16(entry.key_exchange)?;
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
    fn encodes_single_x25519_entry() {
        let public = [0x42_u8; 32];
        let extension = Extension::key_share(&[KeyShareEntry {
            group: NamedGroup(0x001D),
            key_exchange: &public,
        }])
        .unwrap();
        assert_eq!(extension.ext_type(), kind::KEY_SHARE);
        let mut expected = vec![0x00, 0x24, 0x00, 0x1D, 0x00, 0x20];
        expected.extend_from_slice(&public);
        assert_eq!(extension.data(), expected.as_slice());
    }

    #[test]
    fn encodes_entries_in_given_order() {
        let extension = Extension::key_share(&[
            KeyShareEntry {
                group: NamedGroup(0x0A0A),
                key_exchange: &[0x00],
            },
            KeyShareEntry {
                group: NamedGroup(0x0017),
                key_exchange: &[0x04, 0xAA],
            },
        ])
        .unwrap();
        assert_eq!(
            extension.data(),
            &[
                0x00, 0x0B, 0x0A, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x02, 0x04, 0xAA
            ][..]
        );
    }

    #[test]
    fn empty_list_requests_hello_retry() {
        let extension = Extension::key_share(&[]).unwrap();
        assert_eq!(extension.data(), &[0x00, 0x00][..]);
    }

    #[test]
    fn key_and_list_overflow() {
        let too_long = vec![0_u8; 0x1_0000];
        assert!(matches!(
            Extension::key_share(&[KeyShareEntry {
                group: NamedGroup(0x001D),
                key_exchange: &too_long,
            }]),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                actual: 0x1_0000,
                ..
            })
        ));

        // Ключ помещается в свой префикс, список — нет.
        let large = vec![0_u8; 0xFFFC];
        assert!(matches!(
            Extension::key_share(&[KeyShareEntry {
                group: NamedGroup(0x001D),
                key_exchange: &large,
            }]),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                actual: 0x1_0000,
                ..
            })
        ));
    }
}
