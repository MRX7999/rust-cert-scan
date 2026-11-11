//! Расширения согласования прикладного протокола: ALPN (RFC 7301, раздел
//! 3.1) и NPN (draft-agl-tls-nextprotoneg).

use super::{Extension, kind};
use crate::error::EncodeError;

impl Extension {
    /// `application_layer_protocol_negotiation`: список имён протоколов в
    /// заданном порядке.
    ///
    /// Имена не проверяются: допустимы пустое имя (RFC его запрещает) и
    /// пустой список.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если имя длиннее 255 байтов или
    /// список длиннее 65535 байтов.
    pub fn alpn(protocols: &[&[u8]]) -> Result<Self, EncodeError> {
        Self::build(kind::ALPN, |writer| {
            writer.nested_u16(|list| {
                for protocol in protocols {
                    list.put_vec_u8(protocol)?;
                }
                Ok(())
            })
        })
    }

    /// `next_protocol_negotiation` в ClientHello: пустое тело, клиент лишь
    /// сообщает о поддержке NPN.
    #[must_use]
    pub fn next_protocol_negotiation() -> Self {
        Self::from_parts(kind::NEXT_PROTOCOL_NEGOTIATION, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_protocol_list() {
        let extension = Extension::alpn(&[b"h2", b"http/1.1"]).unwrap();
        assert_eq!(extension.ext_type(), kind::ALPN);
        let mut expected = vec![0x00, 0x0C, 0x02];
        expected.extend_from_slice(b"h2");
        expected.push(0x08);
        expected.extend_from_slice(b"http/1.1");
        assert_eq!(extension.data(), expected.as_slice());
    }

    #[test]
    fn empty_list_and_empty_name_are_allowed() {
        assert_eq!(Extension::alpn(&[]).unwrap().data(), &[0x00, 0x00][..]);
        assert_eq!(
            Extension::alpn(&[b""]).unwrap().data(),
            &[0x00, 0x01, 0x00][..]
        );
    }

    #[test]
    fn name_and_list_overflow() {
        let long_name = [b'x'; 256];
        assert_eq!(
            Extension::alpn(&[&long_name]),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 1,
                max: 0xFF,
                actual: 256,
            })
        );

        // 256 имён по 255 байтов: 65536 байтов списка.
        let name = [b'x'; 255];
        let protocols: Vec<&[u8]> = (0..256).map(|_| &name[..]).collect();
        assert!(matches!(
            Extension::alpn(&protocols),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                ..
            })
        ));
    }

    #[test]
    fn npn_has_empty_body() {
        let extension = Extension::next_protocol_negotiation();
        assert_eq!(extension.ext_type(), kind::NEXT_PROTOCOL_NEGOTIATION);
        assert!(extension.data().is_empty());
    }
}
