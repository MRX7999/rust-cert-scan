//! Расширения ClientHello: тип [`Extension`] и его конструкторы.
//!
//! [`Extension`] — код типа и уже закодированное тело. Типизированные
//! конструкторы (`Extension::server_name`, `Extension::key_share` и другие)
//! лежат в подмодулях и кодируют тело по соответствующему RFC;
//! [`Extension::raw`] принимает произвольные тип и байты.
//!
//! Конструкторы не проверяют содержимое на допустимость: пустые списки,
//! неизвестные коды, ключи неверной длины и значения GREASE кодируются как
//! заданы. Ошибка возвращается, только если данные не помещаются в префикс
//! длины. Порядок и повторы расширений определяет вызывающий код, см.
//! [`ClientHello`](crate::client_hello::ClientHello).
//!
//! Коды типов собраны в модуле [`kind`]; их соответствие реестру IANA из
//! `tls-data` проверяется тестом.

mod alpn;
mod groups;
mod key_share;
mod raw;
mod sigalgs;
mod sni;
mod status_request;
mod versions;

pub use key_share::KeyShareEntry;
use tls_data::ExtensionType;

use crate::codec::{Reader, Writer};
use crate::error::{EncodeError, ParseError};

/// Коды типов расширений, для которых есть типизированная сборка или разбор.
pub mod kind {
    use tls_data::ExtensionType;

    /// `server_name` (RFC 6066).
    pub const SERVER_NAME: ExtensionType = ExtensionType(0);
    /// `status_request` (RFC 6066).
    pub const STATUS_REQUEST: ExtensionType = ExtensionType(5);
    /// `supported_groups` (RFC 8422, RFC 7919).
    pub const SUPPORTED_GROUPS: ExtensionType = ExtensionType(10);
    /// `ec_point_formats` (RFC 8422).
    pub const EC_POINT_FORMATS: ExtensionType = ExtensionType(11);
    /// `signature_algorithms` (RFC 8446).
    pub const SIGNATURE_ALGORITHMS: ExtensionType = ExtensionType(13);
    /// `heartbeat` (RFC 6520).
    pub const HEARTBEAT: ExtensionType = ExtensionType(15);
    /// `application_layer_protocol_negotiation` (RFC 7301).
    pub const ALPN: ExtensionType = ExtensionType(16);
    /// `signed_certificate_timestamp` (RFC 6962).
    pub const SIGNED_CERTIFICATE_TIMESTAMP: ExtensionType = ExtensionType(18);
    /// `padding` (RFC 7685).
    pub const PADDING: ExtensionType = ExtensionType(21);
    /// `encrypt_then_mac` (RFC 7366).
    pub const ENCRYPT_THEN_MAC: ExtensionType = ExtensionType(22);
    /// `extended_master_secret` (RFC 7627); в текущем реестре IANA запись
    /// переименована в `extended_main_secret`.
    pub const EXTENDED_MASTER_SECRET: ExtensionType = ExtensionType(23);
    /// `session_ticket` (RFC 5077).
    pub const SESSION_TICKET: ExtensionType = ExtensionType(35);
    /// `supported_versions` (RFC 8446).
    pub const SUPPORTED_VERSIONS: ExtensionType = ExtensionType(43);
    /// `psk_key_exchange_modes` (RFC 8446).
    pub const PSK_KEY_EXCHANGE_MODES: ExtensionType = ExtensionType(45);
    /// `key_share` (RFC 8446).
    pub const KEY_SHARE: ExtensionType = ExtensionType(51);
    /// `next_protocol_negotiation` (NPN, draft-agl-tls-nextprotoneg). В
    /// реестре IANA код 13172 именованной записи не имеет.
    pub const NEXT_PROTOCOL_NEGOTIATION: ExtensionType = ExtensionType(13172);
    /// `renegotiation_info` (RFC 5746).
    pub const RENEGOTIATION_INFO: ExtensionType = ExtensionType(0xFF01);
}

/// Расширение ClientHello: код типа и закодированное тело.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    ext_type: ExtensionType,
    data: Vec<u8>,
}

impl Extension {
    /// Код типа расширения.
    #[must_use]
    pub fn ext_type(&self) -> ExtensionType {
        self.ext_type
    }

    /// Закодированное тело без кода типа и префикса длины.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Пишет расширение: код типа, 16-битную длину и тело.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если тело длиннее 65535 байтов;
    /// буфер при этом не меняется.
    pub fn encode(&self, writer: &mut Writer) -> Result<(), EncodeError> {
        if self.data.len() > 0xFFFF {
            return Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                max: 0xFFFF,
                actual: self.data.len(),
            });
        }
        writer.put_u16(self.ext_type.0);
        writer.put_vec_u16(&self.data)
    }

    /// Расширение с готовым телом.
    pub(crate) fn from_parts(ext_type: ExtensionType, data: Vec<u8>) -> Self {
        Self { ext_type, data }
    }

    /// Расширение, тело которого пишет замыкание.
    pub(crate) fn build<F>(ext_type: ExtensionType, fill: F) -> Result<Self, EncodeError>
    where
        F: FnOnce(&mut Writer) -> Result<(), EncodeError>,
    {
        let mut writer = Writer::new();
        fill(&mut writer)?;
        Ok(Self::from_parts(ext_type, writer.as_slice().to_vec()))
    }
}

/// Расширение в разобранном hello: код типа и тело, заимствованное из
/// входного буфера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawExtension<'a> {
    /// Код типа расширения.
    pub ext_type: ExtensionType,
    /// Тело без кода типа и префикса длины.
    pub data: &'a [u8],
}

/// Итератор по списку расширений: последовательность «тип, 16-битная длина,
/// тело» без общего префикса длины.
///
/// Ничего не аллоцирует. При нарушении формата возвращает одну ошибку и на
/// этом заканчивается.
#[derive(Debug, Clone)]
pub struct RawExtensions<'a> {
    reader: Reader<'a>,
}

impl<'a> RawExtensions<'a> {
    /// Итератор по содержимому блока расширений. Позиции в ошибках
    /// отсчитываются так же, как в переданном читателе.
    #[must_use]
    pub fn new(reader: Reader<'a>) -> Self {
        Self { reader }
    }

    fn read(&mut self) -> Result<RawExtension<'a>, ParseError> {
        let ext_type = ExtensionType(self.reader.u16()?);
        let data = self.reader.vec_u16()?;
        Ok(RawExtension { ext_type, data })
    }
}

impl<'a> Iterator for RawExtensions<'a> {
    type Item = Result<RawExtension<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        let result = self.read();
        if result.is_err() {
            let _ = self.reader.rest();
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterates_raw_extensions() {
        let block = [
            0x00, 0x17, 0x00, 0x00, 0xFF, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00,
        ];
        let items: Vec<_> = RawExtensions::new(Reader::new(&block))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            items,
            vec![
                RawExtension {
                    ext_type: kind::EXTENDED_MASTER_SECRET,
                    data: &[],
                },
                RawExtension {
                    ext_type: kind::RENEGOTIATION_INFO,
                    data: &[0x00],
                },
                RawExtension {
                    ext_type: kind::EXTENDED_MASTER_SECRET,
                    data: &[],
                },
            ]
        );
        assert_eq!(RawExtensions::new(Reader::new(&[])).count(), 0);
    }

    #[test]
    fn raw_extensions_stop_after_error() {
        // Второе расширение заявляет 5 байтов тела, есть только 1.
        let block = [0x00, 0x17, 0x00, 0x00, 0x00, 0x10, 0x00, 0x05, 0xAA];
        let mut iter = RawExtensions::new(Reader::new(&block));
        assert!(matches!(iter.next(), Some(Ok(_))));
        assert_eq!(
            iter.next(),
            Some(Err(ParseError::UnexpectedEof {
                position: 8,
                needed: 5,
                available: 1,
            }))
        );
        assert_eq!(iter.next(), None);

        // Обрезанный заголовок расширения.
        let mut iter = RawExtensions::new(Reader::new(&[0x00, 0x17, 0x00]));
        assert!(matches!(
            iter.next(),
            Some(Err(ParseError::UnexpectedEof { .. }))
        ));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn kinds_match_iana_registry() {
        let named = [
            (kind::SERVER_NAME, "server_name"),
            (kind::STATUS_REQUEST, "status_request"),
            (kind::SUPPORTED_GROUPS, "supported_groups"),
            (kind::EC_POINT_FORMATS, "ec_point_formats"),
            (kind::SIGNATURE_ALGORITHMS, "signature_algorithms"),
            (kind::HEARTBEAT, "heartbeat"),
            (kind::ALPN, "application_layer_protocol_negotiation"),
            (
                kind::SIGNED_CERTIFICATE_TIMESTAMP,
                "signed_certificate_timestamp",
            ),
            (kind::PADDING, "padding"),
            (kind::ENCRYPT_THEN_MAC, "encrypt_then_mac"),
            (kind::EXTENDED_MASTER_SECRET, "extended_main_secret"),
            (kind::SESSION_TICKET, "session_ticket"),
            (kind::SUPPORTED_VERSIONS, "supported_versions"),
            (kind::PSK_KEY_EXCHANGE_MODES, "psk_key_exchange_modes"),
            (kind::KEY_SHARE, "key_share"),
            (kind::RENEGOTIATION_INFO, "renegotiation_info"),
        ];
        for (code, name) in named {
            assert_eq!(code.name(), Some(name), "код {}", code.0);
            assert_eq!(ExtensionType::from_name(name), Some(code));
        }
        assert_eq!(kind::NEXT_PROTOCOL_NEGOTIATION.0, 0x3374);
    }

    #[test]
    fn encodes_type_length_and_body() {
        let extension = Extension::from_parts(ExtensionType(0xABCD), vec![0x01, 0x02, 0x03]);
        assert_eq!(extension.ext_type(), ExtensionType(0xABCD));
        assert_eq!(extension.data(), &[0x01, 0x02, 0x03][..]);
        let mut writer = Writer::new();
        extension.encode(&mut writer).unwrap();
        assert_eq!(
            writer.as_slice(),
            &[0xAB, 0xCD, 0x00, 0x03, 0x01, 0x02, 0x03][..]
        );

        let empty = Extension::from_parts(kind::EXTENDED_MASTER_SECRET, Vec::new());
        let mut writer = Writer::new();
        empty.encode(&mut writer).unwrap();
        assert_eq!(writer.as_slice(), &[0x00, 0x17, 0x00, 0x00][..]);
    }

    #[test]
    fn body_overflow_leaves_buffer_untouched() {
        let extension = Extension::from_parts(kind::PADDING, vec![0_u8; 0x1_0000]);
        let mut writer = Writer::new();
        writer.put_u8(0x55);
        assert_eq!(
            extension.encode(&mut writer),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                max: 0xFFFF,
                actual: 0x1_0000,
            })
        );
        assert_eq!(writer.as_slice(), &[0x55_u8][..]);

        let at_limit = Extension::from_parts(kind::PADDING, vec![0_u8; 0xFFFF]);
        assert_eq!(at_limit.encode(&mut writer), Ok(()));
    }

    #[test]
    fn build_propagates_closure_error() {
        let result = Extension::build(kind::ALPN, |writer| writer.put_vec_u8(&[0_u8; 256]));
        assert!(matches!(
            result,
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 1,
                ..
            })
        ));
    }
}
