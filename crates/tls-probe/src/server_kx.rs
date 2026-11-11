//! Разбор сообщения ServerKeyExchange (SSLv3 – TLS 1.2).
//!
//! Формат тела зависит от key exchange согласованного шифра и от версии
//! протокола, а в самом сообщении ни то, ни другое не записано. Поэтому
//! [`ServerKeyExchange::parse`] принимает тело, согласованную версию и
//! [`KeyExchangeKind`].
//!
//! # Как вид key exchange выводится из шифра
//!
//! [`KeyExchangeKind::from_cipher_info`] читает поля `kx`, `auth` и `export`
//! записи `tls_data::classify::CipherInfo` (строка `cipher-mapping.txt`
//! проекта testssl.sh; `kx` хранится без длины в скобках):
//!
//! | `Kx=` | Условие | Результат |
//! |---|---|---|
//! | `DH` | `Au=None` | [`KeyExchangeKind::Dhe`], `signed: false` |
//! | `DH` | иначе (`RSA`, `DSS`) | [`KeyExchangeKind::Dhe`], `signed: true` |
//! | `ECDH` | `Au=None` | [`KeyExchangeKind::Ecdhe`], `signed: false` |
//! | `ECDH` | иначе (`RSA`, `ECDSA`) | [`KeyExchangeKind::Ecdhe`], `signed: true` |
//! | `RSA` | признак `export` | [`KeyExchangeKind::RsaExport`] |
//! | `RSA` | без `export` | [`UnparsedReason::NoServerKeyExchange`] |
//! | `DH/RSA`, `DH/DSS`, `ECDH/RSA`, `ECDH/ECDSA`, `None` | | [`UnparsedReason::NoServerKeyExchange`] |
//! | `PSK`, `DHEPSK`, `ECDHEPSK`, `RSAPSK` | | [`UnparsedReason::Psk`] |
//! | `SRP`, `KRB5`, `GOST`, `CECPQ1` | | [`UnparsedReason::UnsupportedKeyExchange`] |
//! | `any` (шифры TLS 1.3) | | [`UnparsedReason::Tls13`] |
//! | любое другое | | [`UnparsedReason::UnknownKeyExchange`] |
//!
//! В `cipher-mapping.txt` `Kx=DH` и `Kx=ECDH` без суффикса — эфемерный обмен,
//! в том числе у export-шифров (`DH(512)`) и анонимных. Статический обмен
//! записан как `DH/RSA` и подобные: сервер при нём ServerKeyExchange не шлёт.
//!
//! # Что разбирается
//!
//! - DHE (RFC 5246, раздел 7.4.3): `dh_p`, `dh_g`, `dh_Ys` срезами;
//!   [`DheParams::p_bits`] — длина `p` в битах без ведущих нулей.
//! - ECDHE (RFC 8422, раздел 5.4): `curve_type`, `named_curve`, точка. Явно
//!   заданные кривые (`explicit_prime`, `explicit_char2`) не разбираются:
//!   [`UnparsedReason::ExplicitCurve`].
//! - Export-RSA (RFC 2246, раздел 7.4.3): `rsa_modulus`, `rsa_exponent`.
//! - Подпись: в TLS 1.2 — `SignatureScheme` и подпись; в SSLv3, TLS 1.0 и
//!   TLS 1.1 — подпись без алгоритма; у анонимных шифров подписи нет.
//!
//! Всё остальное возвращается как [`ServerKeyExchange::Unparsed`] с причиной
//! и срезом тела, без ошибки. Ошибка [`ParseError`] означает, что тело не
//! соответствует формату, который задан видом key exchange и версией.
//!
//! Подпись не проверяется, простое число DH со списками известных не
//! сравнивается: это задачи других крейтов (P1-20, P2-03). Для проверки
//! подписи доступен срез подписанных параметров `signed_params`.

use tls_data::classify::CipherInfo;
use tls_data::{NamedGroup, SignatureScheme};

use crate::codec::Reader;
use crate::error::ParseError;
use crate::record::ProtocolVersion;

/// Вид key exchange, от которого зависит формат ServerKeyExchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyExchangeKind {
    /// Эфемерный Diffie-Hellman над конечным полем.
    Dhe {
        /// Параметры подписаны (`false` у анонимных шифров).
        signed: bool,
    },
    /// Эфемерный Diffie-Hellman на эллиптических кривых.
    Ecdhe {
        /// Параметры подписаны (`false` у анонимных шифров).
        signed: bool,
    },
    /// Export-RSA: временный ключ RSA, параметры подписаны.
    RsaExport,
    /// Тело не разбирается; причина — в значении.
    Unsupported(UnparsedReason),
}

impl KeyExchangeKind {
    /// Вид key exchange по свойствам шифра; правила — в документации модуля.
    #[must_use]
    pub fn from_cipher_info(info: &CipherInfo) -> Self {
        let signed = info.auth != "None";
        match info.kx {
            "DH" => Self::Dhe { signed },
            "ECDH" => Self::Ecdhe { signed },
            "RSA" if info.export => Self::RsaExport,
            "RSA" | "DH/RSA" | "DH/DSS" | "ECDH/RSA" | "ECDH/ECDSA" | "None" => {
                Self::Unsupported(UnparsedReason::NoServerKeyExchange)
            }
            "PSK" | "DHEPSK" | "ECDHEPSK" | "RSAPSK" => Self::Unsupported(UnparsedReason::Psk),
            "SRP" | "KRB5" | "GOST" | "CECPQ1" => {
                Self::Unsupported(UnparsedReason::UnsupportedKeyExchange)
            }
            "any" => Self::Unsupported(UnparsedReason::Tls13),
            _ => Self::Unsupported(UnparsedReason::UnknownKeyExchange),
        }
    }

    /// Вид key exchange по свойствам шифра, если они известны. Для шифра,
    /// которого нет в `cipher-mapping.txt` (`info` равно `None`), —
    /// [`UnparsedReason::UnknownKeyExchange`].
    #[must_use]
    pub fn from_optional_info(info: Option<&CipherInfo>) -> Self {
        info.map_or(
            Self::Unsupported(UnparsedReason::UnknownKeyExchange),
            Self::from_cipher_info,
        )
    }
}

/// Почему тело ServerKeyExchange возвращено без разбора.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnparsedReason {
    /// PSK-варианты (`PSK`, `DHEPSK`, `ECDHEPSK`, `RSAPSK`): план их разбора
    /// не требует.
    Psk,
    /// Key exchange, при котором сервер ServerKeyExchange не шлёт (RSA без
    /// export, статические DH и ECDH, `Kx=None`). Сообщение при таком шифре
    /// — аномалия, которую оценивает вызывающий код.
    NoServerKeyExchange,
    /// Key exchange, разбор которого не реализован: SRP, KRB5, GOST, CECPQ1.
    UnsupportedKeyExchange,
    /// Шифр TLS 1.3 (`Kx=any`): в TLS 1.3 сообщения ServerKeyExchange нет.
    Tls13,
    /// Значение `Kx=` неизвестно либо шифр не классифицирован.
    UnknownKeyExchange,
    /// Версия протокола, для которой формат подписи не определён: не SSLv3,
    /// TLS 1.0, TLS 1.1 или TLS 1.2.
    UnsupportedVersion,
    /// ECDHE с явно заданной кривой (`curve_type` не равен `named_curve`).
    ExplicitCurve,
}

/// Тип кривой в `ECParameters` (RFC 8422, раздел 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EcCurveType(pub u8);

impl EcCurveType {
    /// `explicit_prime` (1).
    pub const EXPLICIT_PRIME: Self = Self(1);
    /// `explicit_char2` (2).
    pub const EXPLICIT_CHAR2: Self = Self(2);
    /// `named_curve` (3).
    pub const NAMED_CURVE: Self = Self(3);
}

/// Параметры `ServerDHParams`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DheParams<'a> {
    /// Простое число `dh_p`, big-endian, как в сообщении (ведущие нулевые
    /// байты сохранены).
    pub p: &'a [u8],
    /// Генератор `dh_g`.
    pub g: &'a [u8],
    /// Открытое значение сервера `dh_Ys`.
    pub ys: &'a [u8],
}

impl DheParams<'_> {
    /// Длина `p` в битах без ведущих нулевых байтов и битов; 0, если `p`
    /// состоит из нулей.
    #[must_use]
    pub fn p_bits(&self) -> usize {
        bit_len(self.p)
    }
}

/// Параметры `ServerECDHParams` с именованной кривой.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdheParams<'a> {
    /// Тип кривой; здесь всегда [`EcCurveType::NAMED_CURVE`].
    pub curve_type: EcCurveType,
    /// Именованная группа.
    pub named_curve: NamedGroup,
    /// Открытая точка сервера в том виде, в каком она передана.
    pub point: &'a [u8],
}

/// Параметры `ServerRSAParams` (export-RSA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaExportParams<'a> {
    /// Модуль временного ключа `rsa_modulus`, big-endian.
    pub modulus: &'a [u8],
    /// Открытая экспонента `rsa_exponent`.
    pub exponent: &'a [u8],
}

impl RsaExportParams<'_> {
    /// Длина модуля в битах без ведущих нулевых байтов и битов.
    #[must_use]
    pub fn modulus_bits(&self) -> usize {
        bit_len(self.modulus)
    }
}

/// Подпись параметров ServerKeyExchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KxSignature<'a> {
    /// Алгоритм подписи; `None` в SSLv3, TLS 1.0 и TLS 1.1, где он в
    /// сообщении не передаётся.
    pub scheme: Option<SignatureScheme>,
    /// Байты подписи.
    pub signature: &'a [u8],
}

/// Разобранное сообщение ServerKeyExchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKeyExchange<'a> {
    /// DHE.
    Dhe {
        /// Параметры.
        params: DheParams<'a>,
        /// Байты `ServerDHParams`, которые покрывает подпись.
        signed_params: &'a [u8],
        /// Подпись; `None` у анонимных шифров.
        signature: Option<KxSignature<'a>>,
    },
    /// ECDHE с именованной кривой.
    Ecdhe {
        /// Параметры.
        params: EcdheParams<'a>,
        /// Байты `ServerECDHParams`, которые покрывает подпись.
        signed_params: &'a [u8],
        /// Подпись; `None` у анонимных шифров.
        signature: Option<KxSignature<'a>>,
    },
    /// Export-RSA.
    RsaExport {
        /// Параметры.
        params: RsaExportParams<'a>,
        /// Байты `ServerRSAParams`, которые покрывает подпись.
        signed_params: &'a [u8],
        /// Подпись.
        signature: KxSignature<'a>,
    },
    /// Тело не разобрано.
    Unparsed {
        /// Причина.
        reason: UnparsedReason,
        /// Тело сообщения целиком.
        body: &'a [u8],
    },
}

/// Формат подписи в зависимости от версии и вида key exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureFormat {
    /// Подписи нет (анонимный шифр).
    Absent,
    /// Подпись без алгоритма: SSLv3, TLS 1.0, TLS 1.1.
    Bare,
    /// `SignatureScheme` и подпись: TLS 1.2.
    WithScheme,
}

impl SignatureFormat {
    /// `None` для версии, в которой формат ServerKeyExchange не определён.
    fn select(version: ProtocolVersion, signed: bool) -> Option<Self> {
        let format = match version {
            ProtocolVersion::SSL3_0 | ProtocolVersion::TLS1_0 | ProtocolVersion::TLS1_1 => {
                Self::Bare
            }
            ProtocolVersion::TLS1_2 => Self::WithScheme,
            _ => return None,
        };
        Some(if signed { format } else { Self::Absent })
    }

    fn read<'a>(self, reader: &mut Reader<'a>) -> Result<Option<KxSignature<'a>>, ParseError> {
        let scheme = match self {
            Self::Absent => return Ok(None),
            Self::Bare => None,
            Self::WithScheme => Some(SignatureScheme(reader.u16()?)),
        };
        let signature = reader.vec_u16()?;
        Ok(Some(KxSignature { scheme, signature }))
    }
}

impl<'a> ServerKeyExchange<'a> {
    /// Разбирает тело ServerKeyExchange.
    ///
    /// `version` — согласованная версия протокола (для TLS 1.2 и ниже —
    /// версия из ServerHello), `kind` — вид key exchange согласованного
    /// шифра, см. [`KeyExchangeKind::from_cipher_info`].
    ///
    /// # Errors
    ///
    /// - [`ParseError::UnexpectedEof`], если тело оборвано или длина поля
    ///   больше остатка;
    /// - [`ParseError::InvalidValue`], если обязательное поле (`dh_p`,
    ///   `dh_g`, `dh_Ys`, точка, модуль, экспонента) пустое;
    /// - [`ParseError::TrailingBytes`], если после последнего поля остались
    ///   байты.
    ///
    /// Вид [`KeyExchangeKind::Unsupported`], неподдерживаемая версия и явно
    /// заданная кривая ошибкой не являются: возвращается
    /// [`ServerKeyExchange::Unparsed`].
    pub fn parse(
        body: &'a [u8],
        version: ProtocolVersion,
        kind: KeyExchangeKind,
    ) -> Result<Self, ParseError> {
        let signed = match kind {
            KeyExchangeKind::Dhe { signed } | KeyExchangeKind::Ecdhe { signed } => signed,
            KeyExchangeKind::RsaExport => true,
            KeyExchangeKind::Unsupported(reason) => return Ok(Self::Unparsed { reason, body }),
        };
        let Some(format) = SignatureFormat::select(version, signed) else {
            return Ok(Self::Unparsed {
                reason: UnparsedReason::UnsupportedVersion,
                body,
            });
        };

        let mut reader = Reader::new(body);
        let message = match kind {
            KeyExchangeKind::Dhe { .. } => {
                let params = DheParams {
                    p: non_empty_u16(&mut reader, "пустое поле dh_p")?,
                    g: non_empty_u16(&mut reader, "пустое поле dh_g")?,
                    ys: non_empty_u16(&mut reader, "пустое поле dh_Ys")?,
                };
                let signed_params = consumed(body, &reader);
                Self::Dhe {
                    params,
                    signed_params,
                    signature: format.read(&mut reader)?,
                }
            }
            KeyExchangeKind::Ecdhe { .. } => {
                let curve_type = EcCurveType(reader.u8()?);
                if curve_type != EcCurveType::NAMED_CURVE {
                    return Ok(Self::Unparsed {
                        reason: UnparsedReason::ExplicitCurve,
                        body,
                    });
                }
                let named_curve = NamedGroup(reader.u16()?);
                let position = reader.position();
                let point = reader.vec_u8()?;
                if point.is_empty() {
                    return Err(ParseError::InvalidValue {
                        position,
                        what: "пустая точка ECDHE",
                    });
                }
                let signed_params = consumed(body, &reader);
                Self::Ecdhe {
                    params: EcdheParams {
                        curve_type,
                        named_curve,
                        point,
                    },
                    signed_params,
                    signature: format.read(&mut reader)?,
                }
            }
            KeyExchangeKind::RsaExport => {
                let params = RsaExportParams {
                    modulus: non_empty_u16(&mut reader, "пустое поле rsa_modulus")?,
                    exponent: non_empty_u16(&mut reader, "пустое поле rsa_exponent")?,
                };
                let signed_params = consumed(body, &reader);
                let position = reader.position();
                let Some(signature) = format.read(&mut reader)? else {
                    return Err(ParseError::Internal {
                        position,
                        what: "export-RSA без формата подписи",
                    });
                };
                Self::RsaExport {
                    params,
                    signed_params,
                    signature,
                }
            }
            KeyExchangeKind::Unsupported(reason) => Self::Unparsed { reason, body },
        };
        reader.finish()?;
        Ok(message)
    }

    /// Подпись параметров, если она есть.
    #[must_use]
    pub fn signature(&self) -> Option<&KxSignature<'a>> {
        match self {
            Self::Dhe { signature, .. } | Self::Ecdhe { signature, .. } => signature.as_ref(),
            Self::RsaExport { signature, .. } => Some(signature),
            Self::Unparsed { .. } => None,
        }
    }
}

/// Вектор с двухбайтовой длиной, который по формату не может быть пустым.
fn non_empty_u16<'a>(reader: &mut Reader<'a>, what: &'static str) -> Result<&'a [u8], ParseError> {
    let position = reader.position();
    let value = reader.vec_u16()?;
    if value.is_empty() {
        return Err(ParseError::InvalidValue { position, what });
    }
    Ok(value)
}

/// Байты тела, уже прочитанные читателем, созданным над `body`.
fn consumed<'a>(body: &'a [u8], reader: &Reader<'a>) -> &'a [u8] {
    body.get(..reader.position()).unwrap_or(body)
}

/// Длина big-endian числа в битах без ведущих нулевых байтов и битов.
fn bit_len(value: &[u8]) -> usize {
    let mut bytes = value.iter().copied().skip_while(|byte| *byte == 0);
    let Some(first) = bytes.next() else {
        return 0;
    };
    let top = usize::try_from(u8::BITS.saturating_sub(first.leading_zeros())).unwrap_or(8);
    bytes.count().saturating_mul(8).saturating_add(top)
}

#[cfg(test)]
mod tests {
    //! Все тесты модуля синтетические: байты составлены вручную по RFC 5246
    //! (раздел 7.4.3), RFC 8422 (раздел 5.4) и RFC 2246 (раздел 7.4.3), это
    //! не записи серверов. Тесты на записанных фикстурах — в
    //! `fixture_tests.rs`.

    use tls_data::cipher::CipherSuite;

    use super::*;

    const DHE_SIGNED: KeyExchangeKind = KeyExchangeKind::Dhe { signed: true };
    const DHE_ANON: KeyExchangeKind = KeyExchangeKind::Dhe { signed: false };
    const ECDHE_SIGNED: KeyExchangeKind = KeyExchangeKind::Ecdhe { signed: true };
    const ECDHE_ANON: KeyExchangeKind = KeyExchangeKind::Ecdhe { signed: false };

    fn vec16(data: &[u8]) -> Vec<u8> {
        let mut out = u16::try_from(data.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(data);
        out
    }

    fn dh_params(p: &[u8], g: &[u8], ys: &[u8]) -> Vec<u8> {
        [vec16(p), vec16(g), vec16(ys)].concat()
    }

    fn ecdh_params(group: u16, point: &[u8]) -> Vec<u8> {
        let mut out = vec![0x03];
        out.extend(group.to_be_bytes());
        out.push(u8::try_from(point.len()).unwrap());
        out.extend_from_slice(point);
        out
    }

    fn signature_tls12(scheme: u16, signature: &[u8]) -> Vec<u8> {
        let mut out = scheme.to_be_bytes().to_vec();
        out.extend(vec16(signature));
        out
    }

    fn kind_of(code: u16) -> KeyExchangeKind {
        KeyExchangeKind::from_optional_info(CipherSuite(code).info())
    }

    #[test]
    fn kind_is_derived_from_cipher_table() {
        let unsupported = KeyExchangeKind::Unsupported;
        let cases = [
            // ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256.
            (0xC02C, ECDHE_SIGNED),
            (0xC02F, ECDHE_SIGNED),
            // AECDH-AES128-SHA.
            (0xC018, ECDHE_ANON),
            // DHE-RSA-AES128-GCM-SHA256, DHE-DSS-AES128-SHA.
            (0x009E, DHE_SIGNED),
            (0x0032, DHE_SIGNED),
            // ADH-AES128-SHA.
            (0x0034, DHE_ANON),
            // EXP-EDH-RSA-DES-CBC-SHA (Kx=DH(512)), EXP-ADH-RC4-MD5.
            (0x0014, DHE_SIGNED),
            (0x0017, DHE_ANON),
            // EXP-RC4-MD5 (Kx=RSA(512), export).
            (0x0003, KeyExchangeKind::RsaExport),
            // AES128-SHA: RSA без export.
            (0x002F, unsupported(UnparsedReason::NoServerKeyExchange)),
            // ECDH-ECDSA-AES128-SHA: статический ECDH.
            (0xC004, unsupported(UnparsedReason::NoServerKeyExchange)),
            // TLS_NULL_WITH_NULL_NULL: Kx=None.
            (0x0000, unsupported(UnparsedReason::NoServerKeyExchange)),
            // PSK-AES128-CBC-SHA, DHE-PSK-AES128-CBC-SHA.
            (0x008C, unsupported(UnparsedReason::Psk)),
            (0x0090, unsupported(UnparsedReason::Psk)),
            // SRP-3DES-EDE-CBC-SHA.
            (0xC01A, unsupported(UnparsedReason::UnsupportedKeyExchange)),
            // TLS_AES_128_GCM_SHA256.
            (0x1301, unsupported(UnparsedReason::Tls13)),
            // Кода нет в таблице.
            (0xFFFE, unsupported(UnparsedReason::UnknownKeyExchange)),
        ];
        for (code, expected) in cases {
            assert_eq!(kind_of(code), expected, "шифр {code:#06x}");
        }
    }

    #[test]
    fn every_classified_cipher_maps_without_unknown_kx() {
        // Отображение покрывает все значения Kx= таблицы: неизвестных нет.
        for entry in tls_data::cipher::iter() {
            if let Some(info) = entry.info.as_ref() {
                assert_ne!(
                    KeyExchangeKind::from_cipher_info(info),
                    KeyExchangeKind::Unsupported(UnparsedReason::UnknownKeyExchange),
                    "шифр {:#06x}, Kx={}",
                    entry.code.0,
                    info.kx
                );
            }
        }
    }

    #[test]
    fn bit_length_ignores_leading_zero_bytes_and_bits() {
        assert_eq!(bit_len(&[]), 0);
        assert_eq!(bit_len(&[0x00, 0x00]), 0);
        assert_eq!(bit_len(&[0x01]), 1);
        assert_eq!(bit_len(&[0x80]), 8);
        assert_eq!(bit_len(&[0x00, 0x7F, 0xFF]), 15);
        assert_eq!(bit_len(&[0x00, 0x00, 0xFF, 0x00]), 16);
        let mut p = vec![0x00, 0xC0];
        p.extend([0xFF; 255]);
        assert_eq!(bit_len(&p), 2048);
        *p.get_mut(1).unwrap() = 0x40;
        assert_eq!(bit_len(&p), 2047);
    }

    #[test]
    fn dhe_signed_tls12() {
        let p = [0x00, 0xFF, 0x01];
        let params = dh_params(&p, &[0x02], &[0x12, 0x34]);
        let mut body = params.clone();
        body.extend(signature_tls12(0x0401, &[0xAA; 4]));

        let message = ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_2, DHE_SIGNED).unwrap();
        let ServerKeyExchange::Dhe {
            params: parsed,
            signed_params,
            signature,
        } = message
        else {
            panic!("ожидался DHE, получено {message:?}");
        };
        assert_eq!(parsed.p, &p[..]);
        assert_eq!(parsed.p_bits(), 16);
        assert_eq!(parsed.g, &[0x02][..]);
        assert_eq!(parsed.ys, &[0x12, 0x34][..]);
        assert_eq!(signed_params, &params[..]);
        assert_eq!(
            signature,
            Some(KxSignature {
                scheme: Some(SignatureScheme(0x0401)),
                signature: &[0xAA; 4],
            })
        );
        assert_eq!(message.signature(), signature.as_ref());
    }

    #[test]
    fn dhe_signature_without_algorithm_before_tls12() {
        let mut body = dh_params(&[0x7F, 0xFF], &[0x05], &[0x01]);
        body.extend(vec16(&[0xBB; 3]));
        for version in [
            ProtocolVersion::SSL3_0,
            ProtocolVersion::TLS1_0,
            ProtocolVersion::TLS1_1,
        ] {
            let message = ServerKeyExchange::parse(&body, version, DHE_SIGNED).unwrap();
            assert_eq!(
                message.signature(),
                Some(&KxSignature {
                    scheme: None,
                    signature: &[0xBB; 3],
                }),
                "{version:?}"
            );
        }

        // То же тело в формате TLS 1.2 читается иначе и не сходится по длине.
        let error =
            ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_2, DHE_SIGNED).unwrap_err();
        assert!(matches!(error, ParseError::UnexpectedEof { .. }), "{error}");
    }

    #[test]
    fn anonymous_dhe_has_no_signature() {
        let body = dh_params(&[0xFF; 8], &[0x02], &[0x01; 8]);
        for version in [ProtocolVersion::TLS1_0, ProtocolVersion::TLS1_2] {
            let message = ServerKeyExchange::parse(&body, version, DHE_ANON).unwrap();
            let ServerKeyExchange::Dhe {
                params,
                signed_params,
                signature,
            } = message
            else {
                panic!("ожидался DHE, получено {message:?}");
            };
            assert_eq!(params.p_bits(), 64);
            assert_eq!(signed_params, &body[..]);
            assert_eq!(signature, None);
            assert_eq!(message.signature(), None);
        }

        // Подпись после параметров анонимного шифра — лишние байты.
        let mut extra = body.clone();
        extra.extend(signature_tls12(0x0401, &[0xAA]));
        assert_eq!(
            ServerKeyExchange::parse(&extra, ProtocolVersion::TLS1_2, DHE_ANON).unwrap_err(),
            ParseError::TrailingBytes {
                position: body.len(),
                remaining: 5,
            }
        );
    }

    #[test]
    fn ecdhe_named_curves() {
        // secp256r1 (0x0017), несжатая точка 65 байт; x25519 (0x001d), 32 байта.
        let mut p256_point = vec![0x04];
        p256_point.extend([0x5A; 64]);
        let cases: [(u16, &[u8]); 2] = [(0x0017, &p256_point), (0x001D, &[0x77; 32])];
        for (group, point) in cases {
            let params = ecdh_params(group, point);
            let mut body = params.clone();
            body.extend(signature_tls12(0x0403, &[0x30, 0x02, 0x01, 0x01]));

            let message =
                ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_2, ECDHE_SIGNED).unwrap();
            let ServerKeyExchange::Ecdhe {
                params: parsed,
                signed_params,
                signature,
            } = message
            else {
                panic!("ожидался ECDHE, получено {message:?}");
            };
            assert_eq!(parsed.curve_type, EcCurveType::NAMED_CURVE);
            assert_eq!(parsed.named_curve, NamedGroup(group));
            assert_eq!(parsed.point, point);
            assert_eq!(signed_params, &params[..]);
            let signature = signature.unwrap();
            assert_eq!(signature.scheme, Some(SignatureScheme(0x0403)));
            assert_eq!(signature.signature, &[0x30, 0x02, 0x01, 0x01][..]);
        }
    }

    #[test]
    fn ecdhe_anonymous_and_pre_tls12() {
        let params = ecdh_params(0x0017, &[0x04, 0x01, 0x02]);
        let message =
            ServerKeyExchange::parse(&params, ProtocolVersion::TLS1_0, ECDHE_ANON).unwrap();
        assert_eq!(message.signature(), None);

        let mut body = params.clone();
        body.extend(vec16(&[0xCC; 2]));
        let message =
            ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_1, ECDHE_SIGNED).unwrap();
        assert_eq!(
            message.signature(),
            Some(&KxSignature {
                scheme: None,
                signature: &[0xCC; 2],
            })
        );
    }

    #[test]
    fn explicit_curve_is_returned_unparsed() {
        for curve_type in [0x01_u8, 0x02, 0x00, 0xFF] {
            let body = [curve_type, 0x00, 0x17, 0x01, 0x04];
            assert_eq!(
                ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_2, ECDHE_SIGNED).unwrap(),
                ServerKeyExchange::Unparsed {
                    reason: UnparsedReason::ExplicitCurve,
                    body: &body,
                }
            );
        }
    }

    #[test]
    fn rsa_export() {
        let mut modulus = vec![0x00, 0x80];
        modulus.extend([0x11; 63]);
        let params = [vec16(&modulus), vec16(&[0x01, 0x00, 0x01])].concat();
        let mut body = params.clone();
        body.extend(vec16(&[0xDD; 6]));

        let message =
            ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_0, KeyExchangeKind::RsaExport)
                .unwrap();
        let ServerKeyExchange::RsaExport {
            params: parsed,
            signed_params,
            signature,
        } = message
        else {
            panic!("ожидался export-RSA, получено {message:?}");
        };
        assert_eq!(parsed.modulus, &modulus[..]);
        assert_eq!(parsed.modulus_bits(), 512);
        assert_eq!(parsed.exponent, &[0x01, 0x00, 0x01][..]);
        assert_eq!(signed_params, &params[..]);
        assert_eq!(signature.scheme, None);
        assert_eq!(signature.signature, &[0xDD; 6][..]);
        assert_eq!(message.signature(), Some(&signature));
    }

    #[test]
    fn unsupported_kinds_and_versions_are_not_errors() {
        let body = [0xDE_u8, 0xAD, 0xBE, 0xEF];
        let reasons = [
            UnparsedReason::Psk,
            UnparsedReason::NoServerKeyExchange,
            UnparsedReason::UnsupportedKeyExchange,
            UnparsedReason::Tls13,
            UnparsedReason::UnknownKeyExchange,
        ];
        for reason in reasons {
            let kind = KeyExchangeKind::Unsupported(reason);
            let message = ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_2, kind).unwrap();
            assert_eq!(
                message,
                ServerKeyExchange::Unparsed {
                    reason,
                    body: &body
                }
            );
            assert_eq!(message.signature(), None);
        }

        // Пустое тело при неразбираемом виде тоже не ошибка.
        let kind = KeyExchangeKind::Unsupported(UnparsedReason::Psk);
        assert!(ServerKeyExchange::parse(&[], ProtocolVersion::TLS1_2, kind).is_ok());

        for version in [
            ProtocolVersion::TLS1_3,
            ProtocolVersion(0x0002),
            ProtocolVersion(0xFEFD),
        ] {
            for kind in [
                DHE_SIGNED,
                DHE_ANON,
                ECDHE_SIGNED,
                KeyExchangeKind::RsaExport,
            ] {
                assert_eq!(
                    ServerKeyExchange::parse(&body, version, kind).unwrap(),
                    ServerKeyExchange::Unparsed {
                        reason: UnparsedReason::UnsupportedVersion,
                        body: &body,
                    },
                    "{version:?} {kind:?}"
                );
            }
        }
    }

    #[test]
    fn every_truncation_is_an_error() {
        let mut dhe12 = dh_params(&[0xFF; 4], &[0x02], &[0x09; 4]);
        dhe12.extend(signature_tls12(0x0804, &[0xAA; 5]));
        let mut dhe10 = dh_params(&[0xFF; 4], &[0x02], &[0x09; 4]);
        dhe10.extend(vec16(&[0xAA; 5]));
        let dhe_anon = dh_params(&[0xFF; 4], &[0x02], &[0x09; 4]);
        let mut ecdhe12 = ecdh_params(0x001D, &[0x77; 32]);
        ecdhe12.extend(signature_tls12(0x0403, &[0xAA; 5]));
        let ecdhe_anon = ecdh_params(0x0017, &[0x04; 5]);
        let mut rsa = [vec16(&[0xC1; 8]), vec16(&[0x03])].concat();
        rsa.extend(vec16(&[0xAA; 5]));

        let cases = [
            (dhe12, ProtocolVersion::TLS1_2, DHE_SIGNED),
            (dhe10, ProtocolVersion::TLS1_0, DHE_SIGNED),
            (dhe_anon, ProtocolVersion::TLS1_2, DHE_ANON),
            (ecdhe12, ProtocolVersion::TLS1_2, ECDHE_SIGNED),
            (ecdhe_anon, ProtocolVersion::TLS1_2, ECDHE_ANON),
            (rsa, ProtocolVersion::SSL3_0, KeyExchangeKind::RsaExport),
        ];
        for (body, version, kind) in cases {
            assert!(ServerKeyExchange::parse(&body, version, kind).is_ok());
            for len in 0..body.len() {
                let error = ServerKeyExchange::parse(&body[..len], version, kind).unwrap_err();
                assert!(
                    matches!(error, ParseError::UnexpectedEof { .. }),
                    "{kind:?}, длина {len}: {error}"
                );
            }

            let mut extra = body.clone();
            extra.push(0x00);
            assert_eq!(
                ServerKeyExchange::parse(&extra, version, kind).unwrap_err(),
                ParseError::TrailingBytes {
                    position: body.len(),
                    remaining: 1,
                },
                "{kind:?}"
            );
        }
    }

    #[test]
    fn field_length_larger_than_body() {
        // dh_p заявлен на 0xFFFF байт: память не выделяется, ошибка по остатку.
        let body = [0xFF, 0xFF, 0x01, 0x02];
        let error =
            ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_2, DHE_SIGNED).unwrap_err();
        assert!(matches!(error, ParseError::UnexpectedEof { .. }), "{error}");

        // Точка заявлена на 255 байт.
        let body = [0x03, 0x00, 0x17, 0xFF, 0x04];
        let error =
            ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_2, ECDHE_SIGNED).unwrap_err();
        assert!(matches!(error, ParseError::UnexpectedEof { .. }), "{error}");

        // Подпись заявлена длиннее остатка.
        let mut body = ecdh_params(0x0017, &[0x04; 3]);
        body.extend([0x04, 0x03, 0x00, 0x09, 0xAA]);
        let error =
            ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_2, ECDHE_SIGNED).unwrap_err();
        assert!(matches!(error, ParseError::UnexpectedEof { .. }), "{error}");
    }

    #[test]
    fn empty_mandatory_fields_are_invalid() {
        let cases: [(Vec<u8>, KeyExchangeKind, usize, &str); 6] = [
            (
                dh_params(&[], &[0x02], &[0x01]),
                DHE_ANON,
                0,
                "пустое поле dh_p",
            ),
            (
                dh_params(&[0xFF], &[], &[0x01]),
                DHE_ANON,
                3,
                "пустое поле dh_g",
            ),
            (
                dh_params(&[0xFF], &[0x02], &[]),
                DHE_ANON,
                6,
                "пустое поле dh_Ys",
            ),
            (
                ecdh_params(0x0017, &[]),
                ECDHE_ANON,
                3,
                "пустая точка ECDHE",
            ),
            (
                [vec16(&[]), vec16(&[0x03]), vec16(&[0xAA])].concat(),
                KeyExchangeKind::RsaExport,
                0,
                "пустое поле rsa_modulus",
            ),
            (
                [vec16(&[0xC1]), vec16(&[]), vec16(&[0xAA])].concat(),
                KeyExchangeKind::RsaExport,
                3,
                "пустое поле rsa_exponent",
            ),
        ];
        for (body, kind, position, what) in cases {
            assert_eq!(
                ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_0, kind).unwrap_err(),
                ParseError::InvalidValue { position, what },
                "{kind:?}"
            );
        }

        // Пустая подпись форматом допускается (opaque<0..2^16-1>).
        let mut body = dh_params(&[0xFF], &[0x02], &[0x01]);
        body.extend(vec16(&[]));
        let message = ServerKeyExchange::parse(&body, ProtocolVersion::TLS1_0, DHE_SIGNED).unwrap();
        assert_eq!(message.signature().map(|s| s.signature.len()), Some(0));
    }
}
