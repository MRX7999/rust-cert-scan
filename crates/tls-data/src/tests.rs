//! Тесты таблиц. Ожидаемые значения берутся из файлов данных: снимки
//! разбираются здесь построчно, независимо от разборщика в `build.rs`.

use std::collections::{BTreeMap, BTreeSet};

use crate::classify::{CipherInfo, MinProtocol};
use crate::{
    CipherSuite, Recommended, RegistryEntry, Sslv2CipherKind, alert, cipher, extension, group,
    sigscheme, sslv2,
};

const CIPHERS_CSV: &str = include_str!("../data/iana/tls-parameters-4.csv");
const ALERTS_CSV: &str = include_str!("../data/iana/tls-parameters-6.csv");
const GROUPS_CSV: &str = include_str!("../data/iana/tls-parameters-8.csv");
const SIGSCHEMES_CSV: &str = include_str!("../data/iana/tls-signaturescheme.csv");
const EXTENSIONS_CSV: &str = include_str!("../data/iana/tls-extensiontype-values-1.csv");
const MAPPING: &str = include_str!("../data/testssl/cipher-mapping.txt");

/// Строка реестра с одиночным кодом.
struct Row {
    code: u32,
    /// Первое слово описания.
    name: &'static str,
    /// Текст строки после столбца `Value` и запятой.
    rest: &'static str,
    line: &'static str,
}

fn hex(text: &str, digits: usize) -> Option<u32> {
    let body = text.strip_prefix("0x")?;
    if body.len() != digits {
        return None;
    }
    u32::from_str_radix(body, 16).ok()
}

fn pair_code(value: &str) -> Option<u32> {
    let (high, low) = value.split_once(',')?;
    Some((hex(high, 2)? << 8) | hex(low, 2)?)
}

fn hex16_code(value: &str) -> Option<u32> {
    hex(value, 4)
}

fn decimal_code(value: &str) -> Option<u32> {
    value.parse().ok()
}

/// Все строки с одиночным кодом. Диапазоны и строки-продолжения многострочных
/// полей отсеиваются тем, что их первое поле не разбирается как код.
fn single_rows(csv: &'static str, parse: fn(&str) -> Option<u32>) -> Vec<Row> {
    csv.lines()
        .skip(1)
        .filter_map(|raw| {
            let line = raw.trim_end_matches('\r');
            let (value, rest) = if let Some(stripped) = line.strip_prefix('"') {
                let (value, tail) = stripped.split_once('"')?;
                (value, tail.strip_prefix(',')?)
            } else {
                line.split_once(',')?
            };
            let code = parse(value)?;
            let name = rest
                .trim_start_matches('"')
                .split(&[',', ' ', '"'])
                .next()?;
            Some(Row {
                code,
                name,
                rest,
                line,
            })
        })
        .collect()
}

fn is_placeholder(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    name.is_empty() || lower.starts_with("unassigned") || lower.starts_with("reserved")
}

fn named_rows(csv: &'static str, parse: fn(&str) -> Option<u32>) -> Vec<Row> {
    single_rows(csv, parse)
        .into_iter()
        .filter(|row| !is_placeholder(row.name))
        .collect()
}

fn grease_codes(csv: &'static str, parse: fn(&str) -> Option<u32>) -> Vec<u32> {
    single_rows(csv, parse)
        .into_iter()
        .filter(|row| {
            row.name.to_ascii_lowercase().starts_with("reserved") && row.line.contains("RFC 8701")
        })
        .map(|row| row.code)
        .collect()
}

fn recommended(field: &str) -> Recommended {
    match field {
        "Y" => Recommended::Yes,
        "N" => Recommended::No,
        "D" => Recommended::Discouraged,
        "" => Recommended::Unspecified,
        other => panic!("неизвестное значение Recommended в CSV: {other}"),
    }
}

/// Параметры проверки одного простого реестра.
struct Check<C: 'static> {
    csv: &'static str,
    parse: fn(&str) -> Option<u32>,
    table: &'static [RegistryEntry<C>],
    max: u32,
    code_of: fn(C) -> u32,
    by_code: fn(u32) -> Option<&'static RegistryEntry<C>>,
    by_name: fn(&str) -> Option<&'static RegistryEntry<C>>,
    /// Номер поля `Recommended` после столбца `Value`, если столбец есть и
    /// строки можно делить по запятым.
    recommended_field: Option<usize>,
}

fn check_registry<C: Copy>(check: &Check<C>) {
    let named = named_rows(check.csv, check.parse);
    assert!(!named.is_empty());
    assert_eq!(check.table.len(), named.len());

    let mut name_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &named {
        *name_counts.entry(row.name).or_default() += 1;
    }

    for row in &named {
        let entry = (check.by_code)(row.code).unwrap();
        assert_eq!((check.code_of)(entry.code), row.code);
        assert_eq!(entry.name, row.name);

        let found = (check.by_name)(row.name).unwrap();
        assert_eq!(found.name, row.name);
        if name_counts.get(row.name) == Some(&1) {
            assert_eq!((check.code_of)(found.code), row.code);
        }

        if let Some(index) = check.recommended_field
            && !row.rest.contains('"')
        {
            let field = row.rest.split(',').nth(index).unwrap();
            assert_eq!(entry.recommended, recommended(field), "{}", row.line);
        }
    }

    let codes: Vec<u32> = check
        .table
        .iter()
        .map(|entry| (check.code_of)(entry.code))
        .collect();
    assert!(
        codes
            .iter()
            .zip(codes.iter().skip(1))
            .all(|(left, right)| left < right),
        "таблица должна быть строго отсортирована по коду"
    );

    let known: BTreeSet<u32> = codes.into_iter().collect();
    let unknown = (0..=check.max).find(|code| !known.contains(code)).unwrap();
    assert!((check.by_code)(unknown).is_none());
    assert!((check.by_name)("no_such_name_in_any_registry").is_none());
    assert!((check.by_name)("").is_none());
}

fn to_u16(code: u32) -> u16 {
    u16::try_from(code).unwrap()
}

#[test]
fn groups_match_csv() {
    check_registry(&Check {
        csv: GROUPS_CSV,
        parse: decimal_code,
        table: group::all(),
        max: 0xFFFF,
        code_of: |code| u32::from(code.0),
        by_code: |code| group::by_code(to_u16(code)),
        by_name: group::by_name,
        recommended_field: Some(2),
    });
    assert_eq!(group::iter().count(), group::all().len());
}

#[test]
fn signature_schemes_match_csv() {
    check_registry(&Check {
        csv: SIGSCHEMES_CSV,
        parse: hex16_code,
        table: sigscheme::all(),
        max: 0xFFFF,
        code_of: |code| u32::from(code.0),
        by_code: |code| sigscheme::by_code(to_u16(code)),
        by_name: sigscheme::by_name,
        recommended_field: Some(1),
    });
}

#[test]
fn extension_types_match_csv() {
    check_registry(&Check {
        csv: EXTENSIONS_CSV,
        parse: decimal_code,
        table: extension::all(),
        max: 0xFFFF,
        code_of: |code| u32::from(code.0),
        by_code: |code| extension::by_code(to_u16(code)),
        by_name: extension::by_name,
        recommended_field: None,
    });
}

#[test]
fn alerts_match_csv() {
    check_registry(&Check {
        csv: ALERTS_CSV,
        parse: decimal_code,
        table: alert::all(),
        max: 0xFF,
        code_of: |code| u32::from(code.0),
        by_code: |code| alert::by_code(u8::try_from(code).unwrap()),
        by_name: alert::by_name,
        recommended_field: None,
    });
    assert!(
        alert::iter().all(|entry| entry.recommended == Recommended::Unspecified),
        "в реестре alerts нет столбца Recommended"
    );
}

#[test]
fn wrapper_methods_agree_with_module_functions() {
    let row = named_rows(GROUPS_CSV, decimal_code)
        .into_iter()
        .find(|row| row.code == 29)
        .unwrap();
    let code = group::NamedGroup(29);
    assert_eq!(code.name(), Some(row.name));
    assert_eq!(group::NamedGroup::from_name(row.name), Some(code));
    assert_eq!(code.entry().map(|entry| entry.code), Some(code));
    assert_eq!(u16::from(code), 29);
    assert_eq!(group::NamedGroup::from(29_u16), code);
}

#[test]
fn duplicate_name_resolves_to_entry_without_note() {
    let rows = named_rows(EXTENSIONS_CSV, decimal_code);
    let same: Vec<&Row> = rows
        .iter()
        .filter(|row| row.name == "connection_id")
        .collect();
    assert_eq!(same.len(), 2, "в снимке ожидаются две записи connection_id");
    let plain = same
        .iter()
        .find(|row| row.rest.split(',').next() == Some("connection_id"))
        .unwrap();

    let found = extension::by_name("connection_id").unwrap();
    assert_eq!(u32::from(found.code.0), plain.code);
    assert!(found.note.is_empty());

    let annotated = same.iter().find(|row| row.code != plain.code).unwrap();
    let entry = extension::by_code(to_u16(annotated.code)).unwrap();
    assert_eq!(entry.name, "connection_id");
    assert!(!entry.note.is_empty());
    assert!(annotated.line.contains(entry.note));
}

#[test]
fn grease_values_match_csv() {
    let groups = grease_codes(GROUPS_CSV, decimal_code);
    assert!(!groups.is_empty());
    assert_eq!(
        group::grease()
            .map(|code| u32::from(code.0))
            .collect::<Vec<_>>(),
        groups
    );
    for code in &groups {
        let code = group::NamedGroup(to_u16(*code));
        assert!(code.is_grease());
        assert!(code.entry().is_none());
    }

    let extensions = grease_codes(EXTENSIONS_CSV, decimal_code);
    assert_eq!(
        extension::grease()
            .map(|code| u32::from(code.0))
            .collect::<Vec<_>>(),
        extensions
    );

    let ciphers = grease_codes(CIPHERS_CSV, pair_code);
    assert!(!ciphers.is_empty());
    assert_eq!(
        cipher::grease()
            .map(|code| u32::from(code.0))
            .collect::<Vec<_>>(),
        ciphers
    );
    for code in &ciphers {
        let code = CipherSuite(to_u16(*code));
        assert!(code.is_grease());
        assert!(code.entry().is_none());
    }

    assert_eq!(
        sigscheme::grease().count(),
        grease_codes(SIGSCHEMES_CSV, hex16_code).len()
    );
    assert_eq!(alert::grease().count(), 0);

    let first_named = named_rows(GROUPS_CSV, decimal_code)
        .into_iter()
        .next()
        .unwrap();
    assert!(!group::NamedGroup(to_u16(first_named.code)).is_grease());
}

/// Строка `cipher-mapping.txt`, разбитая по пробелам.
struct MapRow {
    bytes: Vec<u32>,
    tokens: Vec<&'static str>,
}

impl MapRow {
    fn code(&self) -> u32 {
        self.bytes.iter().fold(0, |acc, byte| (acc << 8) | byte)
    }

    fn token(&self, index: usize) -> &'static str {
        self.tokens.get(index).copied().unwrap()
    }

    fn is_sslv2(&self) -> bool {
        self.bytes.len() == 3
    }
}

fn mapping_rows() -> Vec<MapRow> {
    MAPPING
        .lines()
        .map(|line| {
            let tokens: Vec<&'static str> = line.split_whitespace().collect();
            let bytes = tokens
                .first()
                .unwrap()
                .split(',')
                .map(|byte| hex(byte, 2).unwrap())
                .collect();
            MapRow { bytes, tokens }
        })
        .collect()
}

fn dash_or(token: &'static str) -> &'static str {
    if token == "-" { "" } else { token }
}

/// Сверяет все поля и все признаки классификации со строкой файла.
fn check_info(info: &CipherInfo, row: &MapRow) {
    let line = row.tokens.join(" ");
    assert_eq!(info.openssl_name, dash_or(row.token(2)), "{line}");
    assert_eq!(info.mapping_name, dash_or(row.token(3)), "{line}");

    let protocol = match row.token(4) {
        "SSLv2" => MinProtocol::Ssl2,
        "SSLv3" => MinProtocol::Ssl3,
        "TLSv1" => MinProtocol::Tls10,
        "TLSv1.2" => MinProtocol::Tls12,
        "TLSv1.3" => MinProtocol::Tls13,
        other => panic!("неизвестный протокол в файле: {other}"),
    };
    assert_eq!(info.protocol, protocol, "{line}");

    let kx = match info.kx_bits {
        Some(bits) => format!("Kx={}({bits})", info.kx),
        None => format!("Kx={}", info.kx),
    };
    assert_eq!(kx, row.token(5), "{line}");
    assert_eq!(format!("Au={}", info.auth), row.token(6), "{line}");
    let enc = if info.enc == "None" {
        assert_eq!(info.enc_bits, 0, "{line}");
        "Enc=None".to_owned()
    } else {
        format!("Enc={}({})", info.enc, info.enc_bits)
    };
    assert_eq!(enc, row.token(7), "{line}");
    assert_eq!(format!("Mac={}", info.mac), row.token(8), "{line}");
    assert_eq!(info.export, row.tokens.len() == 10, "{line}");

    let enc_token = row.token(7);
    let kx_name = row.token(5).split('(').next().unwrap();
    assert_eq!(info.is_null(), enc_token == "Enc=None", "{line}");
    assert_eq!(info.is_anon(), row.token(6) == "Au=None", "{line}");
    assert_eq!(info.is_export(), row.tokens.contains(&"export"), "{line}");
    assert_eq!(info.is_rc4(), enc_token.starts_with("Enc=RC4("), "{line}");
    assert_eq!(info.is_des(), enc_token.starts_with("Enc=DES("), "{line}");
    assert_eq!(
        info.is_triple_des(),
        enc_token.starts_with("Enc=3DES("),
        "{line}"
    );
    assert_eq!(
        info.has_64bit_block(),
        ["Enc=DES(", "Enc=3DES(", "Enc=IDEA(", "Enc=RC2("]
            .iter()
            .any(|prefix| enc_token.starts_with(prefix)),
        "{line}"
    );
    assert_eq!(
        info.is_cbc(),
        row.token(3).contains("_CBC_") || row.token(2).contains("CBC"),
        "{line}"
    );
    assert_eq!(info.is_aead(), row.token(8) == "Mac=AEAD", "{line}");
    assert_eq!(
        info.has_forward_secrecy(),
        [
            "Kx=DH",
            "Kx=ECDH",
            "Kx=DHEPSK",
            "Kx=ECDHEPSK",
            "Kx=CECPQ1",
            "Kx=any"
        ]
        .contains(&kx_name),
        "{line}"
    );
}

#[test]
fn every_mapping_row_is_in_tables() {
    let rows = mapping_rows();
    assert!(!rows.is_empty());

    for row in rows.iter().filter(|row| !row.is_sslv2()) {
        let code = to_u16(row.code());
        let entry = cipher::by_code(code).unwrap();
        let info = entry.info.as_ref().unwrap();
        check_info(info, row);

        if row.token(2) != "-" {
            let found = cipher::by_openssl_name(row.token(2)).unwrap();
            assert_eq!(found.code, CipherSuite(code));
            assert_eq!(
                CipherSuite::from_openssl_name(row.token(2)),
                Some(CipherSuite(code))
            );
            assert_eq!(CipherSuite(code).openssl_name(), Some(row.token(2)));
        } else {
            assert_eq!(CipherSuite(code).openssl_name(), None);
        }
    }

    for row in rows.iter().filter(|row| row.is_sslv2()) {
        let entry = sslv2::by_code(row.code()).unwrap();
        check_info(&entry.info, row);
        assert_eq!(entry.info.protocol, MinProtocol::Ssl2);
        let found = sslv2::by_openssl_name(row.token(2)).unwrap();
        assert_eq!(found.code, Sslv2CipherKind(row.code()));
        assert_eq!(
            Sslv2CipherKind::from_openssl_name(row.token(2)),
            Some(Sslv2CipherKind(row.code()))
        );
        assert_eq!(
            Sslv2CipherKind(row.code()).openssl_name(),
            Some(row.token(2))
        );
    }

    let tls_rows = rows.iter().filter(|row| !row.is_sslv2()).count();
    let sslv2_rows = rows.iter().filter(|row| row.is_sslv2()).count();
    assert_eq!(
        cipher::iter().filter(|entry| entry.info.is_some()).count(),
        tls_rows
    );
    assert_eq!(sslv2::all().len(), sslv2_rows);
    assert_eq!(sslv2::iter().count(), sslv2_rows);
    assert!(sslv2_rows > 0);
}

#[test]
fn cipher_table_is_union_of_iana_and_mapping() {
    let iana = named_rows(CIPHERS_CSV, pair_code);
    let iana_codes: BTreeSet<u32> = iana.iter().map(|row| row.code).collect();
    assert_eq!(iana_codes.len(), iana.len(), "коды IANA не повторяются");
    let mapping_codes: BTreeSet<u32> = mapping_rows()
        .iter()
        .filter(|row| !row.is_sslv2())
        .map(MapRow::code)
        .collect();

    let union: BTreeSet<u32> = iana_codes.union(&mapping_codes).copied().collect();
    let only_iana = iana_codes.difference(&mapping_codes).count();
    let only_mapping = mapping_codes.difference(&iana_codes).count();

    let table = cipher::all();
    assert_eq!(table.len(), union.len());
    assert_eq!(
        table.iter().filter(|entry| entry.info.is_none()).count(),
        only_iana
    );
    assert_eq!(
        table
            .iter()
            .filter(|entry| entry.iana_name.is_empty())
            .count(),
        only_mapping
    );
    assert!(
        table
            .iter()
            .zip(table.iter().skip(1))
            .all(|(left, right)| left.code < right.code),
        "таблица шифров должна быть строго отсортирована по коду"
    );

    for row in &iana {
        let code = CipherSuite(to_u16(row.code));
        let entry = cipher::by_code(code.0).unwrap();
        assert_eq!(entry.iana_name, row.name);
        assert_eq!(code.iana_name(), Some(row.name));
        assert_eq!(
            cipher::by_iana_name(row.name).map(|entry| entry.code),
            Some(code)
        );
        assert_eq!(CipherSuite::from_iana_name(row.name), Some(code));
        let field = row.rest.split(',').nth(2).unwrap();
        assert_eq!(entry.recommended, recommended(field), "{}", row.line);
    }

    for code in mapping_codes.difference(&iana_codes) {
        let code = CipherSuite(to_u16(*code));
        let entry = code.entry().unwrap();
        assert_eq!(entry.iana_name, "");
        assert_eq!(entry.recommended, Recommended::Unspecified);
        assert_eq!(code.iana_name(), None);
        assert!(code.info().is_some());
    }

    // Имена у шифров, присутствующих в обоих источниках, совпадают либо
    // расхождение видно через `mapping_name`.
    let differing = table
        .iter()
        .filter(|entry| {
            entry.info.is_some_and(|info| {
                !entry.iana_name.is_empty()
                    && !info.mapping_name.is_empty()
                    && info.mapping_name != entry.iana_name
            })
        })
        .count();

    println!(
        "cipher suites: всего {}, IANA {}, cipher-mapping {}, только IANA {only_iana}, \
         только cipher-mapping {only_mapping}, разные имена {differing}",
        table.len(),
        iana_codes.len(),
        mapping_codes.len()
    );
    println!(
        "таблицы: groups {}, signature schemes {}, extensions {}, alerts {}, sslv2 {}; \
         GREASE: ciphers {}, groups {}, extensions {}, signature schemes {}",
        group::all().len(),
        sigscheme::all().len(),
        extension::all().len(),
        alert::all().len(),
        sslv2::all().len(),
        cipher::grease().count(),
        group::grease().count(),
        extension::grease().count(),
        sigscheme::grease().count()
    );
}

#[test]
fn plan_control_codes() {
    let iana = named_rows(CIPHERS_CSV, pair_code);
    for code in [0x1301_u16, 0xC02F] {
        let row = iana.iter().find(|row| row.code == u32::from(code)).unwrap();
        assert_eq!(CipherSuite(code).iana_name(), Some(row.name));
        assert!(CipherSuite(code).info().is_some());
    }
    assert!(group::by_code(29).is_some());

    let known: BTreeSet<u32> = cipher::iter()
        .map(|entry| u32::from(entry.code.0))
        .collect();
    let unknown = (0..=0xFFFF_u32).find(|code| !known.contains(code)).unwrap();
    assert!(cipher::by_code(to_u16(unknown)).is_none());
    assert!(CipherSuite(to_u16(unknown)).iana_name().is_none());
    assert!(cipher::by_iana_name("TLS_NO_SUCH_SUITE").is_none());
    assert!(cipher::by_openssl_name("NO-SUCH-CIPHER").is_none());
    assert!(cipher::by_openssl_name("").is_none());
    assert!(cipher::by_openssl_name("-").is_none());
    assert!(sslv2::by_code(0x00FF_FFFF).is_none());
    assert!(sslv2::by_openssl_name("NO-SUCH-CIPHER").is_none());
}

#[test]
fn code_byte_conversions() {
    let row = mapping_rows()
        .into_iter()
        .find(|row| !row.is_sslv2())
        .unwrap();
    let bytes: Vec<u8> = row
        .bytes
        .iter()
        .map(|byte| u8::try_from(*byte).unwrap())
        .collect();
    let pair = <[u8; 2]>::try_from(bytes.as_slice()).unwrap();
    let code = CipherSuite::from_bytes(pair);
    assert_eq!(u32::from(code.0), row.code());
    assert_eq!(code.to_bytes(), pair);
    assert_eq!(u16::from(code), code.0);
    assert_eq!(CipherSuite::from(code.0), code);

    let row = mapping_rows().into_iter().find(MapRow::is_sslv2).unwrap();
    let bytes: Vec<u8> = row
        .bytes
        .iter()
        .map(|byte| u8::try_from(*byte).unwrap())
        .collect();
    let triple = <[u8; 3]>::try_from(bytes.as_slice()).unwrap();
    let kind = Sslv2CipherKind::from_bytes(triple);
    assert_eq!(kind.0, row.code());
    assert_eq!(kind.to_bytes(), triple);
    assert!(kind.entry().is_some());
}

/// Имена признаков, которые у шифра истинны, в фиксированном порядке.
fn labels(info: &CipherInfo) -> Vec<&'static str> {
    [
        ("null", info.is_null()),
        ("anon", info.is_anon()),
        ("export", info.is_export()),
        ("rc4", info.is_rc4()),
        ("des", info.is_des()),
        ("3des", info.is_triple_des()),
        ("block64", info.has_64bit_block()),
        ("cbc", info.is_cbc()),
        ("aead", info.is_aead()),
        ("fs", info.has_forward_secrecy()),
    ]
    .into_iter()
    .filter(|(_, set)| *set)
    .map(|(label, _)| label)
    .collect()
}

/// Контрольный шифр: имя OpenSSL, таблица, поля его строки в файле, из
/// которых выведено ожидание, и ожидаемые признаки.
struct Control {
    openssl_name: &'static str,
    sslv2: bool,
    file_tokens: &'static [&'static str],
    expected: &'static [&'static str],
}

const CONTROLS: &[Control] = &[
    Control {
        openssl_name: "ECDHE-RSA-AES256-GCM-SHA384",
        sslv2: false,
        file_tokens: &["Kx=ECDH", "Au=RSA", "Enc=AESGCM(256)", "Mac=AEAD"],
        expected: &["aead", "fs"],
    },
    Control {
        openssl_name: "ECDHE-RSA-AES256-SHA",
        sslv2: false,
        file_tokens: &[
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "Kx=ECDH",
            "Enc=AES(256)",
            "Mac=SHA1",
        ],
        expected: &["cbc", "fs"],
    },
    Control {
        openssl_name: "TLS_AES_128_GCM_SHA256",
        sslv2: false,
        file_tokens: &["TLSv1.3", "Kx=any", "Au=any", "Enc=AESGCM(128)", "Mac=AEAD"],
        expected: &["aead", "fs"],
    },
    Control {
        openssl_name: "DES-CBC3-SHA",
        sslv2: false,
        file_tokens: &["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "Kx=RSA", "Enc=3DES(168)"],
        expected: &["3des", "block64", "cbc"],
    },
    Control {
        openssl_name: "DH-RSA-DES-CBC3-SHA",
        sslv2: false,
        file_tokens: &["Kx=DH/RSA", "Au=DH", "Enc=3DES(168)"],
        expected: &["3des", "block64", "cbc"],
    },
    Control {
        openssl_name: "DES-CBC-SHA",
        sslv2: false,
        file_tokens: &["TLS_RSA_WITH_DES_CBC_SHA", "Enc=DES(56)"],
        expected: &["des", "block64", "cbc"],
    },
    Control {
        openssl_name: "IDEA-CBC-SHA",
        sslv2: false,
        file_tokens: &["TLS_RSA_WITH_IDEA_CBC_SHA", "Enc=IDEA(128)"],
        expected: &["block64", "cbc"],
    },
    Control {
        openssl_name: "RC4-SHA",
        sslv2: false,
        file_tokens: &["Kx=RSA", "Enc=RC4(128)", "Mac=SHA1"],
        expected: &["rc4"],
    },
    Control {
        openssl_name: "EXP-RC4-MD5",
        sslv2: false,
        file_tokens: &["Kx=RSA(512)", "Enc=RC4(40)", "export"],
        expected: &["export", "rc4"],
    },
    Control {
        openssl_name: "EXP-EDH-DSS-DES-CBC-SHA",
        sslv2: false,
        file_tokens: &["Kx=DH(512)", "Au=DSS", "Enc=DES(40)", "export"],
        expected: &["export", "des", "block64", "cbc", "fs"],
    },
    Control {
        openssl_name: "NULL-SHA",
        sslv2: false,
        file_tokens: &["Kx=RSA", "Au=RSA", "Enc=None"],
        expected: &["null"],
    },
    Control {
        openssl_name: "NULL",
        sslv2: false,
        file_tokens: &["Kx=None", "Au=None", "Enc=None"],
        expected: &["null", "anon"],
    },
    Control {
        openssl_name: "DES-CFB-M1",
        sslv2: true,
        file_tokens: &["SSLv2", "SSL_CK_DES_64_CFB64_WITH_MD5_1", "Enc=DES(64)"],
        expected: &["des", "block64"],
    },
    Control {
        openssl_name: "EXP-RC2-CBC-MD5",
        sslv2: true,
        file_tokens: &["SSLv2", "Kx=RSA(512)", "Enc=RC2(40)", "export"],
        expected: &["export", "block64", "cbc"],
    },
];

#[test]
fn classification_of_control_ciphers() {
    let rows = mapping_rows();
    assert!(CONTROLS.len() >= 10);

    for control in CONTROLS {
        let row = rows
            .iter()
            .find(|row| row.is_sslv2() == control.sslv2 && row.token(2) == control.openssl_name)
            .unwrap();
        for token in control.file_tokens {
            assert!(
                row.tokens.contains(token),
                "в строке {} нет поля {token}",
                control.openssl_name
            );
        }

        let info = if control.sslv2 {
            sslv2::by_openssl_name(control.openssl_name).unwrap().info
        } else {
            cipher::by_openssl_name(control.openssl_name)
                .unwrap()
                .info
                .unwrap()
        };
        assert_eq!(labels(&info), control.expected, "{}", control.openssl_name);
    }

    // Анонимный шифр с эфемерным DH выбирается из файла по полям.
    let anon = rows
        .iter()
        .find(|row| !row.is_sslv2() && row.token(5) == "Kx=DH" && row.token(6) == "Au=None")
        .unwrap();
    let info = cipher::by_code(to_u16(anon.code())).unwrap().info.unwrap();
    assert!(info.is_anon());
    assert!(info.has_forward_secrecy());

    // Статический ECDH выбирается из файла по полю Kx.
    let fixed = rows
        .iter()
        .find(|row| row.token(5) == "Kx=ECDH/RSA")
        .unwrap();
    let info = cipher::by_code(to_u16(fixed.code())).unwrap().info.unwrap();
    assert!(!info.has_forward_secrecy());
}

#[test]
fn kx_bits_follow_file() {
    let rows = mapping_rows();
    let with_bits = rows
        .iter()
        .filter(|row| !row.is_sslv2() && row.token(5).contains('('))
        .count();
    assert!(with_bits > 0);
    assert_eq!(
        cipher::iter()
            .filter(|entry| entry.info.is_some_and(|info| info.kx_bits.is_some()))
            .count(),
        with_bits
    );
}
