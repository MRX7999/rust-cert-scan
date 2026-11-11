//! Генерация статических таблиц `tls-data` из снимков в `data/`.
//!
//! Входы (только локальные файлы, сеть не используется):
//!
//! - `data/iana/*.csv` — снимки реестров IANA (P1-01);
//! - `data/testssl/cipher-mapping.txt` — таблица шифров testssl.sh (P1-02).
//!
//! Выход: `$OUT_DIR/tables.rs` с массивами, отсортированными по коду, и
//! индексами имён, отсортированными по имени. Файл подключается в
//! `src/lib.rs` через `include!`. Правила отбора строк описаны в
//! doc-комментариях `src/lib.rs` и `src/classify.rs`.
//!
//! Любая ошибка разбора завершает сборку с сообщением вида
//! `<файл>:<строка>: <причина>`.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Каталог снимков IANA относительно манифеста крейта.
const IANA_DIR: &str = "data/iana";

/// Таблица шифров testssl.sh относительно манифеста крейта.
const CIPHER_MAPPING: &str = "data/testssl/cipher-mapping.txt";

/// Подстрока столбца `Reference`, по которой одиночная запись `Reserved`
/// распознаётся как значение GREASE.
const GREASE_REFERENCE: &str = "RFC 8701";

/// Запись столбца `Value` в реестре.
#[derive(Clone, Copy)]
enum ValueSyntax {
    /// Два байта: `0x13,0x01`; диапазоны `0x00,0x1C-1D`, `0x01-09,*`.
    BytePair,
    /// Десятичное число: `29`; диапазоны `1-9`.
    Decimal,
    /// Четыре hex-цифры: `0x0403`; диапазоны `0x0000-0x0200`.
    Hex16,
}

/// Описание одного реестра IANA и имён генерируемых для него таблиц.
struct RegistrySpec {
    /// Имя файла в `data/iana/`.
    file: &'static str,
    /// Запись столбца `Value`.
    syntax: ValueSyntax,
    /// Наибольшее допустимое кодовое значение.
    max: u32,
    /// Заголовок столбца с именем записи.
    name_column: &'static str,
    /// Имя генерируемой таблицы.
    table: &'static str,
    /// Путь к типу-обёртке кода.
    code_type: &'static str,
    /// Целочисленный тип кода.
    int: &'static str,
}

/// Реестр cipher suites: генерируется отдельно, со слиянием с cipher-mapping.
const CIPHER_SUITES: RegistrySpec = RegistrySpec {
    file: "tls-parameters-4.csv",
    syntax: ValueSyntax::BytePair,
    max: 0xFFFF,
    name_column: "Description",
    table: "CIPHER_SUITES",
    code_type: "crate::cipher::CipherSuite",
    int: "u16",
};

/// Реестры, которые превращаются в таблицу `RegistryEntry` без дополнений.
const SIMPLE_REGISTRIES: &[RegistrySpec] = &[
    RegistrySpec {
        file: "tls-parameters-8.csv",
        syntax: ValueSyntax::Decimal,
        max: 0xFFFF,
        name_column: "Description",
        table: "NAMED_GROUPS",
        code_type: "crate::group::NamedGroup",
        int: "u16",
    },
    RegistrySpec {
        file: "tls-signaturescheme.csv",
        syntax: ValueSyntax::Hex16,
        max: 0xFFFF,
        name_column: "Description",
        table: "SIGNATURE_SCHEMES",
        code_type: "crate::sigscheme::SignatureScheme",
        int: "u16",
    },
    RegistrySpec {
        file: "tls-extensiontype-values-1.csv",
        syntax: ValueSyntax::Decimal,
        max: 0xFFFF,
        name_column: "Extension Name",
        table: "EXTENSION_TYPES",
        code_type: "crate::extension::ExtensionType",
        int: "u16",
    },
    RegistrySpec {
        file: "tls-parameters-6.csv",
        syntax: ValueSyntax::Decimal,
        max: 0xFF,
        name_column: "Description",
        table: "ALERT_DESCRIPTIONS",
        code_type: "crate::alert::AlertDescription",
        int: "u8",
    },
];

/// Одна запись CSV: номер первой строки записи в файле и её поля.
struct CsvRecord {
    line: usize,
    fields: Vec<String>,
}

/// Именованная запись реестра IANA.
struct NamedRow {
    name: String,
    note: String,
    /// Имя варианта `crate::Recommended`.
    recommended: &'static str,
}

/// Разобранный реестр: именованные записи по коду и значения GREASE.
struct Registry {
    named: BTreeMap<u32, NamedRow>,
    grease: Vec<u32>,
}

/// Одна строка `cipher-mapping.txt`.
struct MappingRow {
    openssl_name: String,
    mapping_name: String,
    /// Имя варианта `crate::classify::MinProtocol`.
    protocol: &'static str,
    kx: String,
    kx_bits: Option<u16>,
    auth: String,
    enc: String,
    enc_bits: u16,
    mac: String,
    export: bool,
}

/// Разобранный `cipher-mapping.txt`: двухбайтовые коды и SSLv2 cipher kinds.
struct CipherMapping {
    tls: BTreeMap<u32, MappingRow>,
    sslv2: BTreeMap<u32, MappingRow>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: tls-data build.rs: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let manifest_dir = PathBuf::from(env_var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(env_var("OUT_DIR")?);
    println!("cargo:rerun-if-changed=build.rs");

    let mut out = String::from("// Сгенерировано build.rs из data/. Не редактировать.\n\n");

    for spec in SIMPLE_REGISTRIES {
        let registry = load_registry(&manifest_dir, spec)?;
        emit_simple(&mut out, spec, &registry)?;
    }

    let iana = load_registry(&manifest_dir, &CIPHER_SUITES)?;
    let mapping = load_cipher_mapping(&manifest_dir)?;
    emit_ciphers(&mut out, &iana, &mapping)?;

    let dest = out_dir.join("tables.rs");
    fs::write(&dest, out).map_err(|error| format!("{}: {error}", dest.display()))
}

fn env_var(name: &str) -> Result<String, String> {
    env::var(name).map_err(|error| format!("переменная окружения {name}: {error}"))
}

/// Читает файл данных и объявляет его входом сборки.
fn read_data(manifest_dir: &Path, relative: &str) -> Result<String, String> {
    println!("cargo:rerun-if-changed={relative}");
    let path = manifest_dir.join(relative);
    fs::read_to_string(&path).map_err(|error| format!("{relative}: {error}"))
}

/// Минимальный разборщик CSV: поля в двойных кавычках могут содержать
/// запятые, переводы строк и удвоенную кавычку; окончания строк — LF или CRLF.
fn parse_csv(file: &str, text: &str) -> Result<Vec<CsvRecord>, String> {
    let mut records = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut has_content = false;
    let mut line = 1_usize;
    let mut record_line = 1_usize;

    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_quotes {
            match ch {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                    }
                }
                '\n' => {
                    line += 1;
                    field.push('\n');
                }
                '\r' => {}
                other => field.push(other),
            }
            continue;
        }
        match ch {
            '"' => {
                if !field.is_empty() {
                    return Err(format!("{file}:{line}: кавычка в середине поля"));
                }
                in_quotes = true;
                has_content = true;
            }
            ',' => {
                fields.push(std::mem::take(&mut field));
                has_content = true;
            }
            '\r' => {}
            '\n' => {
                if has_content {
                    fields.push(std::mem::take(&mut field));
                    records.push(CsvRecord {
                        line: record_line,
                        fields: std::mem::take(&mut fields),
                    });
                }
                has_content = false;
                line += 1;
                record_line = line;
            }
            other => {
                field.push(other);
                has_content = true;
            }
        }
    }

    if in_quotes {
        return Err(format!("{file}:{record_line}: незакрытая кавычка в записи"));
    }
    if has_content {
        fields.push(field);
        records.push(CsvRecord {
            line: record_line,
            fields,
        });
    }
    Ok(records)
}

/// Разбирает снимок реестра IANA.
///
/// Отбор строк: диапазоны, `Unassigned`, `Reserved` и записи без имени в
/// таблицу не попадают; одиночные `Reserved` со ссылкой на RFC 8701
/// собираются в список GREASE.
fn load_registry(manifest_dir: &Path, spec: &RegistrySpec) -> Result<Registry, String> {
    let relative = format!("{IANA_DIR}/{}", spec.file);
    let text = read_data(manifest_dir, &relative)?;
    let mut records = parse_csv(&relative, &text)?.into_iter();

    let header = records
        .next()
        .ok_or_else(|| format!("{relative}:1: файл пуст, нет строки заголовка"))?;
    let column = |name: &str| header.fields.iter().position(|title| title.trim() == name);
    let required = |name: &str| {
        column(name).ok_or_else(|| format!("{relative}:{}: нет столбца `{name}`", header.line))
    };
    let value_col = required("Value")?;
    let name_col = required(spec.name_column)?;
    let reference_col = required("Reference")?;
    let recommended_col = column("Recommended");
    let width = header.fields.len();

    let mut named: BTreeMap<u32, NamedRow> = BTreeMap::new();
    let mut grease: BTreeSet<u32> = BTreeSet::new();

    for record in records {
        let at = format!("{relative}:{}", record.line);
        if record.fields.len() != width {
            return Err(format!(
                "{at}: ожидалось полей: {width}, получено: {}",
                record.fields.len()
            ));
        }
        let field = |index: usize| record.fields.get(index).map_or("", |text| text.trim());

        let Some(code) =
            parse_value(spec, field(value_col)).map_err(|error| format!("{at}: {error}"))?
        else {
            continue;
        };

        let description = field(name_col);
        let lower = description.to_ascii_lowercase();
        if lower.starts_with("unassigned") {
            continue;
        }
        if lower.starts_with("reserved") {
            if field(reference_col).contains(GREASE_REFERENCE) {
                grease.insert(code);
            }
            continue;
        }

        let mut parts = description.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let note = parts.next().unwrap_or("").trim();

        let recommended = match recommended_col.map(&field) {
            None | Some("") => "Unspecified",
            Some("Y") => "Yes",
            Some("N") => "No",
            Some("D") => "Discouraged",
            Some(other) => {
                return Err(format!("{at}: неизвестное значение Recommended: `{other}`"));
            }
        };

        let row = NamedRow {
            name: name.to_owned(),
            note: note.to_owned(),
            recommended,
        };
        if named.insert(code, row).is_some() {
            return Err(format!("{at}: повторное кодовое значение {code:#06X}"));
        }
    }

    Ok(Registry {
        named,
        grease: grease.into_iter().collect(),
    })
}

/// Разбирает столбец `Value`. Диапазон даёт `None`, одиночный код — `Some`.
fn parse_value(spec: &RegistrySpec, text: &str) -> Result<Option<u32>, String> {
    if text.contains('-') || text.contains('*') {
        return Ok(None);
    }
    let code = match spec.syntax {
        ValueSyntax::BytePair => {
            let (high, low) = text
                .split_once(',')
                .ok_or_else(|| format!("ожидалась пара байтов `0xHH,0xHH`, получено `{text}`"))?;
            (parse_hex(high, 2)? << 8) | parse_hex(low, 2)?
        }
        ValueSyntax::Decimal => text
            .parse::<u32>()
            .map_err(|error| format!("ожидалось десятичное число, получено `{text}`: {error}"))?,
        ValueSyntax::Hex16 => parse_hex(text, 4)?,
    };
    if code > spec.max {
        return Err(format!(
            "кодовое значение {code} больше допустимого {}",
            spec.max
        ));
    }
    Ok(Some(code))
}

/// Разбирает `0x` и ровно `digits` шестнадцатеричных цифр.
fn parse_hex(text: &str, digits: usize) -> Result<u32, String> {
    let body = text
        .trim()
        .strip_prefix("0x")
        .ok_or_else(|| format!("ожидался префикс `0x`, получено `{text}`"))?;
    if body.len() != digits {
        return Err(format!("ожидалось hex-цифр: {digits}, получено `{text}`"));
    }
    u32::from_str_radix(body, 16)
        .map_err(|error| format!("некорректное hex-число `{text}`: {error}"))
}

/// Разбирает `cipher-mapping.txt`.
///
/// Формат строки (поля разделены пробелами):
/// `<код> - <имя OpenSSL> <имя RFC> <протокол> Kx=<kx> Au=<au> Enc=<enc> Mac=<mac> [export]`.
fn load_cipher_mapping(manifest_dir: &Path) -> Result<CipherMapping, String> {
    let text = read_data(manifest_dir, CIPHER_MAPPING)?;
    let mut tls: BTreeMap<u32, MappingRow> = BTreeMap::new();
    let mut sslv2: BTreeMap<u32, MappingRow> = BTreeMap::new();

    for (index, raw) in text.lines().enumerate() {
        let at = format!("{CIPHER_MAPPING}:{}", index + 1);
        let tokens: Vec<&str> = raw.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let [
            code,
            dash,
            openssl,
            rfc,
            protocol,
            kx,
            auth,
            enc,
            mac,
            rest @ ..,
        ] = tokens.as_slice()
        else {
            return Err(format!(
                "{at}: ожидалось не менее 9 полей, получено: {}",
                tokens.len()
            ));
        };
        if *dash != "-" {
            return Err(format!(
                "{at}: второе поле должно быть `-`, получено `{dash}`"
            ));
        }
        let export = match rest {
            [] => false,
            ["export"] => true,
            _ => return Err(format!("{at}: неожиданные поля после Mac: {rest:?}")),
        };

        let protocol = match *protocol {
            "SSLv2" => "Ssl2",
            "SSLv3" => "Ssl3",
            "TLSv1" => "Tls10",
            "TLSv1.2" => "Tls12",
            "TLSv1.3" => "Tls13",
            other => return Err(format!("{at}: неизвестный протокол `{other}`")),
        };
        let (kx, kx_bits) = split_bits(tagged(kx, "Kx=", &at)?, &at)?;
        let (enc, enc_bits) = split_bits(tagged(enc, "Enc=", &at)?, &at)?;

        let row = MappingRow {
            openssl_name: dash_to_empty(openssl),
            mapping_name: dash_to_empty(rfc),
            protocol,
            kx: kx.to_owned(),
            kx_bits,
            auth: tagged(auth, "Au=", &at)?.to_owned(),
            enc: enc.to_owned(),
            enc_bits: enc_bits.unwrap_or(0),
            mac: tagged(mac, "Mac=", &at)?.to_owned(),
            export,
        };

        let bytes = code
            .split(',')
            .map(|byte| parse_hex(byte, 2))
            .collect::<Result<Vec<u32>, String>>()
            .map_err(|error| format!("{at}: {error}"))?;
        let (table, value) = match bytes.as_slice() {
            [high, low] => (&mut tls, (high << 8) | low),
            [first, second, third] => (&mut sslv2, (first << 16) | (second << 8) | third),
            _ => {
                return Err(format!(
                    "{at}: код должен состоять из 2 или 3 байтов: `{code}`"
                ));
            }
        };
        if (protocol == "Ssl2") != (bytes.len() == 3) {
            return Err(format!(
                "{at}: трёхбайтовый код и протокол SSLv2 должны встречаться вместе"
            ));
        }
        if table.insert(value, row).is_some() {
            return Err(format!("{at}: повторный код `{code}`"));
        }
    }

    Ok(CipherMapping { tls, sslv2 })
}

/// Снимает обязательный префикс вида `Kx=`.
fn tagged<'a>(token: &'a str, prefix: &str, at: &str) -> Result<&'a str, String> {
    token
        .strip_prefix(prefix)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{at}: ожидалось поле `{prefix}...`, получено `{token}`"))
}

/// Делит `AES(256)` на имя и число бит; значение без скобок — без числа.
fn split_bits<'a>(value: &'a str, at: &str) -> Result<(&'a str, Option<u16>), String> {
    let Some((name, tail)) = value.split_once('(') else {
        return Ok((value, None));
    };
    let digits = tail
        .strip_suffix(')')
        .ok_or_else(|| format!("{at}: нет закрывающей скобки в `{value}`"))?;
    let bits = digits
        .parse::<u16>()
        .map_err(|error| format!("{at}: некорректное число бит в `{value}`: {error}"))?;
    if name.is_empty() {
        return Err(format!("{at}: пустое имя в `{value}`"));
    }
    Ok((name, Some(bits)))
}

/// `-` в столбце имени означает «имени нет».
fn dash_to_empty(token: &str) -> String {
    if token == "-" {
        String::new()
    } else {
        token.to_owned()
    }
}

/// Строит индекс «имя → код», отсортированный по имени.
///
/// Если одно имя носят две записи, в индекс попадает запись без примечания
/// (например, `connection_id` вместо `connection_id (deprecated)`); если
/// выбрать нельзя, сборка завершается ошибкой.
fn name_index<'a>(
    source: &str,
    items: impl Iterator<Item = (&'a str, &'a str, u32)>,
) -> Result<Vec<(String, u32)>, String> {
    let mut index: BTreeMap<&str, (bool, u32)> = BTreeMap::new();
    for (name, note, code) in items {
        if name.is_empty() {
            continue;
        }
        let annotated = !note.is_empty();
        match index.get(name).copied() {
            None => {
                index.insert(name, (annotated, code));
            }
            Some((true, _)) if !annotated => {
                index.insert(name, (annotated, code));
            }
            Some((false, _)) if annotated => {}
            Some((_, other)) => {
                return Err(format!(
                    "{source}: имя `{name}` носят коды {other:#06X} и {code:#06X}"
                ));
            }
        }
    }
    Ok(index
        .into_iter()
        .map(|(name, (_, code))| (name.to_owned(), code))
        .collect())
}

/// Литерал кода в сгенерированном файле.
fn code_literal(code: u32, int: &str) -> String {
    if int == "u8" {
        format!("0x{code:02X}")
    } else {
        format!("0x{code:04X}")
    }
}

fn emit_name_index(out: &mut String, table: &str, int: &str, index: &[(String, u32)]) {
    out.push_str(&format!(
        "pub(crate) static {table}: &[(&str, {int})] = &[\n"
    ));
    for (name, code) in index {
        out.push_str(&format!("    ({name:?}, {}),\n", code_literal(*code, int)));
    }
    out.push_str("];\n\n");
}

fn emit_grease(out: &mut String, table: &str, int: &str, grease: &[u32]) {
    out.push_str(&format!("pub(crate) static {table}: &[{int}] = &[\n"));
    for code in grease {
        out.push_str(&format!("    {},\n", code_literal(*code, int)));
    }
    out.push_str("];\n\n");
}

fn emit_simple(out: &mut String, spec: &RegistrySpec, registry: &Registry) -> Result<(), String> {
    let table = spec.table;
    let code_type = spec.code_type;

    out.push_str(&format!(
        "pub(crate) static {table}: &[crate::RegistryEntry<{code_type}>] = &[\n"
    ));
    for (code, row) in &registry.named {
        out.push_str(&format!(
            "    crate::RegistryEntry {{ code: {code_type}({}), name: {:?}, note: {:?}, recommended: crate::Recommended::{} }},\n",
            code_literal(*code, spec.int),
            row.name,
            row.note,
            row.recommended
        ));
    }
    out.push_str("];\n\n");

    let index = name_index(
        spec.file,
        registry
            .named
            .iter()
            .map(|(code, row)| (row.name.as_str(), row.note.as_str(), *code)),
    )?;
    emit_name_index(out, &format!("{table}_BY_NAME"), spec.int, &index);
    emit_grease(out, &format!("{table}_GREASE"), spec.int, &registry.grease);
    Ok(())
}

/// Литерал `crate::classify::CipherInfo`.
fn info_literal(row: &MappingRow) -> String {
    let kx_bits = row
        .kx_bits
        .map_or_else(|| "None".to_owned(), |bits| format!("Some({bits})"));
    format!(
        "crate::classify::CipherInfo {{ openssl_name: {:?}, mapping_name: {:?}, protocol: crate::classify::MinProtocol::{}, kx: {:?}, kx_bits: {kx_bits}, auth: {:?}, enc: {:?}, enc_bits: {}, mac: {:?}, export: {} }}",
        row.openssl_name,
        row.mapping_name,
        row.protocol,
        row.kx,
        row.auth,
        row.enc,
        row.enc_bits,
        row.mac,
        row.export
    )
}

fn emit_ciphers(out: &mut String, iana: &Registry, mapping: &CipherMapping) -> Result<(), String> {
    let mut codes: BTreeSet<u32> = iana.named.keys().copied().collect();
    codes.extend(mapping.tls.keys().copied());

    out.push_str("pub(crate) static CIPHER_SUITES: &[crate::cipher::CipherSuiteEntry] = &[\n");
    for code in &codes {
        let row = iana.named.get(code);
        let name = row.map_or("", |row| row.name.as_str());
        let note = row.map_or("", |row| row.note.as_str());
        let recommended = row.map_or("Unspecified", |row| row.recommended);
        let info = mapping.tls.get(code).map_or_else(
            || "None".to_owned(),
            |row| format!("Some({})", info_literal(row)),
        );
        out.push_str(&format!(
            "    crate::cipher::CipherSuiteEntry {{ code: crate::cipher::CipherSuite({}), iana_name: {name:?}, note: {note:?}, recommended: crate::Recommended::{recommended}, info: {info} }},\n",
            code_literal(*code, "u16")
        ));
    }
    out.push_str("];\n\n");

    let by_iana = name_index(
        CIPHER_SUITES.file,
        iana.named
            .iter()
            .map(|(code, row)| (row.name.as_str(), row.note.as_str(), *code)),
    )?;
    emit_name_index(out, "CIPHER_SUITES_BY_IANA_NAME", "u16", &by_iana);

    let by_openssl = name_index(
        CIPHER_MAPPING,
        mapping
            .tls
            .iter()
            .map(|(code, row)| (row.openssl_name.as_str(), "", *code)),
    )?;
    emit_name_index(out, "CIPHER_SUITES_BY_OPENSSL_NAME", "u16", &by_openssl);
    emit_grease(out, "CIPHER_SUITES_GREASE", "u16", &iana.grease);

    out.push_str("pub(crate) static SSLV2_CIPHERS: &[crate::sslv2::Sslv2CipherEntry] = &[\n");
    for (code, row) in &mapping.sslv2 {
        out.push_str(&format!(
            "    crate::sslv2::Sslv2CipherEntry {{ code: crate::sslv2::Sslv2CipherKind({}), info: {} }},\n",
            sslv2_literal(*code),
            info_literal(row)
        ));
    }
    out.push_str("];\n\n");

    let sslv2_by_openssl = name_index(
        CIPHER_MAPPING,
        mapping
            .sslv2
            .iter()
            .map(|(code, row)| (row.openssl_name.as_str(), "", *code)),
    )?;
    out.push_str("pub(crate) static SSLV2_CIPHERS_BY_OPENSSL_NAME: &[(&str, u32)] = &[\n");
    for (name, code) in &sslv2_by_openssl {
        out.push_str(&format!("    ({name:?}, {}),\n", sslv2_literal(*code)));
    }
    out.push_str("];\n");
    Ok(())
}

/// Литерал 24-битного кода SSLv2 с разделителем разрядов: `0x01_0080`.
fn sslv2_literal(code: u32) -> String {
    format!("0x{:02X}_{:04X}", code >> 16, code & 0xFFFF)
}
