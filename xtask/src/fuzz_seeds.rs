//! Подкоманда `fuzz-seeds`: начальный набор входов для фаззинг-целей.
//!
//! Источник — записанные фикстуры `crates/tls-probe/tests/fixtures/*.hex`
//! (формат — `tests/fixtures/README.md`). Результат — бинарные файлы в
//! `fuzz/seeds/<цель>/`, которые хранятся в репозитории; нарабатываемый
//! фаззером корпус лежит отдельно, в `fuzz/corpus/`, и в индекс не попадает.
//!
//! Что куда попадает:
//!
//! | Цель | Содержимое seed-файла |
//! |---|---|
//! | `record_layer` | поток записей каждой фикстуры целиком |
//! | `sslv2` | поток записей фикстур сервера (путь «ответ TLS на SSLv2 hello») |
//! | `server_message` | байт типа и тело каждого handshake-сообщения сервера |
//! | `server_hello` | тело ServerHello и HelloRetryRequest |
//! | `certificate` | тело Certificate |
//! | `server_kx` | тело ServerKeyExchange |
//! | `client_hello` | тело ClientHello из фикстур клиента |
//!
//! Handshake-сообщения извлекает `tls_probe::Decoder`. Записей SSLv2 среди
//! seed-файлов нет: стенд SSLv2 не поддерживает, а синтетические байты за
//! записанные не выдаются.
//!
//! Команда детерминирована: фикстуры обрабатываются в порядке имён, файлы
//! `*.bin`, которых нет в новом наборе, удаляются. Запись группы файлов не
//! атомарна: при сбое посреди записи команду нужно повторить.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tls_probe::{Decoder, Event, HandshakeType};

/// Каталог фикстур относительно корня workspace.
const FIXTURES_DIR: &str = "crates/tls-probe/tests/fixtures";

/// Каталог seed-файлов относительно корня workspace.
const SEEDS_DIR: &str = "fuzz/seeds";

/// Цели, для которых создаются seed-файлы; имена совпадают с именами
/// бинарных целей в `fuzz/Cargo.toml`.
const TARGETS: [&str; 7] = [
    "record_layer",
    "sslv2",
    "server_message",
    "server_hello",
    "certificate",
    "server_kx",
    "client_hello",
];

/// Код возврата при сбое.
const EXIT_FAILURE: u8 = 1;

/// Один seed-файл.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seed {
    /// Имя цели (подкаталог в `fuzz/seeds/`).
    target: &'static str,
    /// Имя файла.
    file_name: String,
    /// Содержимое.
    bytes: Vec<u8>,
}

/// Точка входа подкоманды.
pub fn run(root: &Path) -> ExitCode {
    match generate(root) {
        Ok(seeds) => {
            for target in TARGETS {
                let count = seeds.iter().filter(|seed| seed.target == target).count();
                eprintln!("xtask fuzz-seeds: {SEEDS_DIR}/{target}: файлов: {count}");
            }
            eprintln!("xtask fuzz-seeds: всего файлов: {}", seeds.len());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("xtask fuzz-seeds: {message}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// Собирает набор из фикстур и записывает его на диск.
fn generate(root: &Path) -> Result<Vec<Seed>, String> {
    let seeds = collect(&root.join(FIXTURES_DIR))?;
    let seeds_dir = root.join(SEEDS_DIR);
    for target in TARGETS {
        let dir = seeds_dir.join(target);
        fs::create_dir_all(&dir)
            .map_err(|error| format!("не удалось создать {}: {error}", dir.display()))?;
        for stale in bin_files(&dir)? {
            fs::remove_file(&stale)
                .map_err(|error| format!("не удалось удалить {}: {error}", stale.display()))?;
        }
    }
    for seed in &seeds {
        let path = seeds_dir.join(seed.target).join(&seed.file_name);
        fs::write(&path, &seed.bytes)
            .map_err(|error| format!("не удалось записать {}: {error}", path.display()))?;
    }
    Ok(seeds)
}

/// Файлы `*.bin` каталога.
fn bin_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = fs::read_dir(dir)
        .map_err(|error| format!("не удалось прочитать {}: {error}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("не удалось прочитать {}: {error}", dir.display()))?
            .path();
        if path.extension().is_some_and(|extension| extension == "bin") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Строит набор seed-файлов по каталогу фикстур, ничего не записывая.
fn collect(fixtures: &Path) -> Result<Vec<Seed>, String> {
    let entries = fs::read_dir(fixtures)
        .map_err(|error| format!("не удалось прочитать {}: {error}", fixtures.display()))?;
    let mut names = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("не удалось прочитать {}: {error}", fixtures.display()))?
            .path();
        if path.extension().is_some_and(|extension| extension == "hex")
            && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
        {
            names.push(stem.to_owned());
        }
    }
    names.sort();

    let mut seeds = Vec::new();
    for name in &names {
        let hex = read_text(&fixtures.join(format!("{name}.hex")))?;
        let meta = read_text(&fixtures.join(format!("{name}.meta.toml")))?;
        let bytes = parse_hex(&hex).map_err(|error| format!("{name}.hex: {error}"))?;
        let direction = meta_direction(&meta)
            .ok_or_else(|| format!("{name}.meta.toml: нет ключа direction"))?;
        let messages = handshake_messages(&bytes)
            .map_err(|error| format!("{name}.hex: поток не разобран декодером: {error}"))?;

        seeds.push(Seed {
            target: "record_layer",
            file_name: format!("{name}.bin"),
            bytes: bytes.clone(),
        });
        match direction {
            "server" => {
                seeds.push(Seed {
                    target: "sslv2",
                    file_name: format!("{name}.bin"),
                    bytes,
                });
                for (index, (msg_type, body)) in messages.iter().enumerate() {
                    let file_name = format!("{name}-{index:02}.bin");
                    let mut typed = vec![msg_type.0];
                    typed.extend_from_slice(body);
                    seeds.push(Seed {
                        target: "server_message",
                        file_name: file_name.clone(),
                        bytes: typed,
                    });
                    let target = match *msg_type {
                        HandshakeType::SERVER_HELLO => "server_hello",
                        HandshakeType::CERTIFICATE => "certificate",
                        HandshakeType::SERVER_KEY_EXCHANGE => "server_kx",
                        _ => continue,
                    };
                    seeds.push(Seed {
                        target,
                        file_name,
                        bytes: body.clone(),
                    });
                }
            }
            "client" => {
                for (index, (msg_type, body)) in messages.iter().enumerate() {
                    if *msg_type == HandshakeType::CLIENT_HELLO {
                        seeds.push(Seed {
                            target: "client_hello",
                            file_name: format!("{name}-{index:02}.bin"),
                            bytes: body.clone(),
                        });
                    }
                }
            }
            other => {
                return Err(format!(
                    "{name}.meta.toml: неизвестное значение direction: `{other}`"
                ));
            }
        }
    }
    Ok(seeds)
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path)
        .map_err(|error| format!("не удалось прочитать {}: {error}", path.display()))
}

/// Байты из текста `.hex`: строки, начинающиеся с `#`, — комментарии;
/// остальное — пары шестнадцатеричных цифр через пробельные символы.
fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|pair| {
            if pair.len() == 2 {
                u8::from_str_radix(pair, 16).map_err(|_| format!("не hex-байт: `{pair}`"))
            } else {
                Err(format!("не hex-байт: `{pair}`"))
            }
        })
        .collect()
}

/// Значение ключа `direction` до первой секции метаданных.
fn meta_direction(meta: &str) -> Option<&str> {
    meta.lines()
        .take_while(|line| !line.starts_with('['))
        .find_map(|line| line.strip_prefix("direction = "))
        .map(|value| value.trim().trim_matches('"'))
}

/// Handshake-сообщения потока: тип и тело.
fn handshake_messages(stream: &[u8]) -> Result<Vec<(HandshakeType, Vec<u8>)>, String> {
    let mut decoder = Decoder::default();
    let mut input = stream;
    let mut messages = Vec::new();
    loop {
        match decoder.feed(&mut input) {
            Ok(Event::NeedMore) => return Ok(messages),
            Ok(Event::Handshake(message)) => {
                messages.push((message.msg_type, message.body.to_vec()));
            }
            Ok(_) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf()
    }

    #[test]
    fn hex_comments_and_errors() {
        assert_eq!(
            parse_hex("# комментарий\n16 03 01\n\n00 ff\n"),
            Ok(vec![0x16, 0x03, 0x01, 0x00, 0xFF])
        );
        assert_eq!(parse_hex(""), Ok(Vec::new()));
        assert!(parse_hex("16 0").is_err());
        assert!(parse_hex("zz").is_err());
        assert!(parse_hex("160301").is_err());
    }

    #[test]
    fn direction_is_read_before_first_section() {
        assert_eq!(
            meta_direction("format = 1\ndirection = \"server\"\n[source]\n"),
            Some("server")
        );
        assert_eq!(
            meta_direction("format = 1\n[source]\ndirection = \"client\"\n"),
            None
        );
    }

    #[test]
    fn every_target_gets_seeds_from_fixtures() {
        let seeds = collect(&root().join(FIXTURES_DIR)).unwrap();
        for target in TARGETS {
            assert!(
                seeds.iter().any(|seed| seed.target == target),
                "нет seed-файлов для цели {target}"
            );
        }
        assert!(seeds.iter().all(|seed| !seed.bytes.is_empty()));
    }

    /// Каталог `fuzz/seeds/` в репозитории соответствует фикстурам: после
    /// изменения фикстур нужно выполнить `cargo xtask fuzz-seeds`.
    #[test]
    fn seeds_on_disk_match_fixtures() {
        let root = root();
        let seeds = collect(&root.join(FIXTURES_DIR)).unwrap();
        for target in TARGETS {
            let dir = root.join(SEEDS_DIR).join(target);
            let mut expected: Vec<PathBuf> = seeds
                .iter()
                .filter(|seed| seed.target == target)
                .map(|seed| dir.join(&seed.file_name))
                .collect();
            expected.sort();
            assert_eq!(bin_files(&dir).unwrap(), expected, "цель {target}");
        }
        for seed in &seeds {
            let path = root.join(SEEDS_DIR).join(seed.target).join(&seed.file_name);
            assert_eq!(fs::read(&path).unwrap(), seed.bytes, "{}", path.display());
        }
    }
}
