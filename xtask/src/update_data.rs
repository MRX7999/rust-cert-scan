//! Подкоманда `update-data`: обновление снимков реестров IANA для `tls-data`.
//!
//! Что делает:
//!
//! 1. скачивает каждый реестр из [`SNAPSHOTS`] системным `curl` во временный
//!    файл `<имя>.part` рядом со снимком;
//! 2. проверяет, что получен CSV с ожидаемым заголовком, а не страница ошибки;
//! 3. только если все загрузки успешны, заменяет снимки в
//!    `crates/tls-data/data/iana/`;
//! 4. пересчитывает sha256 (`shasum -a 256`, запасной вариант — `sha256sum`),
//!    размер и число строк, читает дату «Last Updated» с индексной страницы
//!    группы реестров;
//! 5. перезаписывает блок между маркерами в `crates/tls-data/data/SOURCES.md`.
//!
//! Файлы testssl.sh команда не трогает: они привязаны к конкретному коммиту и
//! обновляются вручную вместе с записью в `SOURCES.md`.
//!
//! Сеть используется только здесь; `build.rs` крейта `tls-data` читает
//! локальные снимки. Внешних зависимостей нет: `curl`, `shasum` и `date`
//! вызываются через `std::process::Command`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// Каталог данных `tls-data` относительно корня workspace.
const DATA_DIR: &str = "crates/tls-data/data";

/// Начало блока IANA в `SOURCES.md`.
const BEGIN_MARKER: &str = "<!-- iana:begin (блок перезаписывает cargo xtask update-data) -->";

/// Конец блока IANA в `SOURCES.md`.
const END_MARKER: &str = "<!-- iana:end -->";

/// Индексная страница группы реестров «TLS Parameters».
const TLS_PARAMETERS: &str = "https://www.iana.org/assignments/tls-parameters/";

/// Индексная страница группы реестров «TLS Extensions».
const TLS_EXTENSIONS: &str = "https://www.iana.org/assignments/tls-extensiontype-values/";

/// Снимок одного реестра.
struct Snapshot {
    /// Имя файла в `data/iana/` и на сервере IANA.
    file: &'static str,
    /// Название реестра.
    registry: &'static str,
    /// Индексная страница группы реестров; URL файла — страница плюс имя.
    index: &'static str,
}

/// Реестры, из которых `tls-data` генерирует таблицы.
const SNAPSHOTS: &[Snapshot] = &[
    Snapshot {
        file: "tls-parameters-4.csv",
        registry: "TLS Cipher Suites",
        index: TLS_PARAMETERS,
    },
    Snapshot {
        file: "tls-parameters-6.csv",
        registry: "TLS Alerts",
        index: TLS_PARAMETERS,
    },
    Snapshot {
        file: "tls-parameters-8.csv",
        registry: "TLS Supported Groups",
        index: TLS_PARAMETERS,
    },
    Snapshot {
        file: "tls-signaturescheme.csv",
        registry: "TLS SignatureScheme",
        index: TLS_PARAMETERS,
    },
    Snapshot {
        file: "tls-extensiontype-values-1.csv",
        registry: "TLS ExtensionType Values",
        index: TLS_EXTENSIONS,
    },
];

/// Запускает обновление; печатает ход работы и ошибки в stderr.
pub fn run(root: &Path) -> ExitCode {
    match update(root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask update-data: {message}");
            ExitCode::FAILURE
        }
    }
}

fn update(root: &Path) -> Result<(), String> {
    let data_dir = root.join(DATA_DIR);
    let iana_dir = data_dir.join("iana");
    let sources = data_dir.join("SOURCES.md");

    // Проверка до загрузок: без маркеров результат некуда записать.
    let sources_text = read_text(&sources)?;
    split_at_markers(&sources_text, &sources)?;

    fs::create_dir_all(&iana_dir).map_err(|error| format!("{}: {error}", iana_dir.display()))?;

    let mut parts: Vec<PathBuf> = Vec::new();
    for snapshot in SNAPSHOTS {
        let url = snapshot.url();
        let part = iana_dir.join(format!("{}.part", snapshot.file));
        eprintln!("xtask update-data: загрузка {url}");
        let result = download(&url, &part).and_then(|()| validate_csv(&part));
        parts.push(part);
        if let Err(error) = result {
            remove_all(&parts);
            return Err(format!(
                "{error}; существующие снимки и SOURCES.md не изменены"
            ));
        }
    }

    let date = today_utc()?;
    let mut rows = Vec::new();
    for (snapshot, part) in SNAPSHOTS.iter().zip(&parts) {
        let target = iana_dir.join(snapshot.file);
        let changed = fs::read(&target).ok() != fs::read(part).ok();
        fs::rename(part, &target).map_err(|error| format!("{}: {error}", target.display()))?;
        eprintln!(
            "xtask update-data: {} — {}",
            snapshot.file,
            if changed {
                "обновлён"
            } else {
                "без изменений"
            }
        );

        let bytes = fs::read(&target).map_err(|error| format!("{}: {error}", target.display()))?;
        let lines = bytes.iter().filter(|byte| **byte == b'\n').count();
        rows.push(format!(
            "| `iana/{}` | {} | <{}> | {date} | `{}` | {} | {lines} | {} |",
            snapshot.file,
            snapshot.registry,
            snapshot.url(),
            sha256(&target)?,
            bytes.len(),
            last_updated(snapshot.index)
        ));
    }

    let block = format!(
        "{BEGIN_MARKER}\n\
         | Файл | Реестр | URL | Дата загрузки (UTC) | sha256 | Размер, байт | Строк | Last Updated |\n\
         |---|---|---|---|---|---|---|---|\n\
         {}\n\
         {END_MARKER}",
        rows.join("\n")
    );
    let (before, after) = split_at_markers(&sources_text, &sources)?;
    fs::write(&sources, format!("{before}{block}{after}"))
        .map_err(|error| format!("{}: {error}", sources.display()))?;

    eprintln!(
        "xtask update-data: готово, обновлён {}; проверьте `git diff` и запустите `cargo test -p tls-data`",
        sources.display()
    );
    Ok(())
}

impl Snapshot {
    fn url(&self) -> String {
        format!("{}{}", self.index, self.file)
    }
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Делит текст `SOURCES.md` на часть до блока IANA и часть после него.
fn split_at_markers<'a>(text: &'a str, path: &Path) -> Result<(&'a str, &'a str), String> {
    let missing = |marker: &str| format!("{}: не найден маркер `{marker}`", path.display());
    let (before, tail) = text
        .split_once(BEGIN_MARKER)
        .ok_or_else(|| missing(BEGIN_MARKER))?;
    let (_, after) = tail
        .split_once(END_MARKER)
        .ok_or_else(|| missing(END_MARKER))?;
    Ok((before, after))
}

/// Запускает внешнюю программу и возвращает её stdout.
fn run_tool(program: &str, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("не удалось запустить `{program}`: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{program} {}` завершился неуспешно ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn download(url: &str, dest: &Path) -> Result<(), String> {
    let dest = dest.to_string_lossy();
    run_tool(
        "curl",
        &[
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "120",
            "--output",
            &dest,
            url,
        ],
    )
    .map(|_| ())
}

/// Проверяет, что скачанный файл похож на CSV реестра, а не на страницу ошибки.
fn validate_csv(path: &Path) -> Result<(), String> {
    let text = read_text(path)?;
    let header = text.lines().next().unwrap_or("");
    if !header.starts_with("Value,") {
        return Err(format!(
            "{}: первая строка не похожа на заголовок реестра: `{}`",
            path.display(),
            header.chars().take(80).collect::<String>()
        ));
    }
    if text.lines().count() < 2 {
        return Err(format!("{}: в файле нет записей", path.display()));
    }
    Ok(())
}

fn remove_all(paths: &[PathBuf]) {
    for path in paths {
        // Временного файла может не быть, если загрузка не началась.
        let _ = fs::remove_file(path);
    }
}

fn sha256(path: &Path) -> Result<String, String> {
    let name = path.to_string_lossy();
    let output = run_tool("shasum", &["-a", "256", &name]).or_else(|first| {
        run_tool("sha256sum", &[&name]).map_err(|second| format!("{first}; {second}"))
    })?;
    let text = String::from_utf8_lossy(&output);
    let digest = text.split_whitespace().next().unwrap_or("");
    if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(digest.to_owned())
    } else {
        Err(format!(
            "{}: неожиданный вывод программы подсчёта sha256: `{}`",
            path.display(),
            text.trim()
        ))
    }
}

fn today_utc() -> Result<String, String> {
    let output = run_tool("date", &["-u", "+%Y-%m-%d"])?;
    let text = String::from_utf8_lossy(&output).trim().to_owned();
    if is_date(&text) {
        Ok(text)
    } else {
        Err(format!("неожиданный вывод `date`: `{text}`"))
    }
}

/// Дата «Last Updated» с индексной страницы группы реестров. В самих CSV её
/// нет; если страницу не удалось получить или разобрать, возвращается пометка.
fn last_updated(index: &str) -> String {
    run_tool(
        "curl",
        &[
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "120",
            index,
        ],
    )
    .ok()
    .and_then(|body| find_last_updated(&String::from_utf8_lossy(&body)))
    .unwrap_or_else(|| "не определена".to_owned())
}

/// Ищет первую дату `ГГГГ-ММ-ДД` после слов «Last Updated».
fn find_last_updated(html: &str) -> Option<String> {
    let (_, tail) = html.split_once("Last Updated")?;
    tail.char_indices().take(400).find_map(|(start, _)| {
        let candidate = tail.get(start..start.checked_add(10)?)?;
        is_date(candidate).then(|| candidate.to_owned())
    })
}

fn is_date(text: &str) -> bool {
    text.len() == 10
        && text.bytes().enumerate().all(|(index, byte)| {
            if index == 4 || index == 7 {
                byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_date_after_last_updated() {
        let html = "<dt>Created</dt><dd>2005-08-23</dd><dt>Last Updated</dt><dd>2026-11-05</dd>";
        assert_eq!(find_last_updated(html).as_deref(), Some("2026-11-05"));
        assert_eq!(
            find_last_updated("<dt>Created</dt><dd>2005-08-23</dd>"),
            None
        );
        assert_eq!(find_last_updated("Last Updated: скоро"), None);
    }

    #[test]
    fn date_shape() {
        assert!(is_date("2026-11-11"));
        assert!(!is_date("2026-11-1"));
        assert!(!is_date("2026/11/11"));
        assert!(!is_date("20261111--"));
    }

    #[test]
    fn markers_split_sources() {
        let path = Path::new("SOURCES.md");
        let text = format!("до\n{BEGIN_MARKER}\nстарая таблица\n{END_MARKER}\nпосле\n");
        assert_eq!(split_at_markers(&text, path), Ok(("до\n", "\nпосле\n")));
        assert!(split_at_markers("без маркеров", path).is_err());
        assert!(split_at_markers(&format!("{BEGIN_MARKER} без конца"), path).is_err());
    }

    #[test]
    fn snapshot_urls_point_to_iana() {
        for snapshot in SNAPSHOTS {
            let url = snapshot.url();
            assert!(url.starts_with("https://www.iana.org/assignments/"));
            assert!(url.ends_with(snapshot.file));
            assert!(snapshot.file.ends_with(".csv"));
        }
    }
}
