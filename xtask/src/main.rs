//! Служебные команды разработки: `cargo xtask <подкоманда>`.
//!
//! Alias `xtask` задан в `.cargo/config.toml`. Аргументы разбираются вручную
//! на std: подкоманд мало, внешние зависимости ради них не нужны.
//!
//! Состояние: `ci`, `update-data` (P1-01, модуль `update_data`),
//! `record-fixture` (P1-04 – P1-06, модуль `record_fixture`) и `fuzz-seeds`
//! (P1-09, модуль `fuzz_seeds`) реализованы. `schema` объявлена по P0-05 и
//! завершается с ненулевым кодом, пока не выполнена задача плана, от
//! которой она зависит (P4-08).

mod fuzz_seeds;
mod record_fixture;
mod update_data;

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};

/// Код возврата при ошибке использования: неизвестная подкоманда, лишние аргументы.
const EXIT_USAGE: u8 = 2;

/// Код возврата при сбое шага или вызове ещё не реализованной подкоманды.
const EXIT_FAILURE: u8 = 1;

/// Текст справки.
const HELP: &str = "\
Служебные команды разработки certscan.

Использование: cargo xtask <подкоманда>

Подкоманды:
  ci           fmt --check, clippy -D warnings и test по всему workspace
  update-data  обновление снимков реестров IANA в crates/tls-data/data/iana и SOURCES.md
  record-fixture  запись пары фикстур с локального стенда, только loopback
                  (параметры: cargo xtask record-fixture --help)
  fuzz-seeds   начальный набор входов фаззинг-целей в fuzz/seeds из записанных фикстур
  schema       генерация JSON Schema из типов output (не реализовано, задача P4-08)
  help         эта справка

Параметры:
  -h, --help   эта справка
";

/// Шаги подкоманды `ci`: аргументы cargo в порядке запуска.
const CI_STEPS: &[&[&str]] = &[
    &["fmt", "--all", "--", "--check"],
    &[
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ],
    &["test", "--workspace"],
];

fn main() -> ExitCode {
    let mut args = env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned());

    let Some(command) = args.next() else {
        eprint!("{HELP}");
        return ExitCode::from(EXIT_USAGE);
    };
    let rest: Vec<String> = args.collect();

    match command.as_str() {
        "-h" | "--help" | "help" => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        "ci" => without_args("ci", &rest, run_ci),
        "update-data" => without_args("update-data", &rest, || update_data::run(&workspace_root())),
        "record-fixture" => record_fixture::run(&workspace_root(), &rest),
        "fuzz-seeds" => without_args("fuzz-seeds", &rest, || fuzz_seeds::run(&workspace_root())),
        "schema" => without_args("schema", &rest, || {
            not_implemented(
                "schema",
                "P4-08 (генерация JSON Schema, xtask/src/schema.rs)",
            )
        }),
        other => {
            eprintln!("xtask: неизвестная подкоманда `{other}`");
            eprintln!("Подсказка: список подкоманд — `cargo xtask --help`");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Запускает подкоманду, которая не принимает аргументов; лишние аргументы —
/// ошибка использования.
fn without_args(name: &str, rest: &[String], run: impl FnOnce() -> ExitCode) -> ExitCode {
    match rest.first() {
        Some(extra) => {
            eprintln!("xtask: подкоманда `{name}` не принимает аргументы: `{extra}`");
            eprintln!("Подсказка: список подкоманд — `cargo xtask --help`");
            ExitCode::from(EXIT_USAGE)
        }
        None => run(),
    }
}

/// Сообщает, что подкоманда объявлена, но ещё не реализована.
fn not_implemented(name: &str, task: &str) -> ExitCode {
    eprintln!("xtask: подкоманда `{name}` не реализована");
    eprintln!("Будет реализована в задаче {task}, см. docs/PLAN.md");
    ExitCode::from(EXIT_FAILURE)
}

/// Последовательно выполняет шаги `CI_STEPS`; останавливается на первом
/// неуспешном и возвращает его код.
fn run_ci() -> ExitCode {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let root = workspace_root();

    for step in CI_STEPS {
        let line = step.join(" ");
        eprintln!("xtask ci: cargo {line}");

        let status = Command::new(&cargo).args(*step).current_dir(&root).status();
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("xtask ci: шаг `cargo {line}` завершился неуспешно ({status})");
                return ExitCode::from(exit_code_of(status));
            }
            Err(error) => {
                eprintln!("xtask ci: не удалось запустить `cargo {line}`: {error}");
                return ExitCode::from(EXIT_FAILURE);
            }
        }
    }

    eprintln!("xtask ci: все шаги прошли");
    ExitCode::SUCCESS
}

/// Код возврата дочернего процесса. Завершение по сигналу и коды вне
/// диапазона `1..=255` сводятся к `EXIT_FAILURE`.
fn exit_code_of(status: ExitStatus) -> u8 {
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .filter(|code| *code != 0)
        .unwrap_or(EXIT_FAILURE)
}

/// Корень workspace: родительский каталог манифеста `xtask`.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
