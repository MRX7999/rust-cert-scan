//! `certscan` binary.
//!
//! Phase 0 prints the version or help and exits. A target name is rejected
//! with code 2 so a published binary cannot look like a successful scan.
//! Argument parsing for a real scan is task P1-25.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cli::classify(args.iter().map(String::as_str)) {
        Ok(cli::Command::Version) => {
            println!("certscan {}", env!("CARGO_PKG_VERSION"));
            std::process::ExitCode::SUCCESS
        }
        Ok(cli::Command::Help) => {
            println!("certscan {}", env!("CARGO_PKG_VERSION"));
            print!("{}", cli::HELP);
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("certscan: {error}");
            eprintln!("run `certscan --help` for usage");
            std::process::ExitCode::from(2)
        }
    }
}
