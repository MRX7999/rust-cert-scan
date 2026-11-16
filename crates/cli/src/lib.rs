//! Command-line interface for `certscan`.
//!
//! Argument parsing, TOML profiles and `CERTSCAN_*` environment variables
//! belong here, together with wiring `engine` to an `output` writer.
//! Scanning, checks and serialization do not.
//!
//! State: Phase 0 skeleton, plus a reject-by-default argv gate (D-22).
//! Flag parsing for a real scan is task P1-25. Until then the binary does
//! not open connections, and any argument other than version or help fails.

/// What a successful argument list asks the binary to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Print `certscan <version>` and exit 0.
    Version,
    /// Print usage and exit 0.
    Help,
}

/// Rejected arguments. The binary exits with code 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageError {
    message: &'static str,
}

impl UsageError {
    /// English message printed to stderr. Not a scan result.
    #[must_use]
    pub fn message(self) -> &'static str {
        self.message
    }
}

impl std::fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

/// Usage text. The binary prints the version on the line above it.
pub const HELP: &str = "\
Usage:
  certscan
  certscan --version
  certscan --help

This build does not open connections and does not scan. Any other argument
is rejected so a target cannot look like a successful run.

Use certscan only on systems you own or are explicitly authorized to test.
Scanning other systems without permission may be illegal.

Full flag parsing is not implemented yet.
";

/// Classify argv after the program name.
///
/// No arguments, `-V`, `--version` and `version` ask for the version line.
/// `-h`, `--help` and `help` ask for [`HELP`]. Anything else is an error,
/// including a host name: this build must not look like it scanned.
#[must_use = "a rejected argument list must not be treated as a successful scan"]
pub fn classify<'a, I>(args: I) -> Result<Command, UsageError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(Command::Version);
    };
    let command = match first {
        "-h" | "--help" | "help" => Command::Help,
        "-V" | "--version" | "version" => Command::Version,
        _ => {
            return Err(UsageError {
                message: "scanning is not implemented; this build does not open connections",
            });
        }
    };
    if args.next().is_some() {
        return Err(UsageError {
            message: "too many arguments",
        });
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::{Command, classify};

    #[test]
    fn no_args_is_version() {
        assert_eq!(classify(std::iter::empty()), Ok(Command::Version));
    }

    #[test]
    fn version_flags() {
        assert_eq!(classify(["--version"]), Ok(Command::Version));
        assert_eq!(classify(["-V"]), Ok(Command::Version));
        assert_eq!(classify(["version"]), Ok(Command::Version));
    }

    #[test]
    fn help_flags() {
        assert_eq!(classify(["--help"]), Ok(Command::Help));
        assert_eq!(classify(["-h"]), Ok(Command::Help));
        assert_eq!(classify(["help"]), Ok(Command::Help));
    }

    #[test]
    fn a_target_is_rejected() {
        let error = classify(["example.com"]).expect_err("target must not succeed");
        assert!(error.message().contains("does not open connections"));
    }

    #[test]
    fn extra_arguments_are_rejected() {
        assert!(classify(["--version", "1"]).is_err());
        assert!(classify(["--help", "more"]).is_err());
    }
}
