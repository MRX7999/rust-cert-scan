//! Разбор одной цели.
//!
//! # Формы записи
//!
//! | Запись | Результат |
//! |---|---|
//! | `example.com` | имя, порт по умолчанию |
//! | `example.com:8443` | имя и порт |
//! | `192.0.2.1`, `192.0.2.1:8443` | IPv4 |
//! | `[2001:db8::1]`, `[2001:db8::1]:8443` | IPv6 |
//! | `2001:db8::1` | IPv6 без скобок, порт по умолчанию |
//! | `https://example.com:8443/path?q` | имя, порт, путь с запросом |
//! | `192.0.2.0/24`, `192.0.2.0/24:8443` | сеть IPv4 |
//! | `2001:db8::/120`, `[2001:db8::]/120:8443` | сеть IPv6 |
//!
//! Правила:
//!
//! - порт по умолчанию задаёт вызывающий (обычно [`DEFAULT_PORT`]); порт —
//!   десятичное число от 1 до 65535;
//! - схема URL — только `https`; путь и строка запроса сохраняются для
//!   HTTP-проверок, фрагмент отбрасывается, данные пользователя
//!   (`user@host`) отклоняются;
//! - имя — ASCII: буквы, цифры, дефис и подчёркивание в метках до 63
//!   символов, всё имя до 253 символов; завершающая точка отбрасывается.
//!   Punycode (`xn--…`) принимается как есть. Имена не в ASCII отклоняются:
//!   преобразование IDNA планом не предусмотрено, а молча отправлять такие
//!   имена в DNS и SNI нельзя;
//! - имя, последняя метка которого состоит из цифр (`256.1.1.1`, `10.0.0`),
//!   отклоняется как некорректный адрес: это опечатка в IPv4, а не имя.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::cidr::Cidr;

/// Порт по умолчанию.
pub const DEFAULT_PORT: u16 = 443;

/// Наибольшая длина имени хоста.
const MAX_NAME_LEN: usize = 253;
/// Наибольшая длина метки имени.
const MAX_LABEL_LEN: usize = 63;
/// Наибольшее число цифр в номере порта.
const MAX_PORT_DIGITS: usize = 5;

/// Хост цели: имя либо адрес.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetHost {
    /// Имя хоста: ASCII, без завершающей точки.
    Name(String),
    /// IP-адрес.
    Ip(IpAddr),
}

impl fmt::Display for TargetHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name),
            Self::Ip(addr) => write!(f, "{addr}"),
        }
    }
}

/// Цель сканирования.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScanTarget {
    /// Имя или адрес.
    pub host: TargetHost,
    /// TCP-порт.
    pub port: u16,
    /// Имя для SNI вместо имени цели (`--sni`).
    pub sni: Option<String>,
    /// Адрес, с которым соединяться, не разрешая имя (`--ip`).
    pub ip_override: Option<IpAddr>,
    /// Путь и строка запроса из URL — для HTTP-проверок.
    pub path: Option<String>,
}

impl ScanTarget {
    /// Цель без переопределений и пути.
    #[must_use]
    pub fn new(host: TargetHost, port: u16) -> Self {
        Self {
            host,
            port,
            sni: None,
            ip_override: None,
            path: None,
        }
    }

    /// Имя для SNI: заданное через `--sni`, иначе имя цели; `None` для
    /// цели-адреса без `--sni` (RFC 6066: литералы в SNI не передаются).
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        match (&self.sni, &self.host) {
            (Some(sni), _) => Some(sni),
            (None, TargetHost::Name(name)) => Some(name),
            (None, TargetHost::Ip(_)) => None,
        }
    }

    /// Адрес соединения, известный без резолва: `--ip` либо адрес цели.
    #[must_use]
    pub fn connect_ip(&self) -> Option<IpAddr> {
        self.ip_override.or(match &self.host {
            TargetHost::Ip(addr) => Some(*addr),
            TargetHost::Name(_) => None,
        })
    }

    /// Цель для [`net::Connector`]: имя или IP-литерал и порт.
    /// Переопределения в неё не входят: адрес `--ip` передаётся через
    /// [`ScanTarget::resolve_options`], имя `--sni` берёт построитель
    /// ClientHello из [`ScanTarget::server_name`].
    #[must_use]
    pub fn to_net(&self) -> net::Target {
        net::Target::new(self.host.to_string(), self.port)
    }

    /// Параметры резолва с учётом `--ip` этой цели; остальное — из `base`.
    #[must_use]
    pub fn resolve_options(&self, base: net::ResolveOptions) -> net::ResolveOptions {
        net::ResolveOptions {
            ip_override: self.ip_override.or(base.ip_override),
            ..base
        }
    }
}

impl fmt::Display for ScanTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_net())?;
        if let Some(path) = &self.path {
            f.write_str(path)?;
        }
        Ok(())
    }
}

/// Результат разбора записи: одна цель либо сеть.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSpec {
    /// Одна цель.
    Single(ScanTarget),
    /// Сеть: цель — каждый её адрес.
    Network {
        /// Сеть.
        cidr: Cidr,
        /// Порт для всех адресов сети.
        port: u16,
    },
}

/// Вид ошибки разбора цели.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetErrorKind {
    /// Пустая запись.
    Empty,
    /// Пробел или управляющий символ внутри записи.
    InvalidCharacter,
    /// Схема URL не `https`.
    UnsupportedScheme,
    /// Данные пользователя в URL (`user@host`).
    UserInfo,
    /// Нет закрывающей скобки после адреса IPv6.
    UnclosedBracket,
    /// Порт — не число от 1 до 65535.
    InvalidPort,
    /// Некорректный IP-адрес.
    InvalidAddress,
    /// Некорректное имя хоста.
    InvalidName,
    /// Имя длиннее 253 символов.
    NameTooLong,
    /// Имя не в ASCII: IDNA не поддерживается, нужен punycode.
    NonAsciiName,
    /// Некорректная длина префикса сети.
    InvalidPrefix,
    /// Сеть больше допустимого предела.
    NetworkTooLarge {
        /// Число бит хоста: в сети 2 в этой степени адресов.
        host_bits: u32,
        /// Действующий предел числа адресов.
        limit: u64,
    },
}

impl fmt::Display for TargetErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("пустая запись"),
            Self::InvalidCharacter => f.write_str("пробел или управляющий символ в записи"),
            Self::UnsupportedScheme => f.write_str("поддерживается только схема https"),
            Self::UserInfo => f.write_str("данные пользователя в URL не поддерживаются"),
            Self::UnclosedBracket => f.write_str("нет закрывающей скобки после адреса IPv6"),
            Self::InvalidPort => f.write_str("порт должен быть числом от 1 до 65535"),
            Self::InvalidAddress => f.write_str("некорректный IP-адрес"),
            Self::InvalidName => f.write_str("некорректное имя хоста"),
            Self::NameTooLong => f.write_str("имя хоста длиннее 253 символов"),
            Self::NonAsciiName => f.write_str(
                "имя не в ASCII: IDNA не поддерживается, укажите имя в punycode (xn--…)",
            ),
            Self::InvalidPrefix => f.write_str("некорректная длина префикса сети"),
            Self::NetworkTooLarge { host_bits, limit } => {
                write!(f, "в сети 2^{host_bits} адресов, предел — {limit}")
            }
        }
    }
}

/// Ошибка разбора цели: исходная запись и вид ошибки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetError {
    /// Исходная запись без изменений.
    pub input: String,
    /// Вид ошибки.
    pub kind: TargetErrorKind,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "некорректная цель «{}»: {}", self.input, self.kind)
    }
}

impl std::error::Error for TargetError {}

/// Разбирает запись цели; формы — в документации модуля.
///
/// # Errors
///
/// [`TargetError`] с исходной записью и видом ошибки.
pub fn parse_target(input: &str, default_port: u16) -> Result<TargetSpec, TargetError> {
    parse_trimmed(input.trim(), default_port).map_err(|kind| TargetError {
        input: input.to_owned(),
        kind,
    })
}

fn parse_trimmed(text: &str, default_port: u16) -> Result<TargetSpec, TargetErrorKind> {
    if text.is_empty() {
        return Err(TargetErrorKind::Empty);
    }
    if text
        .chars()
        .any(|symbol| symbol.is_whitespace() || symbol.is_control())
    {
        return Err(TargetErrorKind::InvalidCharacter);
    }
    if let Some((scheme, rest)) = text.split_once("://") {
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(TargetErrorKind::UnsupportedScheme);
        }
        return parse_url_rest(rest, default_port).map(TargetSpec::Single);
    }
    if let Some((addr, tail)) = text.split_once('/') {
        return parse_network(addr, tail, default_port);
    }
    let (host, port) = parse_authority(text, default_port)?;
    Ok(TargetSpec::Single(ScanTarget::new(host, port)))
}

/// Часть URL после `https://`: адресная часть, путь, запрос, фрагмент.
fn parse_url_rest(rest: &str, default_port: u16) -> Result<ScanTarget, TargetErrorKind> {
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(end) => rest.split_at_checked(end).unwrap_or((rest, "")),
        None => (rest, ""),
    };
    let (host, port) = parse_authority(authority, default_port)?;
    let without_fragment = tail.split_once('#').map_or(tail, |(before, _)| before);
    let path = if without_fragment.is_empty() {
        None
    } else if without_fragment.starts_with('/') {
        Some(without_fragment.to_owned())
    } else {
        // Запрос без пути: `https://host?q`.
        Some(format!("/{without_fragment}"))
    };
    Ok(ScanTarget {
        path,
        ..ScanTarget::new(host, port)
    })
}

/// Сеть: адрес (в скобках или без), длина префикса и необязательный порт.
fn parse_network(addr: &str, tail: &str, default_port: u16) -> Result<TargetSpec, TargetErrorKind> {
    let bare = match addr.strip_prefix('[') {
        Some(inner) => inner
            .strip_suffix(']')
            .ok_or(TargetErrorKind::UnclosedBracket)?,
        None => addr,
    };
    let addr: IpAddr = bare.parse().map_err(|_| TargetErrorKind::InvalidAddress)?;
    let (prefix, port) = match tail.split_once(':') {
        Some((prefix, port)) => (prefix, parse_port(port)?),
        None => (tail, default_port),
    };
    let digits = !prefix.is_empty() && prefix.bytes().all(|byte| byte.is_ascii_digit());
    if !digits {
        return Err(TargetErrorKind::InvalidPrefix);
    }
    let prefix: u8 = prefix.parse().map_err(|_| TargetErrorKind::InvalidPrefix)?;
    let cidr = Cidr::new(addr, prefix).ok_or(TargetErrorKind::InvalidPrefix)?;
    Ok(TargetSpec::Network { cidr, port })
}

/// Адресная часть: имя или адрес и необязательный порт.
fn parse_authority(text: &str, default_port: u16) -> Result<(TargetHost, u16), TargetErrorKind> {
    if text.contains('@') {
        return Err(TargetErrorKind::UserInfo);
    }
    if let Some(rest) = text.strip_prefix('[') {
        let (inside, after) = rest
            .split_once(']')
            .ok_or(TargetErrorKind::UnclosedBracket)?;
        let addr: Ipv6Addr = inside
            .parse()
            .map_err(|_| TargetErrorKind::InvalidAddress)?;
        let port = if after.is_empty() {
            default_port
        } else {
            parse_port(
                after
                    .strip_prefix(':')
                    .ok_or(TargetErrorKind::InvalidPort)?,
            )?
        };
        return Ok((TargetHost::Ip(IpAddr::V6(addr)), port));
    }
    if text.matches(':').count() >= 2 {
        // IPv6 без скобок: порт в такой записи указать нельзя.
        let addr: Ipv6Addr = text.parse().map_err(|_| TargetErrorKind::InvalidAddress)?;
        return Ok((TargetHost::Ip(IpAddr::V6(addr)), default_port));
    }
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => (host, parse_port(port)?),
        None => (text, default_port),
    };
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        return Ok((TargetHost::Ip(IpAddr::V4(addr)), port));
    }
    Ok((TargetHost::Name(validate_name(host)?), port))
}

fn parse_port(text: &str) -> Result<u16, TargetErrorKind> {
    let digits = !text.is_empty()
        && text.len() <= MAX_PORT_DIGITS
        && text.bytes().all(|byte| byte.is_ascii_digit());
    if !digits {
        return Err(TargetErrorKind::InvalidPort);
    }
    match text.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(TargetErrorKind::InvalidPort),
    }
}

fn validate_name(host: &str) -> Result<String, TargetErrorKind> {
    if !host.is_ascii() {
        return Err(TargetErrorKind::NonAsciiName);
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() {
        return Err(TargetErrorKind::InvalidName);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(TargetErrorKind::NameTooLong);
    }
    let valid_label = |label: &str| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    if !name.split('.').all(valid_label) {
        return Err(TargetErrorKind::InvalidName);
    }
    let numeric_tail = name
        .rsplit('.')
        .next()
        .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()));
    if numeric_tail {
        return Err(TargetErrorKind::InvalidAddress);
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(input: &str) -> ScanTarget {
        match parse_target(input, DEFAULT_PORT) {
            Ok(TargetSpec::Single(target)) => target,
            other => panic!("{input}: {other:?}"),
        }
    }

    fn network(input: &str) -> (Cidr, u16) {
        match parse_target(input, DEFAULT_PORT) {
            Ok(TargetSpec::Network { cidr, port }) => (cidr, port),
            other => panic!("{input}: {other:?}"),
        }
    }

    fn kind(input: &str) -> TargetErrorKind {
        let error = parse_target(input, DEFAULT_PORT).unwrap_err();
        assert_eq!(error.input, input);
        error.kind
    }

    fn name(text: &str) -> TargetHost {
        TargetHost::Name(text.to_owned())
    }

    fn ip(text: &str) -> TargetHost {
        TargetHost::Ip(text.parse().unwrap())
    }

    #[test]
    fn name_with_and_without_port() {
        assert_eq!(
            single("example.com"),
            ScanTarget::new(name("example.com"), 443)
        );
        assert_eq!(
            single("example.com:8443"),
            ScanTarget::new(name("example.com"), 8443)
        );
        assert_eq!(single("localhost"), ScanTarget::new(name("localhost"), 443));
        assert_eq!(
            single("  example.com:1 \t"),
            ScanTarget::new(name("example.com"), 1)
        );
        assert_eq!(
            single("example.com:65535"),
            ScanTarget::new(name("example.com"), 65535)
        );
    }

    #[test]
    fn name_details() {
        // Завершающая точка отбрасывается, регистр сохраняется.
        assert_eq!(single("Example.COM.").host, name("Example.COM"));
        // Punycode и подчёркивание принимаются как есть.
        assert_eq!(
            single("xn--e1afmkfd.xn--p1ai").host,
            name("xn--e1afmkfd.xn--p1ai")
        );
        assert_eq!(
            single("_dmarc.example.com").host,
            name("_dmarc.example.com")
        );
        assert_eq!(single("a-b.example").host, name("a-b.example"));
    }

    #[test]
    fn ipv4_with_and_without_port() {
        assert_eq!(single("192.0.2.1"), ScanTarget::new(ip("192.0.2.1"), 443));
        assert_eq!(
            single("192.0.2.1:8443"),
            ScanTarget::new(ip("192.0.2.1"), 8443)
        );
    }

    #[test]
    fn ipv6_in_brackets_and_bare() {
        assert_eq!(
            single("[2001:db8::1]"),
            ScanTarget::new(ip("2001:db8::1"), 443)
        );
        assert_eq!(
            single("[2001:db8::1]:8443"),
            ScanTarget::new(ip("2001:db8::1"), 8443)
        );
        assert_eq!(
            single("2001:db8::1"),
            ScanTarget::new(ip("2001:db8::1"), 443)
        );
        assert_eq!(single("::1"), ScanTarget::new(ip("::1"), 443));
    }

    #[test]
    fn url_keeps_path_and_query() {
        let target = single("https://example.com:8443/a/b?q=1#frag");
        assert_eq!(target.host, name("example.com"));
        assert_eq!(target.port, 8443);
        assert_eq!(target.path.as_deref(), Some("/a/b?q=1"));

        assert_eq!(single("https://example.com").path, None);
        assert_eq!(single("https://example.com/").path.as_deref(), Some("/"));
        assert_eq!(
            single("https://example.com?q=1").path.as_deref(),
            Some("/?q=1")
        );
        assert_eq!(single("https://example.com#top").path, None);
        assert_eq!(single("HTTPS://example.com").port, 443);

        let v6 = single("https://[2001:db8::1]:8443/x");
        assert_eq!(v6.host, ip("2001:db8::1"));
        assert_eq!(v6.port, 8443);
        assert_eq!(v6.path.as_deref(), Some("/x"));

        let v4 = single("https://192.0.2.1/");
        assert_eq!(v4.host, ip("192.0.2.1"));
        assert_eq!(v4.port, 443);
    }

    #[test]
    fn default_port_comes_from_the_caller() {
        let spec = parse_target("example.com", 8443).unwrap();
        assert_eq!(
            spec,
            TargetSpec::Single(ScanTarget::new(name("example.com"), 8443))
        );
        let spec = parse_target("10.0.0.0/30", 8443).unwrap();
        assert!(matches!(spec, TargetSpec::Network { port: 8443, .. }));
    }

    #[test]
    fn networks() {
        let (cidr, port) = network("192.0.2.0/24");
        assert_eq!(cidr.to_string(), "192.0.2.0/24");
        assert_eq!(port, 443);

        let (cidr, port) = network("192.0.2.77/24:8443");
        assert_eq!(cidr.to_string(), "192.0.2.0/24");
        assert_eq!(port, 8443);

        let (cidr, port) = network("2001:db8::/120");
        assert_eq!(cidr.to_string(), "2001:db8::/120");
        assert_eq!(port, 443);

        let (cidr, port) = network("[2001:db8::]/120:8443");
        assert_eq!(cidr.to_string(), "2001:db8::/120");
        assert_eq!(port, 8443);

        let (cidr, _) = network("0.0.0.0/0");
        assert_eq!(cidr.prefix(), 0);
    }

    #[test]
    fn empty_and_whitespace() {
        assert_eq!(kind(""), TargetErrorKind::Empty);
        assert_eq!(kind("   "), TargetErrorKind::Empty);
        assert_eq!(kind("example.com 443"), TargetErrorKind::InvalidCharacter);
        assert_eq!(kind("exa\u{7}mple.com"), TargetErrorKind::InvalidCharacter);
    }

    #[test]
    fn url_errors() {
        assert_eq!(
            kind("http://example.com"),
            TargetErrorKind::UnsupportedScheme
        );
        assert_eq!(
            kind("ftp://example.com"),
            TargetErrorKind::UnsupportedScheme
        );
        assert_eq!(kind("://example.com"), TargetErrorKind::UnsupportedScheme);
        assert_eq!(kind("https://user@example.com"), TargetErrorKind::UserInfo);
        assert_eq!(kind("user@example.com"), TargetErrorKind::UserInfo);
        assert_eq!(kind("https://"), TargetErrorKind::InvalidName);
        assert_eq!(kind("https:///path"), TargetErrorKind::InvalidName);
    }

    #[test]
    fn port_errors() {
        assert_eq!(kind("example.com:"), TargetErrorKind::InvalidPort);
        assert_eq!(kind("example.com:0"), TargetErrorKind::InvalidPort);
        assert_eq!(kind("example.com:65536"), TargetErrorKind::InvalidPort);
        assert_eq!(kind("example.com:https"), TargetErrorKind::InvalidPort);
        assert_eq!(kind("example.com:+443"), TargetErrorKind::InvalidPort);
        assert_eq!(kind("example.com:000443"), TargetErrorKind::InvalidPort);
        assert_eq!(kind("[::1]8443"), TargetErrorKind::InvalidPort);
        assert_eq!(kind("[::1]:"), TargetErrorKind::InvalidPort);
        assert_eq!(kind("192.0.2.0/24:0"), TargetErrorKind::InvalidPort);
    }

    #[test]
    fn address_errors() {
        assert_eq!(kind("256.1.1.1"), TargetErrorKind::InvalidAddress);
        assert_eq!(kind("10.0.0"), TargetErrorKind::InvalidAddress);
        assert_eq!(kind("1.2.3.4.5:443"), TargetErrorKind::InvalidAddress);
        assert_eq!(kind("[2001:db8::zz]"), TargetErrorKind::InvalidAddress);
        assert_eq!(kind("[192.0.2.1]"), TargetErrorKind::InvalidAddress);
        assert_eq!(kind("2001:db8::1::2"), TargetErrorKind::InvalidAddress);
        assert_eq!(kind("fe80::1%eth0"), TargetErrorKind::InvalidAddress);
        assert_eq!(kind("[2001:db8::1"), TargetErrorKind::UnclosedBracket);
        assert_eq!(kind("example.com/24"), TargetErrorKind::InvalidAddress);
        assert_eq!(kind("example.com/path"), TargetErrorKind::InvalidAddress);
    }

    #[test]
    fn name_errors() {
        assert_eq!(kind("-example.com"), TargetErrorKind::InvalidName);
        assert_eq!(kind("example-.com"), TargetErrorKind::InvalidName);
        assert_eq!(kind("exa..mple.com"), TargetErrorKind::InvalidName);
        assert_eq!(kind(".example.com"), TargetErrorKind::InvalidName);
        assert_eq!(kind("exa*mple.com"), TargetErrorKind::InvalidName);
        assert_eq!(kind("."), TargetErrorKind::InvalidName);
        assert_eq!(kind(":443"), TargetErrorKind::InvalidName);

        let long_label = format!("{}.example", "a".repeat(64));
        assert_eq!(kind(&long_label), TargetErrorKind::InvalidName);
        let fits = format!("{}.example", "a".repeat(63));
        assert_eq!(single(&fits).host, name(&fits));

        let label = "a".repeat(63);
        let long_name = format!("{label}.{label}.{label}.{label}");
        assert_eq!(long_name.len(), 255);
        assert_eq!(kind(&long_name), TargetErrorKind::NameTooLong);
    }

    #[test]
    fn non_ascii_names_are_rejected_with_a_hint() {
        assert_eq!(kind("пример.рф"), TargetErrorKind::NonAsciiName);
        assert_eq!(
            kind("https://bücher.example/"),
            TargetErrorKind::NonAsciiName
        );
        let error = parse_target("пример.рф", DEFAULT_PORT).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("пример.рф"));
        assert!(text.contains("punycode"));
    }

    #[test]
    fn prefix_errors() {
        assert_eq!(kind("192.0.2.0/33"), TargetErrorKind::InvalidPrefix);
        assert_eq!(kind("192.0.2.0/"), TargetErrorKind::InvalidPrefix);
        assert_eq!(kind("192.0.2.0/-1"), TargetErrorKind::InvalidPrefix);
        assert_eq!(kind("192.0.2.0/2x"), TargetErrorKind::InvalidPrefix);
        assert_eq!(kind("192.0.2.0/999"), TargetErrorKind::InvalidPrefix);
        assert_eq!(kind("2001:db8::/129"), TargetErrorKind::InvalidPrefix);
        assert_eq!(kind("[2001:db8::/64"), TargetErrorKind::UnclosedBracket);
    }

    #[test]
    fn error_keeps_the_original_input() {
        let error = parse_target("  example.com:99999  ", DEFAULT_PORT).unwrap_err();
        assert_eq!(error.input, "  example.com:99999  ");
        assert_eq!(error.kind, TargetErrorKind::InvalidPort);
        assert_eq!(
            error.to_string(),
            "некорректная цель «  example.com:99999  »: порт должен быть числом от 1 до 65535"
        );
    }

    #[test]
    fn name_target_converts_to_a_net_target() {
        let target = single("https://example.com:8443/status");
        let net_target = target.to_net();
        assert_eq!(net_target, net::Target::new("example.com", 8443));
        assert_eq!(net_target.server_name(), Some("example.com"));
        assert_eq!(target.server_name(), net_target.server_name());
        assert_eq!(target.connect_ip(), None);
        assert_eq!(target.to_string(), "example.com:8443/status");
    }

    #[test]
    fn address_targets_convert_to_net_targets() {
        let v4 = single("192.0.2.1:8443");
        assert_eq!(v4.to_net(), net::Target::new("192.0.2.1", 8443));
        assert_eq!(v4.to_net().server_name(), None);
        assert_eq!(v4.server_name(), None);
        assert_eq!(v4.connect_ip(), Some("192.0.2.1".parse().unwrap()));

        let v6 = single("[2001:db8::1]:8443");
        let net_target = v6.to_net();
        assert_eq!(net_target, net::Target::new("2001:db8::1", 8443));
        assert_eq!(net_target.server_name(), None);
        assert_eq!(net_target.to_string(), "[2001:db8::1]:8443");
        assert_eq!(v6.to_string(), "[2001:db8::1]:8443");
        assert_eq!(
            net::parse_ip_literal(&net_target.host),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn overrides_survive_next_to_the_net_target() {
        let override_ip: IpAddr = "198.51.100.7".parse().unwrap();
        let target = ScanTarget {
            sni: Some("front.example".to_owned()),
            ip_override: Some(override_ip),
            ..single("example.com")
        };
        // Имя и порт уходят в net::Target, адрес — в параметры резолва,
        // имя SNI остаётся у цели.
        assert_eq!(target.to_net(), net::Target::new("example.com", 443));
        assert_eq!(target.server_name(), Some("front.example"));
        assert_eq!(target.connect_ip(), Some(override_ip));
        let options = target.resolve_options(net::ResolveOptions::default());
        assert_eq!(options.ip_override, Some(override_ip));
        assert_eq!(options.family, net::ResolveOptions::default().family);

        let global: IpAddr = "203.0.113.9".parse().unwrap();
        let base = net::ResolveOptions {
            ip_override: Some(global),
            ..net::ResolveOptions::default()
        };
        assert_eq!(target.resolve_options(base).ip_override, Some(override_ip));
        let plain = single("example.com");
        assert_eq!(plain.resolve_options(base).ip_override, Some(global));

        let by_address = ScanTarget {
            sni: Some("front.example".to_owned()),
            ..single("192.0.2.1")
        };
        assert_eq!(by_address.server_name(), Some("front.example"));
        assert_eq!(by_address.to_net().server_name(), None);
    }
}
