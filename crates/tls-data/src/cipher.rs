//! Cipher suites SSLv3/TLS: реестр IANA «TLS Cipher Suites»
//! (`data/iana/tls-parameters-4.csv`), дополненный таблицей шифров testssl.sh
//! (`data/testssl/cipher-mapping.txt`).
//!
//! Таблица — объединение двух источников по двухбайтовому коду:
//!
//! - шифр есть в обоих источниках: заполнены и имя IANA, и
//!   [`CipherSuiteEntry::info`];
//! - шифр есть только в IANA: `info` равно `None` (шифр не классифицирован);
//! - шифр есть только в `cipher-mapping.txt` (устаревшие и нестандартные
//!   коды): имя IANA — пустая строка, `recommended` —
//!   [`Recommended::Unspecified`], имя по версии testssl.sh доступно в
//!   [`CipherInfo::mapping_name`].
//!
//! Расхождения между источниками не сглаживаются: имя IANA берётся только из
//! реестра IANA. Правила отбора строк реестра описаны в документации крейта,
//! формат `cipher-mapping.txt` и классификация — в [`crate::classify`].
//! Трёхбайтовые коды SSLv2 лежат в отдельной таблице [`crate::sslv2`].

use crate::classify::CipherInfo;
use crate::{Recommended, generated};

/// Двухбайтовый код cipher suite SSLv3/TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    /// Код из двух байтов в сетевом порядке.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }

    /// Два байта кода в сетевом порядке.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Запись таблицы для этого кода.
    #[must_use]
    pub fn entry(self) -> Option<&'static CipherSuiteEntry> {
        by_code(self.0)
    }

    /// Имя IANA; `None`, если кода нет в таблице или у него нет записи IANA.
    #[must_use]
    pub fn iana_name(self) -> Option<&'static str> {
        self.entry()
            .map(|entry| entry.iana_name)
            .filter(|name| !name.is_empty())
    }

    /// Имя OpenSSL; `None`, если его нет в `cipher-mapping.txt`.
    #[must_use]
    pub fn openssl_name(self) -> Option<&'static str> {
        self.info()
            .map(|info| info.openssl_name)
            .filter(|name| !name.is_empty())
    }

    /// Свойства шифра из `cipher-mapping.txt`; `None`, если шифр не
    /// классифицирован.
    #[must_use]
    pub fn info(self) -> Option<&'static CipherInfo> {
        self.entry().and_then(|entry| entry.info.as_ref())
    }

    /// Признак значения GREASE (RFC 8701) по данным реестра IANA.
    #[must_use]
    pub fn is_grease(self) -> bool {
        generated::CIPHER_SUITES_GREASE
            .binary_search(&self.0)
            .is_ok()
    }

    /// Код по точному имени IANA.
    #[must_use]
    pub fn from_iana_name(name: &str) -> Option<Self> {
        by_iana_name(name).map(|entry| entry.code)
    }

    /// Код по точному имени OpenSSL.
    #[must_use]
    pub fn from_openssl_name(name: &str) -> Option<Self> {
        by_openssl_name(name).map(|entry| entry.code)
    }
}

impl From<u16> for CipherSuite {
    fn from(code: u16) -> Self {
        Self(code)
    }
}

impl From<CipherSuite> for u16 {
    fn from(code: CipherSuite) -> Self {
        code.0
    }
}

/// Запись объединённой таблицы cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuiteEntry {
    /// Кодовое значение.
    pub code: CipherSuite,
    /// Имя IANA; пустая строка, если шифра нет в реестре IANA.
    pub iana_name: &'static str,
    /// Остаток описания IANA после имени; обычно пуст.
    pub note: &'static str,
    /// Столбец `Recommended` реестра IANA.
    pub recommended: Recommended,
    /// Свойства из `cipher-mapping.txt`; `None`, если шифра там нет.
    pub info: Option<CipherInfo>,
}

/// Все записи таблицы по возрастанию кода.
#[must_use]
pub fn all() -> &'static [CipherSuiteEntry] {
    generated::CIPHER_SUITES
}

/// Итератор по записям таблицы по возрастанию кода.
pub fn iter() -> impl Iterator<Item = &'static CipherSuiteEntry> {
    all().iter()
}

/// Поиск записи по коду.
#[must_use]
pub fn by_code(code: u16) -> Option<&'static CipherSuiteEntry> {
    let table = all();
    table
        .binary_search_by_key(&code, |entry| entry.code.0)
        .ok()
        .and_then(|index| table.get(index))
}

/// Поиск записи по точному имени IANA (с учётом регистра).
#[must_use]
pub fn by_iana_name(name: &str) -> Option<&'static CipherSuiteEntry> {
    lookup_name(generated::CIPHER_SUITES_BY_IANA_NAME, name)
}

/// Поиск записи по точному имени OpenSSL (с учётом регистра).
#[must_use]
pub fn by_openssl_name(name: &str) -> Option<&'static CipherSuiteEntry> {
    lookup_name(generated::CIPHER_SUITES_BY_OPENSSL_NAME, name)
}

/// Значения GREASE реестра cipher suites по возрастанию кода.
pub fn grease() -> impl Iterator<Item = CipherSuite> {
    generated::CIPHER_SUITES_GREASE
        .iter()
        .copied()
        .map(CipherSuite)
}

fn lookup_name(
    names: &'static [(&'static str, u16)],
    name: &str,
) -> Option<&'static CipherSuiteEntry> {
    names
        .binary_search_by(|&(candidate, _)| candidate.cmp(name))
        .ok()
        .and_then(|index| names.get(index))
        .and_then(|&(_, code)| by_code(code))
}
