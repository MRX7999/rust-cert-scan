//! SSLv2 cipher kinds: трёхбайтовые коды из `data/testssl/cipher-mapping.txt`.
//!
//! В реестрах IANA этих кодов нет, единственный источник — таблица шифров
//! testssl.sh. В таблицу попадают все строки файла с трёхбайтовым кодом;
//! формат файла и классификация описаны в [`crate::classify`].

use crate::classify::CipherInfo;
use crate::generated;

/// Трёхбайтовый код SSLv2 cipher kind в младших 24 битах.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sslv2CipherKind(pub u32);

impl Sslv2CipherKind {
    /// Код из трёх байтов в сетевом порядке.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 3]) -> Self {
        let [first, second, third] = bytes;
        Self(u32::from_be_bytes([0, first, second, third]))
    }

    /// Три младших байта кода в сетевом порядке.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 3] {
        let [_, first, second, third] = self.0.to_be_bytes();
        [first, second, third]
    }

    /// Запись таблицы для этого кода.
    #[must_use]
    pub fn entry(self) -> Option<&'static Sslv2CipherEntry> {
        by_code(self.0)
    }

    /// Имя OpenSSL; `None`, если кода нет в таблице.
    #[must_use]
    pub fn openssl_name(self) -> Option<&'static str> {
        self.entry()
            .map(|entry| entry.info.openssl_name)
            .filter(|name| !name.is_empty())
    }

    /// Код по точному имени OpenSSL.
    #[must_use]
    pub fn from_openssl_name(name: &str) -> Option<Self> {
        by_openssl_name(name).map(|entry| entry.code)
    }
}

/// Запись таблицы SSLv2 cipher kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sslv2CipherEntry {
    /// Кодовое значение.
    pub code: Sslv2CipherKind,
    /// Свойства из `cipher-mapping.txt`.
    pub info: CipherInfo,
}

/// Все записи таблицы по возрастанию кода.
#[must_use]
pub fn all() -> &'static [Sslv2CipherEntry] {
    generated::SSLV2_CIPHERS
}

/// Итератор по записям таблицы по возрастанию кода.
pub fn iter() -> impl Iterator<Item = &'static Sslv2CipherEntry> {
    all().iter()
}

/// Поиск записи по 24-битному коду.
#[must_use]
pub fn by_code(code: u32) -> Option<&'static Sslv2CipherEntry> {
    let table = all();
    table
        .binary_search_by_key(&code, |entry| entry.code.0)
        .ok()
        .and_then(|index| table.get(index))
}

/// Поиск записи по точному имени OpenSSL (с учётом регистра).
#[must_use]
pub fn by_openssl_name(name: &str) -> Option<&'static Sslv2CipherEntry> {
    let names = generated::SSLV2_CIPHERS_BY_OPENSSL_NAME;
    names
        .binary_search_by(|&(candidate, _)| candidate.cmp(name))
        .ok()
        .and_then(|index| names.get(index))
        .and_then(|&(_, code)| by_code(code))
}
