//! Статические таблицы параметров TLS.
//!
//! Назначение: снимки реестров IANA (cipher suites, supported groups, типы
//! расширений, схемы подписи, alerts) и дополнения к ним (имена OpenSSL,
//! классификация suites, SSLv2 cipher kinds), а также поиск по коду и по имени.
//!
//! Границы ответственности: только данные и поиск по ним. Крейт не выполняет
//! I/O, не разбирает wire-формат и не зависит от других крейтов workspace.
//! Таблицы генерируются в `build.rs` из снимков, лежащих в репозитории;
//! `build.rs` к сети не обращается.
//!
//! # Источники
//!
//! | Модуль | Файл в `data/` | Реестр |
//! |---|---|---|
//! | [`cipher`] | `iana/tls-parameters-4.csv` | TLS Cipher Suites |
//! | [`alert`] | `iana/tls-parameters-6.csv` | TLS Alerts |
//! | [`group`] | `iana/tls-parameters-8.csv` | TLS Supported Groups |
//! | [`sigscheme`] | `iana/tls-signaturescheme.csv` | TLS SignatureScheme |
//! | [`extension`] | `iana/tls-extensiontype-values-1.csv` | TLS ExtensionType Values |
//! | [`cipher`], [`sslv2`], [`classify`] | `testssl/cipher-mapping.txt` | таблица шифров testssl.sh (GPLv2) |
//!
//! Происхождение файлов (URL, дата, sha256) записано в `data/SOURCES.md`;
//! снимки IANA обновляет `cargo xtask update-data`.
//!
//! # Что попадает в таблицы IANA
//!
//! Строка реестра становится записью таблицы, если её столбец `Value`
//! содержит одиночный код, а описание не начинается с `Unassigned` или
//! `Reserved` (без учёта регистра). Отбрасываются:
//!
//! - диапазоны кодов в любой записи: `0x00,0x1C-1D`, `0x01-09,*`, `1-9`,
//!   `0x0000-0x0200` — это всегда `Unassigned`, `Reserved` или
//!   `Reserved for Private Use`;
//! - одиночные коды с описанием `Unassigned` или `Reserved…`;
//! - записи с пустым описанием.
//!
//! Одиночная запись `Reserved`, у которой столбец `Reference` ссылается на
//! RFC 8701, считается значением GREASE: в таблицу имён она не входит, но
//! попадает в отдельный список (функции `grease()` и методы `is_grease()`).
//!
//! Имя записи — первое слово описания. Остаток описания, если он есть
//! (`(OBSOLETE)`, `(deprecated)`, `(renamed from "elliptic_curves")`),
//! сохраняется в поле `note`. Если одно имя носят две записи, поиск по имени
//! возвращает запись без примечания (`connection_id` — код 54, а не
//! устаревший 53).
//!
//! Столбец `Recommended` переносится в [`Recommended`]; у реестра alerts
//! такого столбца нет, там всегда [`Recommended::Unspecified`].
//!
//! Таблицы отсортированы по коду, поиск по коду и по имени — бинарный.
//! Поиск по имени чувствителен к регистру.

#![forbid(unsafe_code)]

/// Объявляет тип-обёртку кода и функции поиска для реестра IANA, который
/// хранится как таблица [`RegistryEntry`].
macro_rules! registry {
    (
        $(#[$meta:meta])*
        $ty:ident($int:ty), $table:ident, $names:ident, $grease:ident
    ) => {
        use $crate::RegistryEntry;

        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $ty(pub $int);

        impl $ty {
            /// Запись реестра для этого кода; `None`, если именованной записи нет.
            #[must_use]
            pub fn entry(self) -> Option<&'static RegistryEntry<$ty>> {
                by_code(self.0)
            }

            /// Имя IANA; `None`, если именованной записи нет.
            #[must_use]
            pub fn name(self) -> Option<&'static str> {
                self.entry().map(|entry| entry.name)
            }

            /// Признак значения GREASE (RFC 8701) по данным реестра.
            #[must_use]
            pub fn is_grease(self) -> bool {
                $crate::generated::$grease.binary_search(&self.0).is_ok()
            }

            /// Код по точному имени IANA.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                by_name(name).map(|entry| entry.code)
            }
        }

        impl From<$int> for $ty {
            fn from(code: $int) -> Self {
                Self(code)
            }
        }

        impl From<$ty> for $int {
            fn from(code: $ty) -> Self {
                code.0
            }
        }

        /// Все именованные записи реестра по возрастанию кода.
        #[must_use]
        pub fn all() -> &'static [RegistryEntry<$ty>] {
            $crate::generated::$table
        }

        /// Итератор по именованным записям реестра по возрастанию кода.
        pub fn iter() -> impl Iterator<Item = &'static RegistryEntry<$ty>> {
            all().iter()
        }

        /// Поиск записи по коду.
        #[must_use]
        pub fn by_code(code: $int) -> Option<&'static RegistryEntry<$ty>> {
            let table = all();
            table
                .binary_search_by_key(&code, |entry| entry.code.0)
                .ok()
                .and_then(|index| table.get(index))
        }

        /// Поиск записи по точному имени IANA (с учётом регистра).
        #[must_use]
        pub fn by_name(name: &str) -> Option<&'static RegistryEntry<$ty>> {
            let names = $crate::generated::$names;
            names
                .binary_search_by(|&(candidate, _)| candidate.cmp(name))
                .ok()
                .and_then(|index| names.get(index))
                .and_then(|&(_, code)| by_code(code))
        }

        /// Значения GREASE этого реестра по возрастанию кода.
        pub fn grease() -> impl Iterator<Item = $ty> {
            $crate::generated::$grease.iter().copied().map($ty)
        }
    };
}

pub mod alert;
pub mod cipher;
pub mod classify;
pub mod extension;
pub mod group;
pub mod sigscheme;
pub mod sslv2;

/// Таблицы, сгенерированные `build.rs`.
mod generated {
    include!(concat!(env!("OUT_DIR"), "/tables.rs"));
}

pub use alert::AlertDescription;
pub use cipher::{CipherSuite, CipherSuiteEntry};
pub use classify::{CipherInfo, MinProtocol};
pub use extension::ExtensionType;
pub use group::NamedGroup;
pub use sigscheme::SignatureScheme;
pub use sslv2::{Sslv2CipherEntry, Sslv2CipherKind};

/// Значение столбца `Recommended` реестра IANA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recommended {
    /// `Y`: рекомендовано IETF.
    Yes,
    /// `N`: не рекомендовано (не оценивалось либо ограниченная применимость).
    No,
    /// `D`: использование не одобряется (discouraged).
    Discouraged,
    /// Столбец пуст либо отсутствует в реестре.
    Unspecified,
}

/// Именованная запись реестра IANA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryEntry<C> {
    /// Кодовое значение.
    pub code: C,
    /// Имя IANA: первое слово описания.
    pub name: &'static str,
    /// Остаток описания после имени, например `(OBSOLETE)`; обычно пуст.
    pub note: &'static str,
    /// Столбец `Recommended`.
    pub recommended: Recommended,
}

#[cfg(test)]
mod tests;
