//! Свойства шифров из `etc/cipher-mapping.txt` проекта testssl.sh и их
//! классификация.
//!
//! # Формат `cipher-mapping.txt`
//!
//! Файл хранится без правок в `data/testssl/cipher-mapping.txt` (GPLv2, см.
//! `data/testssl/NOTICE.md`). Одна строка — один шифр, поля разделены
//! пробелами, комментариев и пустых строк нет:
//!
//! ```text
//! <код> - <имя OpenSSL> <имя RFC> <протокол> Kx=<kx> Au=<au> Enc=<enc> Mac=<mac> [export]
//! ```
//!
//! | Поле | Содержимое | Куда попадает |
//! |---|---|---|
//! | код | `0xHH,0xHH` (SSLv3/TLS) либо `0xHH,0xHH,0xHH` (SSLv2) | код записи; трёхбайтовые коды идут в таблицу [`crate::sslv2`] |
//! | `-` | разделитель | проверяется и отбрасывается |
//! | имя OpenSSL | например `ECDHE-RSA-AES256-GCM-SHA384`; `-`, если имени нет | [`CipherInfo::openssl_name`], `-` превращается в пустую строку |
//! | имя RFC | например `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`; `-`, если имени нет | [`CipherInfo::mapping_name`], `-` превращается в пустую строку |
//! | протокол | `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.2`, `TLSv1.3` | [`CipherInfo::protocol`] |
//! | `Kx=` | обмен ключами, у export-шифров с длиной в скобках: `RSA(512)` | [`CipherInfo::kx`], [`CipherInfo::kx_bits`] |
//! | `Au=` | аутентификация | [`CipherInfo::auth`] |
//! | `Enc=` | шифр и длина ключа в битах: `AESGCM(256)`; `None` без скобок | [`CipherInfo::enc`], [`CipherInfo::enc_bits`] (для `None` — 0) |
//! | `Mac=` | MAC либо `AEAD` | [`CipherInfo::mac`] |
//! | `export` | необязательный признак export-шифра | [`CipherInfo::export`] |
//!
//! Значения полей `kx`, `auth`, `enc`, `mac` хранятся строками в том виде, в
//! каком они записаны в файле.
//!
//! # Правила классификации
//!
//! В `docs/ARCHITECTURE.md` и `docs/PLAN.md` перечислены только названия
//! категорий, без критериев, поэтому каждое правило выведено из полей файла:
//!
//! | Метод | Правило |
//! |---|---|
//! | [`CipherInfo::is_null`] | `Enc=None` |
//! | [`CipherInfo::is_anon`] | `Au=None` (включая `TLS_NULL_WITH_NULL_NULL` и `SSL_CK_NULL`, у которых и `Kx=None`) |
//! | [`CipherInfo::is_export`] | признак `export` в конце строки |
//! | [`CipherInfo::is_rc4`] | `Enc=RC4` |
//! | [`CipherInfo::is_des`] | `Enc=DES` |
//! | [`CipherInfo::is_triple_des`] | `Enc=3DES` |
//! | [`CipherInfo::has_64bit_block`] | `Enc` — `DES`, `3DES`, `IDEA` или `RC2` |
//! | [`CipherInfo::is_cbc`] | имя RFC содержит `_CBC_` либо имя OpenSSL содержит `CBC` |
//! | [`CipherInfo::is_aead`] | `Mac=AEAD` |
//! | [`CipherInfo::has_forward_secrecy`] | `Kx` — `DH`, `ECDH`, `DHEPSK`, `ECDHEPSK`, `CECPQ1` или `any` |
//!
//! Пояснения:
//!
//! - Размер блока в файле не записан. Список для `has_64bit_block` — это
//!   свойство перечисленных алгоритмов, а не поле таблицы. ГОСТ 28147-89
//!   (`Enc=GOST`) в список не включён: в файле он встречается только в
//!   режиме счётчика (`_CNT_`), и решение о нём оставлено проверкам.
//! - В файле `Kx=DH` и `Kx=ECDH` без суффикса обозначают эфемерный обмен
//!   (имена RFC содержат `_DHE_`, `_ECDHE_` или `_anon_`), а статический
//!   записан как `DH/RSA`, `DH/DSS`, `ECDH/RSA`, `ECDH/ECDSA`. Анонимные
//!   шифры с эфемерным DH поэтому тоже имеют признак forward secrecy;
//!   сочетать его с [`CipherInfo::is_anon`] должна проверка.
//! - `Kx=any` стоит у шифров TLS 1.3. Признак forward secrecy для них —
//!   допущение: в TLS 1.3 обмен ключами не зависит от suite, и режим
//!   `psk_ke` без (EC)DHE по suite не виден.
//! - `SRP`, `KRB5`, `GOST`, `RSA`, `PSK`, `RSAPSK` признака forward secrecy не
//!   имеют.
//!
//! Вне объёма: группа стойкости (LOW, MEDIUM, HIGH и подобные). Пороги в
//! документах проекта не определены и из файла не выводятся; для будущих
//! проверок доступны исходные поля [`CipherInfo::enc_bits`] и
//! [`CipherInfo::kx_bits`].
//!
//! Шифр, которого нет в `cipher-mapping.txt`, не классифицирован:
//! [`crate::cipher::CipherSuiteEntry::info`] равно `None`.

/// Минимальная версия протокола из столбца «протокол» `cipher-mapping.txt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MinProtocol {
    /// `SSLv2`.
    Ssl2,
    /// `SSLv3`.
    Ssl3,
    /// `TLSv1`.
    Tls10,
    /// `TLSv1.2`.
    Tls12,
    /// `TLSv1.3`.
    Tls13,
}

/// Свойства шифра из одной строки `cipher-mapping.txt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherInfo {
    /// Имя OpenSSL; пустая строка, если в файле стоит `-`.
    pub openssl_name: &'static str,
    /// Имя RFC по версии testssl.sh; пустая строка, если в файле стоит `-`.
    pub mapping_name: &'static str,
    /// Минимальная версия протокола.
    pub protocol: MinProtocol,
    /// Обмен ключами (`Kx=`) без длины в скобках.
    pub kx: &'static str,
    /// Длина ключа обмена в битах, если она указана в скобках (`RSA(512)`).
    pub kx_bits: Option<u16>,
    /// Аутентификация (`Au=`).
    pub auth: &'static str,
    /// Алгоритм шифрования (`Enc=`) без длины в скобках; `None` у шифров без
    /// шифрования.
    pub enc: &'static str,
    /// Длина ключа шифрования в битах; 0 для `Enc=None`.
    pub enc_bits: u16,
    /// MAC (`Mac=`); `AEAD` у AEAD-шифров.
    pub mac: &'static str,
    /// Признак `export` в конце строки.
    pub export: bool,
}

impl CipherInfo {
    /// Шифр без шифрования: `Enc=None`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.enc == "None"
    }

    /// Шифр без аутентификации сервера: `Au=None`.
    #[must_use]
    pub fn is_anon(&self) -> bool {
        self.auth == "None"
    }

    /// Export-шифр: признак `export` в файле.
    #[must_use]
    pub fn is_export(&self) -> bool {
        self.export
    }

    /// Шифр RC4: `Enc=RC4`.
    #[must_use]
    pub fn is_rc4(&self) -> bool {
        self.enc == "RC4"
    }

    /// Одинарный DES: `Enc=DES`.
    #[must_use]
    pub fn is_des(&self) -> bool {
        self.enc == "DES"
    }

    /// Тройной DES: `Enc=3DES`.
    #[must_use]
    pub fn is_triple_des(&self) -> bool {
        self.enc == "3DES"
    }

    /// Блочный шифр с 64-битным блоком: `DES`, `3DES`, `IDEA`, `RC2`.
    #[must_use]
    pub fn has_64bit_block(&self) -> bool {
        matches!(self.enc, "DES" | "3DES" | "IDEA" | "RC2")
    }

    /// Режим CBC: имя RFC содержит `_CBC_` либо имя OpenSSL содержит `CBC`.
    #[must_use]
    pub fn is_cbc(&self) -> bool {
        self.mapping_name.contains("_CBC_") || self.openssl_name.contains("CBC")
    }

    /// AEAD-шифр: `Mac=AEAD`.
    #[must_use]
    pub fn is_aead(&self) -> bool {
        self.mac == "AEAD"
    }

    /// Эфемерный обмен ключами: `Kx` — `DH`, `ECDH`, `DHEPSK`, `ECDHEPSK`,
    /// `CECPQ1` или `any` (TLS 1.3).
    #[must_use]
    pub fn has_forward_secrecy(&self) -> bool {
        matches!(
            self.kx,
            "DH" | "ECDH" | "DHEPSK" | "ECDHEPSK" | "CECPQ1" | "any"
        )
    }
}
