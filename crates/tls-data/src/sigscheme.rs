//! Реестр IANA «TLS SignatureScheme» (`data/iana/tls-signaturescheme.csv`).
//!
//! Правила отбора строк описаны в документации крейта.

registry! {
    /// Код схемы подписи из расширения `signature_algorithms`.
    SignatureScheme(u16),
    SIGNATURE_SCHEMES,
    SIGNATURE_SCHEMES_BY_NAME,
    SIGNATURE_SCHEMES_GREASE
}
