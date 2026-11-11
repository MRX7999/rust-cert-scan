//! Реестр IANA «TLS ExtensionType Values»
//! (`data/iana/tls-extensiontype-values-1.csv`).
//!
//! Правила отбора строк описаны в документации крейта.

registry! {
    /// Код типа расширения TLS.
    ExtensionType(u16),
    EXTENSION_TYPES,
    EXTENSION_TYPES_BY_NAME,
    EXTENSION_TYPES_GREASE
}
