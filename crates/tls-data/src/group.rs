//! Реестр IANA «TLS Supported Groups» (`data/iana/tls-parameters-8.csv`).
//!
//! Правила отбора строк описаны в документации крейта.

registry! {
    /// Код группы (`NamedGroup`) из расширений `supported_groups` и `key_share`.
    NamedGroup(u16),
    NAMED_GROUPS,
    NAMED_GROUPS_BY_NAME,
    NAMED_GROUPS_GREASE
}
