//! Реестр IANA «TLS Alerts» (`data/iana/tls-parameters-6.csv`).
//!
//! Правила отбора строк описаны в документации крейта. Столбца `Recommended`
//! и значений GREASE в этом реестре нет.

registry! {
    /// Код описания alert (`AlertDescription`).
    AlertDescription(u8),
    ALERT_DESCRIPTIONS,
    ALERT_DESCRIPTIONS_BY_NAME,
    ALERT_DESCRIPTIONS_GREASE
}
