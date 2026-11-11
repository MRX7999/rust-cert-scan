//! Сетевой слой сканера.
//!
//! Назначение: `Connector` — единственная точка открытия соединений: TCP,
//! DNS с кэшем, прокси, преамбулы STARTTLS, раздельные таймауты, учёт
//! соединений на цель; обмен байтами пробника с сервером.
//!
//! Границы ответственности: крейт доставляет байты и классифицирует сетевые
//! ошибки, но не интерпретирует содержимое TLS-ответов и не принимает решений
//! о находках. Разбор wire-формата — в `tls-probe`.
//!
//! Состояние: выполнена P1-10 — разрешение имён и DNS-кэш ([`dns`]),
//! открытие соединений ([`connector`]), таймауты и дедлайны ([`timeouts`]),
//! учёт соединений ([`stats`]); P1-11 — обмен пробником ([`probe_io`]). Proxy и STARTTLS — задачи Фазы 3; точка
//! расширения для них — обобщённый по транспорту [`Conn`].

pub mod connector;
pub mod dns;
pub mod probe_io;
pub mod stats;
pub mod timeouts;

pub use connector::{
    Conn, ConnectAttempt, ConnectError, ConnectErrorClass, ConnectFailure, ConnectStage, Connector,
    ConnectorConfig, DEFAULT_MAX_ADDRESSES, Target,
};
pub use dns::{
    AddressFamily, DnsCache, DnsCacheConfig, DnsError, DnsMode, ResolveFuture, ResolveOptions,
    Resolver, SystemResolver, parse_ip_literal,
};
pub use probe_io::{
    EofKind, OwnedHandshake, OwnedRecord, OwnedSslv2ServerHello, ProbeSession, ProbeTranscript,
    READ_BUFFER_LEN, StopReason, TranscriptItem, Until, WriteFailure, send_and_collect,
};
pub use stats::{ConnStats, ConnStatsSnapshot};
pub use timeouts::{Deadline, Timeouts};

#[cfg(test)]
mod probe_io_tests;
