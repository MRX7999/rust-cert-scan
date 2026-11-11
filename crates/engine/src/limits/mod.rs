//! Лимиты соединений и скорости.
//!
//! Состав:
//!
//! - [`semaphores`] — семафор с изменяемым лимитом и таблица состояния
//!   хостов с ленивым созданием и удалением записей;
//! - [`token_bucket`] — ограничение числа соединений в секунду;
//! - [`jitter`] — случайная добавка к задержке перед соединением;
//! - [`stats`] — счётчики ожидания на каждом этапе получения разрешения;
//! - [`backoff`] — классификация исходов соединений и AIMD на хост;
//! - [`breaker`] — circuit breaker на хост и ранний выход;
//! - [`limiter`] — единая точка получения разрешения на соединение:
//!   объединяет всё перечисленное.
//!
//! Время берётся только из `tokio::time`, поэтому тесты идут на
//! приостановленных часах.

pub mod backoff;
pub mod breaker;
pub mod jitter;
pub mod limiter;
pub mod semaphores;
pub mod stats;
pub mod token_bucket;

pub use backoff::{Aimd, AimdConfig, Effective, Outcome, Signal, is_local_exhaustion};
pub use breaker::{Breaker, BreakerConfig, BreakerState, Decision, DisableReason, Reaction};
pub use jitter::{Jitter, JitterRange, JitterSource, SplitMix64};
pub use limiter::{Denied, GuardConfig, HostHandle, Limiter, LimitsConfig, Permit, UNLIMITED};
pub use semaphores::{AdjustableSemaphore, HostEntry, HostTable, SlotPermit};
pub use stats::{LimitStats, LimitStatsSnapshot, Stage, StageSnapshot};
pub use token_bucket::{Rate, TokenBucket};

#[cfg(test)]
mod limiter_tests;
