//! Таймауты сетевого слоя и общий дедлайн.
//!
//! `docs/ARCHITECTURE.md`, раздел 5, требует трёх раздельных таймаутов
//! (connect, handshake, read) и общего дедлайна, который обрывает медленную
//! «капельную» отдачу данных. Числовых значений в архитектуре нет: значения
//! по умолчанию ниже — предварительные, `docs/DECISIONS.md`, D-17.
//!
//! Время берётся из [`tokio::time::Instant`], поэтому тесты идут на
//! приостановленных часах. Арифметика времени не паникует: дедлайн, не
//! представимый в `Instant`, считается отсутствующим ([`Deadline::after`]),
//! остаток считается через `checked_duration_since`.

use std::time::Duration;

use tokio::time::Instant;

/// Таймаут установления TCP-соединения с одним адресом по умолчанию.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Таймаут ожидания первого байта ответа после отправки пробника по
/// умолчанию.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Таймаут ожидания очередной порции ответа по умолчанию.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Таймаут отправки одного пробника целиком по умолчанию.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Общий дедлайн одного обмена (все отправки и чтения на одном соединении)
/// по умолчанию.
pub const DEFAULT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Сколько закрытие соединения ждёт завершения `shutdown`, прежде чем
/// просто отпустить сокет.
pub const CLOSE_TIMEOUT: Duration = Duration::from_millis(250);

/// Таймауты одного соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Установление TCP-соединения с одним адресом (`--connect-timeout`).
    pub connect: Duration,
    /// От отправки пробника до первого байта ответа (`--handshake-timeout`).
    pub handshake: Duration,
    /// Между порциями ответа (`--read-timeout`).
    pub read: Duration,
    /// Отправка одного пробника целиком.
    pub write: Duration,
    /// Общий дедлайн обмена на одном соединении, считая от создания
    /// [`ProbeSession`](crate::probe_io::ProbeSession). Дедлайн всей
    /// проверки (`--check-timeout`) задаёт вызывающий код через
    /// [`ProbeSession::set_deadline`](crate::probe_io::ProbeSession::set_deadline).
    pub exchange: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT_TIMEOUT,
            handshake: DEFAULT_HANDSHAKE_TIMEOUT,
            read: DEFAULT_READ_TIMEOUT,
            write: DEFAULT_WRITE_TIMEOUT,
            exchange: DEFAULT_EXCHANGE_TIMEOUT,
        }
    }
}

/// Абсолютный дедлайн либо его отсутствие.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline(Option<Instant>);

impl Deadline {
    /// Дедлайна нет.
    pub const NONE: Self = Self(None);

    /// Дедлайн в заданный момент.
    #[must_use]
    pub fn at(instant: Instant) -> Self {
        Self(Some(instant))
    }

    /// Дедлайн через `timeout` после `start`. Если момент не представим
    /// (переполнение), дедлайна нет: такой таймаут заведомо больше любого
    /// реального ожидания.
    #[must_use]
    pub fn after(start: Instant, timeout: Duration) -> Self {
        Self(start.checked_add(timeout))
    }

    /// Момент дедлайна; `None`, если дедлайна нет.
    #[must_use]
    pub fn instant(&self) -> Option<Instant> {
        self.0
    }

    /// Более ранний из двух дедлайнов.
    #[must_use]
    pub fn earliest(self, other: Self) -> Self {
        match (self.0, other.0) {
            (Some(a), Some(b)) => Self(Some(a.min(b))),
            (Some(a), None) => Self(Some(a)),
            (None, b) => Self(b),
        }
    }

    /// Остаток до дедлайна: `None`, если дедлайн наступил;
    /// [`Duration::MAX`], если дедлайна нет.
    #[must_use]
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        let Some(at) = self.0 else {
            return Some(Duration::MAX);
        };
        let left = at.checked_duration_since(now)?;
        if left.is_zero() { None } else { Some(left) }
    }

    /// Истина, если дедлайн наступил.
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        self.remaining(now).is_none()
    }

    /// Время, отведённое очередной операции: не больше `timeout` и не больше
    /// остатка до дедлайна. `None` — дедлайн наступил, операцию начинать
    /// нельзя.
    #[must_use]
    pub fn budget(&self, now: Instant, timeout: Duration) -> Option<Duration> {
        self.remaining(now).map(|left| left.min(timeout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_documented_constants() {
        let timeouts = Timeouts::default();
        assert_eq!(timeouts.connect, Duration::from_secs(5));
        assert_eq!(timeouts.handshake, Duration::from_secs(10));
        assert_eq!(timeouts.read, Duration::from_secs(5));
        assert_eq!(timeouts.write, Duration::from_secs(5));
        assert_eq!(timeouts.exchange, Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn budget_is_capped_by_timeout_and_by_deadline() {
        let start = Instant::now();
        let deadline = Deadline::after(start, Duration::from_secs(10));

        assert_eq!(
            deadline.budget(start, Duration::from_secs(3)),
            Some(Duration::from_secs(3))
        );
        tokio::time::advance(Duration::from_secs(8)).await;
        let now = Instant::now();
        assert_eq!(deadline.remaining(now), Some(Duration::from_secs(2)));
        assert_eq!(
            deadline.budget(now, Duration::from_secs(3)),
            Some(Duration::from_secs(2))
        );
        assert!(!deadline.is_expired(now));

        // Ровно в момент дедлайна и после него операцию начинать нельзя.
        tokio::time::advance(Duration::from_secs(2)).await;
        let now = Instant::now();
        assert_eq!(deadline.remaining(now), None);
        assert_eq!(deadline.budget(now, Duration::from_secs(3)), None);
        assert!(deadline.is_expired(now));
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(deadline.is_expired(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn missing_and_unrepresentable_deadlines_never_expire() {
        let now = Instant::now();
        assert_eq!(Deadline::NONE.remaining(now), Some(Duration::MAX));
        assert_eq!(
            Deadline::NONE.budget(now, Duration::from_secs(1)),
            Some(Duration::from_secs(1))
        );

        // Переполнение при сложении не паникует: дедлайна нет.
        let huge = Deadline::after(now, Duration::MAX);
        assert_eq!(huge, Deadline::NONE);
        assert_eq!(huge.instant(), None);
        assert!(!huge.is_expired(now));
    }

    #[tokio::test(start_paused = true)]
    async fn zero_timeout_expires_immediately() {
        let now = Instant::now();
        let deadline = Deadline::after(now, Duration::ZERO);
        assert!(deadline.is_expired(now));
        assert_eq!(deadline.budget(now, Duration::from_secs(1)), None);
    }

    #[tokio::test(start_paused = true)]
    async fn earliest_picks_the_sooner_deadline() {
        let now = Instant::now();
        let near = Deadline::after(now, Duration::from_secs(1));
        let far = Deadline::after(now, Duration::from_secs(9));
        assert_eq!(near.earliest(far), near);
        assert_eq!(far.earliest(near), near);
        assert_eq!(near.earliest(Deadline::NONE), near);
        assert_eq!(Deadline::NONE.earliest(far), far);
        assert_eq!(Deadline::NONE.earliest(Deadline::NONE), Deadline::NONE);
        assert_eq!(Deadline::at(now).instant(), Some(now));
    }
}
