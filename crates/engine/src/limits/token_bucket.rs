//! Token bucket на `tokio::time`: ограничение числа соединений в секунду.
//!
//! # Модель
//!
//! Реализация — GCRA (эквивалент token bucket без счётчика токенов): в
//! состоянии хранится один момент времени `tat` — когда был бы выдан
//! следующий токен при равномерной выдаче. Токен выдаётся, если
//! `now >= tat - (burst - 1) * T`, где `T` — интервал между токенами; после
//! выдачи `tat = max(tat, now) + T`. Отсюда свойства:
//!
//! - после простоя подряд выдаётся не более `burst` токенов, дальше — по
//!   одному за `T`;
//! - за любой интервал длиной `D` выдаётся не более `burst + D / T` токенов;
//! - арифметика целочисленная, остатки не накапливаются и не теряются.
//!
//! # Отмена
//!
//! [`TokenBucket::take`] списывает токен только в момент выдачи: пока задача
//! ждёт, состояние не изменено, поэтому сброс future ничего не теряет.
//! Очередь ожидающих — FIFO (`tokio::sync::Mutex`), сброшенный ожидающий
//! освобождает место следующему. Если токен уже выдан, а соединение не
//! состоится (отмена на следующем этапе захвата), его возвращает
//! [`TokenBucket::refund`].
//!
//! # Скорость
//!
//! [`Rate`] хранит скорость в тысячных соединения в секунду: адаптивный
//! backoff делит скорость хоста пополам, и целых соединений в секунду для
//! этого мало. «Без ограничения» — отдельное значение [`Rate::Unlimited`].

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

/// Наносекунд на один токен при скорости в одну тысячную соединения в
/// секунду.
const NANOS_PER_TOKEN_AT_ONE_MILLI: u64 = 1_000_000_000_000;

/// Тысячных в одном соединении в секунду.
const MILLI: u64 = 1000;

/// Скорость выдачи разрешений.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rate {
    /// Без ограничения: токен выдаётся сразу.
    Unlimited,
    /// Тысячных соединения в секунду; ноль трактуется как одна тысячная
    /// (одно соединение за 1000 с), чтобы скорость не обращалась в ноль.
    MilliPerSecond(u64),
}

impl Rate {
    /// Скорость в целых соединениях в секунду.
    #[must_use]
    pub fn per_second(connections: u32) -> Self {
        Self::MilliPerSecond(u64::from(connections).saturating_mul(MILLI))
    }

    /// Истина для [`Rate::Unlimited`].
    #[must_use]
    pub fn is_unlimited(self) -> bool {
        matches!(self, Self::Unlimited)
    }

    /// Скорость в тысячных соединения в секунду; `None` — без ограничения.
    #[must_use]
    pub fn milli_per_second(self) -> Option<u64> {
        match self {
            Self::Unlimited => None,
            Self::MilliPerSecond(milli) => Some(milli.max(1)),
        }
    }

    /// Интервал между токенами; `None` — без ограничения.
    #[must_use]
    pub fn interval(self) -> Option<Duration> {
        self.milli_per_second()
            .map(|milli| Duration::from_nanos(NANOS_PER_TOKEN_AT_ONE_MILLI / milli))
    }
}

/// Token bucket; описание — в документации модуля.
#[derive(Debug)]
pub struct TokenBucket {
    state: Mutex<State>,
    /// Очередь ожидающих: токен ждёт только её владелец, остальные стоят в
    /// порядке прихода.
    queue: tokio::sync::Mutex<()>,
}

#[derive(Debug)]
struct State {
    rate: Rate,
    burst: u32,
    /// Момент выдачи следующего токена при равномерной выдаче.
    tat: Instant,
}

impl TokenBucket {
    /// Полный bucket: `burst` токенов доступны сразу. `burst` меньше 1
    /// трактуется как 1.
    #[must_use]
    pub fn new(rate: Rate, burst: u32) -> Self {
        Self {
            state: Mutex::new(State {
                rate,
                burst: burst.max(1),
                tat: Instant::now(),
            }),
            queue: tokio::sync::Mutex::new(()),
        }
    }

    /// Текущая скорость.
    #[must_use]
    pub fn rate(&self) -> Rate {
        self.lock().rate
    }

    /// Меняет скорость. Уже выданные токены не отзываются; новая скорость
    /// действует со следующей выдачи.
    pub fn set_rate(&self, rate: Rate) {
        self.lock().rate = rate;
    }

    /// Выдаёт токен, если он доступен сейчас.
    ///
    /// # Errors
    ///
    /// Время до ближайшего токена, если сейчас его нет; состояние при этом
    /// не меняется.
    pub fn try_take(&self) -> Result<(), Duration> {
        let mut state = self.lock();
        let Some(interval) = state.rate.interval() else {
            return Ok(());
        };
        let now = Instant::now();
        let tolerance = interval.saturating_mul(state.burst.saturating_sub(1));
        let wait = state
            .tat
            .checked_sub(tolerance)
            .and_then(|ready_at| ready_at.checked_duration_since(now))
            .unwrap_or(Duration::ZERO);
        if !wait.is_zero() {
            return Err(wait);
        }
        let base = state.tat.max(now);
        state.tat = base.checked_add(interval).unwrap_or(base);
        Ok(())
    }

    /// Ждёт токен и возвращает время ожидания. Ожидающие обслуживаются в
    /// порядке прихода; сброс future токен не расходует.
    pub async fn take(&self) -> Duration {
        let started = Instant::now();
        let _turn = self.queue.lock().await;
        loop {
            match self.try_take() {
                Ok(()) => return started.elapsed(),
                Err(wait) => tokio::time::sleep(wait).await,
            }
        }
    }

    /// Возвращает один выданный токен: соединение не состоялось. Вызывать
    /// не чаще одного раза на выданный токен.
    pub fn refund(&self) {
        let mut state = self.lock();
        if let Some(interval) = state.rate.interval() {
            state.tat = state.tat.checked_sub(interval).unwrap_or(state.tat);
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Под замком нет кода, способного паниковать посреди изменения, так
        // что состояние отравленного мьютекса согласовано.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const TEN_PER_SECOND: u32 = 10;
    const STEP: Duration = Duration::from_millis(100);

    #[test]
    fn rate_units_and_intervals() {
        assert_eq!(Rate::per_second(TEN_PER_SECOND).interval(), Some(STEP));
        assert_eq!(
            Rate::per_second(TEN_PER_SECOND).milli_per_second(),
            Some(10_000)
        );
        assert_eq!(
            Rate::MilliPerSecond(500).interval(),
            Some(Duration::from_secs(2))
        );
        // Ноль не обращает скорость в ноль.
        assert_eq!(Rate::MilliPerSecond(0).milli_per_second(), Some(1));
        assert_eq!(
            Rate::MilliPerSecond(0).interval(),
            Some(Duration::from_secs(1000))
        );
        assert_eq!(Rate::Unlimited.interval(), None);
        assert_eq!(Rate::Unlimited.milli_per_second(), None);
        assert!(Rate::Unlimited.is_unlimited());
        assert!(!Rate::per_second(1).is_unlimited());
    }

    #[tokio::test(start_paused = true)]
    async fn burst_is_available_at_once_then_one_token_per_interval() {
        let bucket = TokenBucket::new(Rate::per_second(TEN_PER_SECOND), 3);
        for _ in 0..3 {
            assert_eq!(bucket.try_take(), Ok(()));
        }
        assert_eq!(bucket.try_take(), Err(STEP));

        tokio::time::advance(Duration::from_millis(40)).await;
        assert_eq!(bucket.try_take(), Err(Duration::from_millis(60)));

        tokio::time::advance(Duration::from_millis(60)).await;
        assert_eq!(bucket.try_take(), Ok(()));
        assert_eq!(bucket.try_take(), Err(STEP));
    }

    #[tokio::test(start_paused = true)]
    async fn no_more_than_rate_plus_burst_per_second() {
        let bucket = TokenBucket::new(Rate::per_second(TEN_PER_SECOND), 1);
        let start = Instant::now();
        let mut within_first_second = 0_u32;
        for _ in 0..25 {
            bucket.take().await;
            if start.elapsed() < Duration::from_secs(1) {
                within_first_second += 1;
            }
        }
        // Токены в моменты 0, 100, …, 900 мс — ровно 10 за первую секунду.
        assert_eq!(within_first_second, TEN_PER_SECOND);
        assert_eq!(start.elapsed(), Duration::from_millis(2400));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_time_does_not_accumulate_more_than_burst() {
        let bucket = TokenBucket::new(Rate::per_second(TEN_PER_SECOND), 2);
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(bucket.try_take(), Ok(()));
        assert_eq!(bucket.try_take(), Ok(()));
        assert_eq!(bucket.try_take(), Err(STEP));
    }

    #[tokio::test(start_paused = true)]
    async fn unlimited_never_waits_and_zero_burst_means_one() {
        let unlimited = TokenBucket::new(Rate::Unlimited, 1);
        let start = Instant::now();
        for _ in 0..1000 {
            assert_eq!(unlimited.take().await, Duration::ZERO);
        }
        assert_eq!(start.elapsed(), Duration::ZERO);

        let single = TokenBucket::new(Rate::per_second(TEN_PER_SECOND), 0);
        assert_eq!(single.try_take(), Ok(()));
        assert_eq!(single.try_take(), Err(STEP));
    }

    #[tokio::test(start_paused = true)]
    async fn set_rate_applies_to_the_next_token() {
        let bucket = TokenBucket::new(Rate::per_second(TEN_PER_SECOND), 1);
        assert_eq!(bucket.try_take(), Ok(()));
        bucket.set_rate(Rate::per_second(5));
        assert_eq!(bucket.rate(), Rate::per_second(5));
        // Уже выданный токен занял 100 мс; следующий после него — 200 мс.
        assert_eq!(bucket.take().await, STEP);
        assert_eq!(bucket.take().await, Duration::from_millis(200));

        bucket.set_rate(Rate::Unlimited);
        assert_eq!(bucket.take().await, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_wait_consumes_nothing_and_frees_the_queue() {
        let bucket = TokenBucket::new(Rate::per_second(TEN_PER_SECOND), 1);
        assert_eq!(bucket.try_take(), Ok(()));
        let start = Instant::now();

        let cancelled = tokio::time::timeout(Duration::from_millis(30), bucket.take()).await;
        assert!(cancelled.is_err(), "ожидание прервано таймаутом");

        // Токен не израсходован: он доступен ровно в 100 мс от начала, а
        // очередь свободна.
        assert_eq!(bucket.take().await, Duration::from_millis(70));
        assert_eq!(start.elapsed(), STEP);
        assert_eq!(bucket.try_take(), Err(STEP));
    }

    #[tokio::test(start_paused = true)]
    async fn refund_returns_exactly_one_token() {
        let bucket = TokenBucket::new(Rate::per_second(TEN_PER_SECOND), 1);
        assert_eq!(bucket.try_take(), Ok(()));
        assert_eq!(bucket.try_take(), Err(STEP));
        bucket.refund();
        assert_eq!(bucket.try_take(), Ok(()));
        assert_eq!(bucket.try_take(), Err(STEP));

        // Для неограниченной скорости возврат ничего не меняет.
        let unlimited = TokenBucket::new(Rate::Unlimited, 1);
        unlimited.refund();
        assert_eq!(unlimited.try_take(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn waiters_are_served_in_arrival_order() {
        let bucket = Arc::new(TokenBucket::new(Rate::per_second(TEN_PER_SECOND), 1));
        assert_eq!(bucket.try_take(), Ok(()));
        let order = Arc::new(Mutex::new(Vec::new()));

        let mut tasks = Vec::new();
        for id in 0..5_u32 {
            let bucket = Arc::clone(&bucket);
            let order = Arc::clone(&order);
            tasks.push(tokio::spawn(async move {
                bucket.take().await;
                order.lock().unwrap().push((id, Instant::now()));
            }));
            // Даём задаче встать в очередь до запуска следующей.
            tokio::task::yield_now().await;
        }
        let start = Instant::now();
        for task in tasks {
            task.await.unwrap();
        }

        let served = order.lock().unwrap().clone();
        let ids: Vec<u32> = served.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, (0..5).collect::<Vec<u32>>());
        // По одному токену за интервал, без пачек.
        for (position, (_, at)) in served.iter().enumerate() {
            let expected = STEP.saturating_mul(u32::try_from(position).unwrap() + 1);
            assert_eq!(at.duration_since(start), expected);
        }
    }
}
