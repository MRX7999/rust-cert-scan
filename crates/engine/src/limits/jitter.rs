//! Jitter: случайная добавка к задержке перед соединением.
//!
//! Добавка разносит соединения во времени, чтобы параллельные задачи не
//! открывали их пачками в один и тот же момент. Источник случайности — за
//! trait'ом [`JitterSource`]; штатная реализация — [`SplitMix64`] с
//! внедряемым seed, поэтому тесты детерминированы. Внешний крейт не
//! используется: генератор занимает десять строк, а криптостойкость здесь
//! не нужна — значения ни от чего не защищают.

use std::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Источник псевдослучайных чисел для jitter.
pub trait JitterSource: fmt::Debug + Send {
    /// Очередное 64-битное значение.
    fn next_u64(&mut self) -> u64;
}

/// Генератор SplitMix64 (Steele, Lea, Flood, 2014): одно 64-битное слово
/// состояния, период 2^64. Не криптостойкий.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Генератор с заданным seed: одинаковый seed даёт одинаковую
    /// последовательность.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Генератор с seed из системных часов (наносекунды от эпохи Unix).
    #[must_use]
    pub fn from_clock() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since_epoch| since_epoch.as_nanos());
        // Младшие 64 бита: именно они меняются от запуска к запуску.
        Self::new(u64::try_from(nanos & u128::from(u64::MAX)).unwrap_or(0))
    }
}

impl JitterSource for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Диапазон jitter: добавка выбирается равномерно из `min..=max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JitterRange {
    /// Наименьшая добавка.
    pub min: Duration,
    /// Наибольшая добавка; значение меньше `min` трактуется как `min`.
    pub max: Duration,
}

impl JitterRange {
    /// Jitter выключен: добавка всегда нулевая.
    pub const DISABLED: Self = Self {
        min: Duration::ZERO,
        max: Duration::ZERO,
    };

    /// Диапазон от нуля до `max`.
    #[must_use]
    pub fn up_to(max: Duration) -> Self {
        Self {
            min: Duration::ZERO,
            max,
        }
    }

    /// Истина, если добавка всегда нулевая.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.min.is_zero() && self.max.is_zero()
    }
}

/// Генератор добавок из заданного диапазона.
#[derive(Debug)]
pub struct Jitter {
    range: JitterRange,
    source: Mutex<Box<dyn JitterSource>>,
}

impl Jitter {
    /// Jitter с заданным источником случайности.
    #[must_use]
    pub fn new(range: JitterRange, source: Box<dyn JitterSource>) -> Self {
        Self {
            range,
            source: Mutex::new(source),
        }
    }

    /// Jitter на [`SplitMix64`] с заданным seed.
    #[must_use]
    pub fn seeded(range: JitterRange, seed: u64) -> Self {
        Self::new(range, Box::new(SplitMix64::new(seed)))
    }

    /// Диапазон добавок.
    #[must_use]
    pub fn range(&self) -> JitterRange {
        self.range
    }

    /// Очередная добавка из диапазона. Для выключенного jitter и для
    /// диапазона из одной точки источник не опрашивается.
    #[must_use]
    pub fn next_delay(&self) -> Duration {
        let min = self.range.min;
        let max = self.range.max.max(min);
        let span = u64::try_from(max.saturating_sub(min).as_nanos()).unwrap_or(u64::MAX);
        if span == 0 {
            return min;
        }
        let random = self
            .source
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .next_u64();
        // Смещение от взятия остатка пренебрежимо: span много меньше 2^64.
        let offset = match span.checked_add(1) {
            Some(modulus) => random % modulus,
            None => random,
        };
        min.saturating_add(Duration::from_nanos(offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: u64 = 0x5EED;
    const FIFTY_MS: Duration = Duration::from_millis(50);

    #[test]
    fn splitmix_matches_reference_values() {
        // Эталон: первые значения SplitMix64 при seed 0.
        let mut generator = SplitMix64::new(0);
        assert_eq!(generator.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(generator.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(generator.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn same_seed_gives_the_same_sequence() {
        let first = Jitter::seeded(JitterRange::up_to(FIFTY_MS), SEED);
        let second = Jitter::seeded(JitterRange::up_to(FIFTY_MS), SEED);
        let other = Jitter::seeded(JitterRange::up_to(FIFTY_MS), SEED + 1);
        let a: Vec<Duration> = (0..64).map(|_| first.next_delay()).collect();
        let b: Vec<Duration> = (0..64).map(|_| second.next_delay()).collect();
        let c: Vec<Duration> = (0..64).map(|_| other.next_delay()).collect();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn delays_stay_within_the_range_and_cover_it() {
        let range = JitterRange {
            min: Duration::from_millis(10),
            max: FIFTY_MS,
        };
        let jitter = Jitter::seeded(range, SEED);
        assert_eq!(jitter.range(), range);
        let delays: Vec<Duration> = (0..10_000).map(|_| jitter.next_delay()).collect();
        assert!(
            delays
                .iter()
                .all(|delay| (range.min..=range.max).contains(delay))
        );
        // Значения не вырождены: встречаются обе половины диапазона.
        let middle = Duration::from_millis(30);
        let low = delays.iter().filter(|delay| **delay < middle).count();
        assert!((4000..=6000).contains(&low), "нижняя половина: {low}");
    }

    #[derive(Debug)]
    struct Fixed(u64);

    impl JitterSource for Fixed {
        fn next_u64(&mut self) -> u64 {
            self.0
        }
    }

    #[test]
    fn range_bounds_are_inclusive() {
        let range = JitterRange::up_to(Duration::from_nanos(9));
        // 9 по модулю 10 — верхняя граница, 10 по модулю 10 — нижняя.
        assert_eq!(
            Jitter::new(range, Box::new(Fixed(9))).next_delay(),
            Duration::from_nanos(9)
        );
        assert_eq!(
            Jitter::new(range, Box::new(Fixed(10))).next_delay(),
            Duration::ZERO
        );
    }

    #[derive(Debug)]
    struct Forbidden;

    impl JitterSource for Forbidden {
        fn next_u64(&mut self) -> u64 {
            panic!("источник не должен опрашиваться");
        }
    }

    #[test]
    fn disabled_and_degenerate_ranges_do_not_use_the_source() {
        assert!(JitterRange::DISABLED.is_disabled());
        assert!(!JitterRange::up_to(FIFTY_MS).is_disabled());

        let disabled = Jitter::new(JitterRange::DISABLED, Box::new(Forbidden));
        assert_eq!(disabled.next_delay(), Duration::ZERO);

        // max меньше min трактуется как min.
        let inverted = JitterRange {
            min: FIFTY_MS,
            max: Duration::from_millis(1),
        };
        let fixed = Jitter::new(inverted, Box::new(Forbidden));
        assert_eq!(fixed.next_delay(), FIFTY_MS);
    }

    #[test]
    fn clock_seeded_generator_produces_values() {
        let mut generator = SplitMix64::from_clock();
        let first = generator.next_u64();
        let second = generator.next_u64();
        assert_ne!(first, second);
    }
}
