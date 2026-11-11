//! Память об отключённых и приостановленных хостах.
//!
//! Состояние хоста в [`HostTable`](super::semaphores::HostTable) живёт,
//! пока с адресом идёт работа, и удаляется вместе с последней ссылкой. Без
//! памяти следующая цель на тот же адрес начинала бы с чистого листа и
//! заново тратила соединения и паузы на хост, уже признанный недоступным
//! или блокирующим.
//!
//! # Что запоминается
//!
//! [`BreakerMemo`] — снимок breaker'а в момент изменения его состояния:
//!
//! - отключение с причиной уровня хоста
//!   ([`DisableReason::is_host_wide`](super::breaker::DisableReason::is_host_wide)),
//!   то есть `blocked_or_down`. Срок жизни записи —
//!   [`MemoryConfig::disabled_ttl`];
//! - размыкание с неистёкшей паузой и числом циклов. Запись живёт до конца
//!   паузы, но не дольше [`MemoryConfig::disabled_ttl`].
//!
//! # Что не запоминается и почему
//!
//! - Причины `unreachable` (закрытый порт), `not_tls` и `unresolved`: ключ
//!   состояния — IP-адрес без порта и имени (`docs/DECISIONS.md`, D-18), а
//!   эти причины относятся к порту или имени. Запомнить их на адрес значило
//!   бы отказать цели на другом порту того же адреса.
//! - Сниженные AIMD лимиты и задержка: один сигнал перегрузки бывает у
//!   значительной доли целей, и такие записи вытесняли бы из ограниченной
//!   памяти записи об отключённых хостах. Новая цель начинает с настроенных
//!   лимитов; если хост по-прежнему перегружен, AIMD снижает их с первого
//!   же сигнала.
//!
//! # Размер
//!
//! Записей не больше [`MemoryConfig::capacity`]. При переполнении
//! вытесняется запись, сделанная раньше всех: срок жизни записей об
//! отключении одинаков, поэтому она же истекает первой. Порядок записи
//! хранится в очереди с ленивым удалением: устаревшие элементы очереди
//! пропускаются при вытеснении, а сама очередь уплотняется, когда вырастает
//! больше удвоенной ёмкости. Память не растёт с числом целей.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

use super::breaker::BreakerMemo;

/// Число запоминаемых адресов по умолчанию (предварительное значение,
/// `docs/DECISIONS.md`).
pub const DEFAULT_MEMORY_CAPACITY: usize = 4096;

/// Срок жизни записи об отключении по умолчанию (предварительное значение,
/// `docs/DECISIONS.md`).
pub const DEFAULT_DISABLED_TTL: Duration = Duration::from_secs(600);

/// Запас очереди порядка сверх удвоенной ёмкости, после которого очередь
/// уплотняется.
const ORDER_SLACK: usize = 16;

/// Параметры памяти об отключённых хостах.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryConfig {
    /// Наибольшее число запоминаемых адресов; ноль выключает память.
    pub capacity: usize,
    /// Срок жизни записи об отключении; он же ограничивает сверху срок
    /// жизни записи о паузе. Ноль выключает память.
    pub disabled_ttl: Duration,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_MEMORY_CAPACITY,
            disabled_ttl: DEFAULT_DISABLED_TTL,
        }
    }
}

impl MemoryConfig {
    /// Память выключена: ничего не запоминается.
    pub const DISABLED: Self = Self {
        capacity: 0,
        disabled_ttl: Duration::ZERO,
    };
}

/// Запись памяти, действующая на момент запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Remembered {
    /// Что запомнено.
    pub memo: BreakerMemo,
    /// Момент, когда хост перешёл в это состояние.
    pub at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    memo: BreakerMemo,
    at: Instant,
    expires: Instant,
    /// Номер записи: по нему элемент очереди порядка сверяется с таблицей.
    seq: u64,
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<IpAddr, Entry>,
    /// Порядок записи; элемент действителен, если номер совпадает с
    /// номером записи в таблице.
    order: VecDeque<(u64, IpAddr)>,
    next_seq: u64,
    evicted: u64,
}

impl Inner {
    /// Вытесняет запись, сделанную раньше всех.
    fn evict_oldest(&mut self) {
        while let Some((seq, addr)) = self.order.pop_front() {
            let current = self.map.get(&addr).is_some_and(|entry| entry.seq == seq);
            if current {
                self.map.remove(&addr);
                self.evicted = self.evicted.saturating_add(1);
                return;
            }
        }
    }

    /// Убирает из очереди элементы, которым не соответствует запись.
    fn compact(&mut self) {
        let map = &self.map;
        self.order
            .retain(|(seq, addr)| map.get(addr).is_some_and(|entry| entry.seq == *seq));
    }
}

/// Ограниченная память об отключённых и приостановленных хостах; описание —
/// в документации модуля.
#[derive(Debug)]
pub struct HostMemory {
    config: MemoryConfig,
    inner: Mutex<Inner>,
}

impl HostMemory {
    /// Пустая память с заданными параметрами.
    #[must_use]
    pub fn new(config: MemoryConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Параметры памяти.
    #[must_use]
    pub fn config(&self) -> &MemoryConfig {
        &self.config
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        // Под замком нет кода, способного паниковать посреди изменения.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Истина, если память выключена конфигурацией.
    fn is_off(&self) -> bool {
        self.config.capacity == 0 || self.config.disabled_ttl.is_zero()
    }

    /// Запоминает состояние хоста `addr` на момент `now`, заменяя прежнюю
    /// запись. Запись с уже истёкшим сроком (пауза закончилась) не
    /// создаётся, а прежняя удаляется.
    pub fn remember(&self, addr: IpAddr, memo: BreakerMemo, now: Instant) {
        if self.is_off() {
            return;
        }
        let ttl_end = now.checked_add(self.config.disabled_ttl).unwrap_or(now);
        let expires = match memo {
            BreakerMemo::Disabled(_) => ttl_end,
            BreakerMemo::Open { until, .. } => until.min(ttl_end),
        };
        let mut inner = self.inner();
        if expires <= now {
            inner.map.remove(&addr);
            return;
        }
        let seq = inner.next_seq;
        inner.next_seq = inner.next_seq.wrapping_add(1);
        let entry = Entry {
            memo,
            at: now,
            expires,
            seq,
        };
        let is_new = inner.map.insert(addr, entry).is_none();
        inner.order.push_back((seq, addr));
        if is_new {
            while inner.map.len() > self.config.capacity {
                inner.evict_oldest();
            }
        }
        let order_limit = self
            .config
            .capacity
            .saturating_mul(2)
            .saturating_add(ORDER_SLACK);
        if inner.order.len() > order_limit {
            inner.compact();
        }
    }

    /// Удаляет запись о хосте: его состояние больше не требует памяти
    /// (breaker замкнулся).
    pub fn forget(&self, addr: IpAddr) {
        if self.is_off() {
            return;
        }
        self.inner().map.remove(&addr);
    }

    /// Запись о хосте `addr`, действующая в момент `now`. Истёкшая запись
    /// удаляется.
    #[must_use]
    pub fn lookup(&self, addr: IpAddr, now: Instant) -> Option<Remembered> {
        if self.is_off() {
            return None;
        }
        let mut inner = self.inner();
        let entry = inner.map.get(&addr).copied()?;
        if entry.expires <= now {
            inner.map.remove(&addr);
            return None;
        }
        Some(Remembered {
            memo: entry.memo,
            at: entry.at,
        })
    }

    /// Число хранимых записей, считая истёкшие, но ещё не удалённые.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner().map.len()
    }

    /// Истина, если записей нет.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner().map.is_empty()
    }

    /// Сколько записей вытеснено из-за переполнения.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.inner().evicted
    }

    /// Длина очереди порядка: для проверки, что она не растёт.
    #[cfg(test)]
    fn order_len(&self) -> usize {
        self.inner().order.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::breaker::DisableReason;
    use std::net::Ipv4Addr;

    const BLOCKED: BreakerMemo = BreakerMemo::Disabled(DisableReason::BlockedOrDown);
    const BASE: u32 = 0x0A00_0000;

    fn ip(index: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(BASE.wrapping_add(index)))
    }

    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn memory(capacity: usize, ttl_secs: u64) -> HostMemory {
        HostMemory::new(MemoryConfig {
            capacity,
            disabled_ttl: secs(ttl_secs),
        })
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let config = MemoryConfig::default();
        assert_eq!(config.capacity, 4096);
        assert_eq!(config.disabled_ttl, secs(600));
        assert_eq!(MemoryConfig::DISABLED.capacity, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_host_is_remembered_until_the_ttl_ends() {
        let memory = memory(8, 600);
        let start = Instant::now();
        assert_eq!(memory.lookup(ip(1), start), None);

        memory.remember(ip(1), BLOCKED, start);
        let expected = Some(Remembered {
            memo: BLOCKED,
            at: start,
        });
        assert_eq!(memory.lookup(ip(1), start), expected);
        assert_eq!(memory.lookup(ip(1), start + secs(599)), expected);
        assert_eq!(memory.lookup(ip(2), start), None);
        assert_eq!(memory.len(), 1);

        // Срок истёк: запись удаляется при обращении.
        assert_eq!(memory.lookup(ip(1), start + secs(600)), None);
        assert!(memory.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn pause_is_remembered_until_it_ends_but_not_longer_than_the_ttl() {
        let memory = memory(8, 30);
        let start = Instant::now();
        let pause = BreakerMemo::Open {
            until: start + secs(10),
            cycles: 2,
        };
        memory.remember(ip(1), pause, start);
        assert_eq!(
            memory
                .lookup(ip(1), start + secs(9))
                .map(|found| found.memo),
            Some(pause)
        );
        assert_eq!(memory.lookup(ip(1), start + secs(10)), None);

        // Пауза длиннее срока жизни ограничена им.
        let long = BreakerMemo::Open {
            until: start + secs(60),
            cycles: 3,
        };
        memory.remember(ip(2), long, start);
        assert!(memory.lookup(ip(2), start + secs(29)).is_some());
        assert_eq!(memory.lookup(ip(2), start + secs(30)), None);

        // Уже истёкшая пауза не запоминается и стирает прежнюю запись.
        memory.remember(ip(3), BLOCKED, start);
        let ended = BreakerMemo::Open {
            until: start,
            cycles: 1,
        };
        memory.remember(ip(3), ended, start + secs(1));
        assert_eq!(memory.lookup(ip(3), start + secs(1)), None);
    }

    #[tokio::test(start_paused = true)]
    async fn newer_record_replaces_the_older_one_and_forget_removes_it() {
        let memory = memory(8, 600);
        let start = Instant::now();
        let pause = BreakerMemo::Open {
            until: start + secs(5),
            cycles: 1,
        };
        memory.remember(ip(1), pause, start);
        memory.remember(ip(1), BLOCKED, start + secs(2));
        assert_eq!(
            memory.lookup(ip(1), start + secs(100)),
            Some(Remembered {
                memo: BLOCKED,
                at: start + secs(2),
            })
        );
        assert_eq!(memory.len(), 1);

        memory.forget(ip(1));
        assert_eq!(memory.lookup(ip(1), start + secs(100)), None);
        memory.forget(ip(1));
        assert!(memory.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn switched_off_memory_keeps_nothing() {
        let start = Instant::now();
        for memory in [
            HostMemory::new(MemoryConfig::DISABLED),
            memory(0, 600),
            memory(8, 0),
        ] {
            memory.remember(ip(1), BLOCKED, start);
            assert_eq!(memory.lookup(ip(1), start), None);
            assert!(memory.is_empty());
            memory.forget(ip(1));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn oldest_record_is_evicted_when_the_memory_is_full() {
        let memory = memory(3, 600);
        let start = Instant::now();
        for index in 1..=3 {
            memory.remember(ip(index), BLOCKED, start);
        }
        assert_eq!(memory.evicted(), 0);

        // Обновление существующей записи никого не вытесняет, но делает её
        // самой свежей.
        memory.remember(ip(1), BLOCKED, start + secs(1));
        assert_eq!(memory.len(), 3);
        assert_eq!(memory.evicted(), 0);

        memory.remember(ip(4), BLOCKED, start + secs(2));
        assert_eq!(memory.len(), 3);
        assert_eq!(memory.evicted(), 1);
        assert_eq!(memory.lookup(ip(2), start + secs(2)), None, "вытеснена");
        for index in (1..=4).filter(|index| *index != 2) {
            assert!(memory.lookup(ip(index), start + secs(2)).is_some());
        }

        memory.remember(ip(5), BLOCKED, start + secs(3));
        assert_eq!(memory.lookup(ip(3), start + secs(3)), None, "вытеснена");
        assert_eq!(memory.evicted(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn memory_does_not_grow_with_a_million_targets() {
        const CAPACITY: usize = 256;
        const TARGETS: u32 = 1_000_000;

        let memory = memory(CAPACITY, 600);
        let start = Instant::now();
        let mut peak = 0_usize;
        let mut peak_order = 0_usize;
        for index in 0..TARGETS {
            memory.remember(ip(index), BLOCKED, start);
            peak = peak.max(memory.len());
            peak_order = peak_order.max(memory.order_len());
        }
        assert_eq!(peak, CAPACITY);
        assert!(peak_order <= CAPACITY * 2 + ORDER_SLACK + 1, "{peak_order}");
        assert_eq!(memory.len(), CAPACITY);
        let expected_evictions = u64::from(TARGETS) - u64::try_from(CAPACITY).unwrap();
        assert_eq!(memory.evicted(), expected_evictions);

        // В памяти остались последние адреса.
        assert!(memory.lookup(ip(TARGETS - 1), start).is_some());
        assert_eq!(memory.lookup(ip(0), start), None);
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_updates_of_one_host_do_not_grow_the_order_queue() {
        const CAPACITY: usize = 8;

        let memory = memory(CAPACITY, 600);
        let start = Instant::now();
        for round in 0..100_000_u64 {
            let pause = BreakerMemo::Open {
                until: start + secs(round + 10),
                cycles: 1,
            };
            memory.remember(ip(1), pause, start + secs(round));
            assert!(memory.order_len() <= CAPACITY * 2 + ORDER_SLACK + 1);
        }
        assert_eq!(memory.len(), 1);
        assert_eq!(memory.evicted(), 0);
    }
}
