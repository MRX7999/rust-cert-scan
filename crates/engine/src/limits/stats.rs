//! Счётчики ожидания разрешений: сколько раз и как долго задачи упирались в
//! каждый лимит.
//!
//! Устройство повторяет [`net::ConnStats`]: область — узел дерева, запись
//! учитывается в своей области и во всех предках, счётчики атомарные и
//! насыщающиеся. Общая область живёт в
//! [`Limiter`](crate::limits::Limiter), область хоста — её потомок; так
//! будущий JSON-вывод получает ожидание и на цель, и на весь скан — рядом с
//! `connections` из `ConnStats`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Этап получения разрешения, на котором задача может ждать.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Слот параллельно сканируемых хостов.
    HostSlot,
    /// Слот соединений на хост.
    HostConnections,
    /// Токен rate limit хоста.
    HostRate,
    /// Токен глобального rate limit.
    GlobalRate,
    /// Задержка перед соединением: jitter и пауза backoff.
    Delay,
    /// Слот глобального лимита соединений.
    GlobalConnections,
}

/// Число этапов в [`Stage`].
const STAGES: usize = 6;

impl Stage {
    /// Все этапы в порядке захвата.
    pub const ALL: [Self; STAGES] = [
        Self::HostSlot,
        Self::HostConnections,
        Self::HostRate,
        Self::GlobalRate,
        Self::Delay,
        Self::GlobalConnections,
    ];

    /// Короткая метка для журналов и вывода.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::HostSlot => "host_slot",
            Self::HostConnections => "host_connections",
            Self::HostRate => "host_rate",
            Self::GlobalRate => "global_rate",
            Self::Delay => "delay",
            Self::GlobalConnections => "global_connections",
        }
    }
}

#[derive(Debug, Default)]
struct StageCounters {
    hits: AtomicU64,
    wait_nanos: AtomicU64,
}

#[derive(Debug, Default)]
struct Node {
    permits: AtomicU64,
    denied: AtomicU64,
    total_wait_nanos: AtomicU64,
    host_slot: StageCounters,
    host_connections: StageCounters,
    host_rate: StageCounters,
    global_rate: StageCounters,
    delay: StageCounters,
    global_connections: StageCounters,
    parent: Option<Arc<Node>>,
}

impl Node {
    fn stage(&self, stage: Stage) -> &StageCounters {
        match stage {
            Stage::HostSlot => &self.host_slot,
            Stage::HostConnections => &self.host_connections,
            Stage::HostRate => &self.host_rate,
            Stage::GlobalRate => &self.global_rate,
            Stage::Delay => &self.delay,
            Stage::GlobalConnections => &self.global_connections,
        }
    }
}

/// Область учёта ожидания; клонирование даёт ссылку на ту же область.
#[derive(Debug, Clone, Default)]
pub struct LimitStats {
    node: Arc<Node>,
}

/// Счётчики одного этапа.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StageSnapshot {
    /// Сколько раз задача ждала на этом этапе.
    pub hits: u64,
    /// Суммарное время ожидания на этом этапе.
    pub wait: Duration,
}

/// Значения счётчиков области на момент вызова [`LimitStats::snapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LimitStatsSnapshot {
    /// Число выданных разрешений на соединение.
    pub permits: u64,
    /// Число отказов в разрешении (breaker открыт, хост отключён).
    pub denied: u64,
    /// Суммарное время от запроса разрешения до его выдачи.
    pub total_wait: Duration,
    /// Ожидание слота параллельно сканируемых хостов.
    pub host_slot: StageSnapshot,
    /// Ожидание слота соединений на хост.
    pub host_connections: StageSnapshot,
    /// Ожидание токена rate limit хоста.
    pub host_rate: StageSnapshot,
    /// Ожидание токена глобального rate limit.
    pub global_rate: StageSnapshot,
    /// Задержки перед соединением: jitter и пауза backoff.
    pub delay: StageSnapshot,
    /// Ожидание слота глобального лимита соединений.
    pub global_connections: StageSnapshot,
}

impl LimitStatsSnapshot {
    /// Счётчики этапа `stage`.
    #[must_use]
    pub fn stage(&self, stage: Stage) -> StageSnapshot {
        match stage {
            Stage::HostSlot => self.host_slot,
            Stage::HostConnections => self.host_connections,
            Stage::HostRate => self.host_rate,
            Stage::GlobalRate => self.global_rate,
            Stage::Delay => self.delay,
            Stage::GlobalConnections => self.global_connections,
        }
    }
}

impl LimitStats {
    /// Новая корневая область с нулевыми счётчиками.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Дочерняя область: всё, что учтено в ней, учитывается и в этой
    /// области, и в её предках.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            node: Arc::new(Node {
                parent: Some(Arc::clone(&self.node)),
                ..Node::default()
            }),
        }
    }

    /// Учитывает ожидание длительностью `waited` на этапе `stage`. Вызывать
    /// только если задача действительно ждала: каждый вызов — одно
    /// срабатывание лимита.
    pub fn record_wait(&self, stage: Stage, waited: Duration) {
        let nanos = saturating_nanos(waited);
        self.for_each_node(|node| {
            let counters = node.stage(stage);
            add_saturating(&counters.hits, 1);
            add_saturating(&counters.wait_nanos, nanos);
        });
    }

    /// Учитывает выданное разрешение; `total_wait` — время от запроса до
    /// выдачи.
    pub fn record_permit(&self, total_wait: Duration) {
        let nanos = saturating_nanos(total_wait);
        self.for_each_node(|node| {
            add_saturating(&node.permits, 1);
            add_saturating(&node.total_wait_nanos, nanos);
        });
    }

    /// Учитывает отказ в разрешении.
    pub fn record_denied(&self) {
        self.for_each_node(|node| add_saturating(&node.denied, 1));
    }

    /// Текущие значения счётчиков области.
    #[must_use]
    pub fn snapshot(&self) -> LimitStatsSnapshot {
        let node = &self.node;
        LimitStatsSnapshot {
            permits: node.permits.load(Ordering::Relaxed),
            denied: node.denied.load(Ordering::Relaxed),
            total_wait: Duration::from_nanos(node.total_wait_nanos.load(Ordering::Relaxed)),
            host_slot: stage_snapshot(&node.host_slot),
            host_connections: stage_snapshot(&node.host_connections),
            host_rate: stage_snapshot(&node.host_rate),
            global_rate: stage_snapshot(&node.global_rate),
            delay: stage_snapshot(&node.delay),
            global_connections: stage_snapshot(&node.global_connections),
        }
    }

    fn for_each_node(&self, mut apply: impl FnMut(&Node)) {
        let mut current = Some(&self.node);
        while let Some(node) = current {
            apply(node);
            current = node.parent.as_ref();
        }
    }
}

fn stage_snapshot(counters: &StageCounters) -> StageSnapshot {
    StageSnapshot {
        hits: counters.hits.load(Ordering::Relaxed),
        wait: Duration::from_nanos(counters.wait_nanos.load(Ordering::Relaxed)),
    }
}

fn saturating_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Прибавляет `value` к счётчику, останавливаясь на `u64::MAX`.
fn add_saturating(counter: &AtomicU64, value: u64) {
    // Замыкание всегда возвращает `Some`, поэтому `try_update` не может
    // вернуть ошибку; результат — прежнее значение, оно не нужно.
    let _previous = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_scope_is_empty() {
        assert_eq!(LimitStats::new().snapshot(), LimitStatsSnapshot::default());
    }

    #[test]
    fn waits_are_counted_per_stage() {
        let stats = LimitStats::new();
        for (position, stage) in Stage::ALL.into_iter().enumerate() {
            let millis = u64::try_from(position).unwrap() + 1;
            stats.record_wait(stage, Duration::from_millis(millis));
            stats.record_wait(stage, Duration::from_millis(millis));
        }
        let snapshot = stats.snapshot();
        for (position, stage) in Stage::ALL.into_iter().enumerate() {
            let millis = u64::try_from(position).unwrap() + 1;
            assert_eq!(
                snapshot.stage(stage),
                StageSnapshot {
                    hits: 2,
                    wait: Duration::from_millis(millis * 2),
                },
                "{}",
                stage.label()
            );
        }
        assert_eq!(snapshot.permits, 0);
        assert_eq!(snapshot.total_wait, Duration::ZERO);
    }

    #[test]
    fn labels_are_distinct() {
        let mut labels: Vec<&str> = Stage::ALL.into_iter().map(Stage::label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), STAGES);
    }

    #[test]
    fn child_scopes_roll_up_to_every_ancestor() {
        let scan = LimitStats::new();
        let host_a = scan.child();
        let host_b = scan.child();

        host_a.record_wait(Stage::HostRate, Duration::from_millis(100));
        host_a.record_permit(Duration::from_millis(100));
        host_b.record_wait(Stage::GlobalConnections, Duration::from_millis(30));
        host_b.record_permit(Duration::from_millis(30));
        host_b.record_permit(Duration::ZERO);
        host_b.record_denied();

        assert_eq!(host_a.snapshot().permits, 1);
        assert_eq!(host_a.snapshot().host_rate.hits, 1);
        assert_eq!(host_a.snapshot().global_connections.hits, 0);
        assert_eq!(host_b.snapshot().permits, 2);
        assert_eq!(host_b.snapshot().denied, 1);

        let total = scan.snapshot();
        assert_eq!(total.permits, 3);
        assert_eq!(total.denied, 1);
        assert_eq!(total.total_wait, Duration::from_millis(130));
        assert_eq!(total.host_rate.wait, Duration::from_millis(100));
        assert_eq!(total.global_connections.wait, Duration::from_millis(30));
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let stats = LimitStats::new();
        stats.record_permit(Duration::MAX);
        stats.record_permit(Duration::MAX);
        stats.record_wait(Stage::Delay, Duration::MAX);
        stats.record_wait(Stage::Delay, Duration::MAX);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.permits, 2);
        assert_eq!(snapshot.total_wait, Duration::from_nanos(u64::MAX));
        assert_eq!(snapshot.delay.hits, 2);
        assert_eq!(snapshot.delay.wait, Duration::from_nanos(u64::MAX));
    }
}
