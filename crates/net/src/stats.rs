//! Учёт соединений: число попыток, число открытых соединений и время connect.
//!
//! `docs/ARCHITECTURE.md`, разделы 4.1 и 8.2: счётчик живёт в
//! [`Connector`](crate::connector::Connector), а JSON-вывод несёт
//! `connections` и `duration_ms` и на проверку, и на цель. Поэтому
//! [`ConnStats`] — дерево областей: область проверки создаётся из области
//! цели методом [`ConnStats::child`], и каждое соединение учитывается в своей
//! области и во всех её предках. Вызывающий код передаёт нужную область в
//! [`Connector::connect`](crate::connector::Connector::connect) и читает её
//! через [`ConnStats::snapshot`].
//!
//! Счётчики атомарные и насыщающиеся: переполнение не приводит ни к панике,
//! ни к переходу через ноль.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Область учёта соединений; клонирование даёт ссылку на ту же область.
#[derive(Debug, Clone, Default)]
pub struct ConnStats {
    node: Arc<Node>,
}

#[derive(Debug, Default)]
struct Node {
    attempts: AtomicU64,
    connections: AtomicU64,
    connect_nanos: AtomicU64,
    parent: Option<Arc<Node>>,
}

/// Значения счётчиков области на момент вызова [`ConnStats::snapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnStatsSnapshot {
    /// Число попыток TCP-соединения, считая неудачные и попытки с каждым
    /// адресом цели.
    pub attempts: u64,
    /// Число открытых соединений.
    pub connections: u64,
    /// Суммарное время, проведённое в connect, считая неудачные попытки.
    pub connect_time: Duration,
}

impl ConnStats {
    /// Новая корневая область с нулевыми счётчиками.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Дочерняя область: всё, что учтено в ней, учитывается и в этой
    /// области, и в её предках. Соседние дочерние области независимы.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            node: Arc::new(Node {
                parent: Some(Arc::clone(&self.node)),
                ..Node::default()
            }),
        }
    }

    /// Учитывает одну попытку соединения длительностью `elapsed`;
    /// `connected` — истина, если соединение открыто.
    ///
    /// [`Connector`](crate::connector::Connector) вызывает метод сам;
    /// наружу он открыт для транспортов, которые открывают соединения в
    /// обход `Connector` (тестовые заглушки, будущие proxy).
    pub fn record_connect(&self, elapsed: Duration, connected: bool) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let mut current = Some(&self.node);
        while let Some(node) = current {
            add_saturating(&node.attempts, 1);
            if connected {
                add_saturating(&node.connections, 1);
            }
            add_saturating(&node.connect_nanos, nanos);
            current = node.parent.as_ref();
        }
    }

    /// Текущие значения счётчиков области.
    #[must_use]
    pub fn snapshot(&self) -> ConnStatsSnapshot {
        ConnStatsSnapshot {
            attempts: self.node.attempts.load(Ordering::Relaxed),
            connections: self.node.connections.load(Ordering::Relaxed),
            connect_time: Duration::from_nanos(self.node.connect_nanos.load(Ordering::Relaxed)),
        }
    }
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
        assert_eq!(ConnStats::new().snapshot(), ConnStatsSnapshot::default());
    }

    #[test]
    fn records_attempts_connections_and_time() {
        let stats = ConnStats::new();
        stats.record_connect(Duration::from_millis(30), true);
        stats.record_connect(Duration::from_millis(70), false);
        assert_eq!(
            stats.snapshot(),
            ConnStatsSnapshot {
                attempts: 2,
                connections: 1,
                connect_time: Duration::from_millis(100),
            }
        );
    }

    #[test]
    fn child_scopes_roll_up_to_every_ancestor() {
        let target = ConnStats::new();
        let check_a = target.child();
        let check_b = target.child();
        let nested = check_a.child();

        check_a.record_connect(Duration::from_millis(10), true);
        check_b.record_connect(Duration::from_millis(20), true);
        check_b.record_connect(Duration::from_millis(5), false);
        nested.record_connect(Duration::from_millis(1), true);

        assert_eq!(check_a.snapshot().connections, 2);
        assert_eq!(check_a.snapshot().attempts, 2);
        assert_eq!(check_b.snapshot().connections, 1);
        assert_eq!(check_b.snapshot().attempts, 2);
        assert_eq!(nested.snapshot().connections, 1);
        assert_eq!(
            target.snapshot(),
            ConnStatsSnapshot {
                attempts: 4,
                connections: 3,
                connect_time: Duration::from_millis(36),
            }
        );
    }

    #[test]
    fn clone_refers_to_the_same_scope() {
        let stats = ConnStats::new();
        let alias = stats.clone();
        alias.record_connect(Duration::from_millis(1), true);
        assert_eq!(stats.snapshot().connections, 1);
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let stats = ConnStats::new();
        stats.record_connect(Duration::MAX, true);
        stats.record_connect(Duration::MAX, true);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.connections, 2);
        assert_eq!(snapshot.connect_time, Duration::from_nanos(u64::MAX));
    }
}
