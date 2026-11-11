//! Сквозной тест механизмов без сети и без цикла сканирования: поток целей
//! → разрешения → подставной «соединитель» → исходы.
//!
//! Цели — адреса двух сетей loopback. Соединений нет вовсе: «соединитель»
//! ждёт на приостановленных часах и отвечает исходом по адресу хоста.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::{Instant, sleep};

use crate::limits::{DisableReason, HostHandle, Limiter, LimitsConfig, Outcome};
use crate::targets::{TargetOptions, TargetSource, TargetStream};

/// Соединений на хост: одно пробное и одиннадцать параллельных.
const CHECKS: usize = 12;
/// Длительность одного «соединения».
const CONNECTION_TIME: Duration = Duration::from_millis(20);
/// Буфер потока целей.
const BUFFER: u64 = 16;
/// Делитель, по остатку от которого выбирается поведение хоста.
const KIND_MODULUS: u8 = 10;
/// Остаток для хостов, сбрасывающих соединения.
const RESETS_REMAINDER: u8 = 3;
/// Остаток для хостов с закрытым портом.
const CLOSED_REMAINDER: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Отвечает: успехи вперемешку со штатными отказами.
    Good,
    /// Сбрасывает каждое соединение.
    Resets,
    /// Порт закрыт.
    Closed,
}

fn kind(addr: IpAddr) -> Kind {
    let last = match addr {
        IpAddr::V4(v4) => v4.octets().last().copied().unwrap_or(0),
        IpAddr::V6(_) => 0,
    };
    match last % KIND_MODULUS {
        RESETS_REMAINDER => Kind::Resets,
        CLOSED_REMAINDER => Kind::Closed,
        _ => Kind::Good,
    }
}

/// Подставной «соединитель»: исход по адресу и номеру попытки.
fn outcome(addr: IpAddr, attempt: usize) -> Outcome {
    match kind(addr) {
        Kind::Resets => Outcome::Reset,
        Kind::Closed => Outcome::ConnectRefused,
        Kind::Good => match attempt % 3 {
            0 => Outcome::ConditionMet,
            1 => Outcome::FatalAlert,
            _ => Outcome::EofAtMessageBoundary,
        },
    }
}

#[derive(Debug, Default)]
struct Gauge {
    current: AtomicUsize,
    max: AtomicUsize,
}

impl Gauge {
    fn enter(&self) {
        let now = self
            .current
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        self.max.fetch_max(now, Ordering::SeqCst);
    }

    fn leave(&self) {
        self.current.fetch_sub(1, Ordering::SeqCst);
    }

    fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
struct HostReport {
    kind: Kind,
    connections: usize,
    not_tested: usize,
    reason: Option<DisableReason>,
    disabled: Option<DisableReason>,
    max_parallel: usize,
}

/// Одна «проверка»: разрешение → соединение → исход.
async fn check(
    host: &HostHandle,
    attempt: usize,
    global: &Gauge,
    local: &Gauge,
) -> Result<(), DisableReason> {
    let permit = host.acquire_waiting().await?;
    global.enter();
    local.enter();
    sleep(CONNECTION_TIME).await;
    local.leave();
    global.leave();
    permit.report(outcome(host.addr(), attempt));
    Ok(())
}

async fn scan_host(host: &Arc<HostHandle>, global: &Arc<Gauge>) -> HostReport {
    let local = Arc::new(Gauge::default());
    let mut results = Vec::new();
    // Первое соединение — в одиночку, как в конвейере цели: по нему
    // срабатывает ранний выход.
    results.push(check(host, 0, global, &local).await);
    let mut tasks = Vec::new();
    for attempt in 1..CHECKS {
        let host = Arc::clone(host);
        let global = Arc::clone(global);
        let local = Arc::clone(&local);
        tasks.push(tokio::spawn(async move {
            check(&host, attempt, &global, &local).await
        }));
    }
    for task in tasks {
        results.push(task.await.unwrap());
    }
    let connections = results.iter().filter(|result| result.is_ok()).count();
    HostReport {
        kind: kind(host.addr()),
        connections,
        not_tested: results.len().saturating_sub(connections),
        reason: results
            .iter()
            .find_map(|result| result.as_ref().err().copied()),
        disabled: host.disabled(),
        max_parallel: local.max(),
    }
}

#[tokio::test(start_paused = true)]
async fn stream_limits_backoff_and_breaker_work_together() {
    let config = LimitsConfig {
        max_connections: 8,
        max_connections_per_host: 2,
        max_hosts: 6,
        ..LimitsConfig::default()
    };
    let limiter = Limiter::seeded(config, 42);

    let sources = vec![
        TargetSource::Spec("127.0.0.0/24".to_owned()),
        TargetSource::Spec("127.0.1.0/26".to_owned()),
    ];
    let options = TargetOptions {
        buffer: usize::try_from(BUFFER).unwrap(),
        ..TargetOptions::default()
    };
    let mut stream = TargetStream::new(sources, options);

    let global = Arc::new(Gauge::default());
    let hosts = Arc::new(Gauge::default());
    let started = Instant::now();
    let mut tasks = Vec::new();
    let mut consumed: u64 = 0;
    while let Some(item) = stream.next().await {
        consumed = consumed.saturating_add(1);
        // Поток не уходит вперёд, пока планировщик ждёт слот хоста.
        assert!(stream.produced() <= consumed.saturating_add(BUFFER));
        let target = item.unwrap();
        assert_eq!(target.to_net().port, 443);
        assert_eq!(target.server_name(), None);
        let addr = target.connect_ip().unwrap();
        assert!(addr.is_loopback());

        let host = Arc::new(limiter.host(addr).await);
        hosts.enter();
        let global = Arc::clone(&global);
        let hosts = Arc::clone(&hosts);
        tasks.push(tokio::spawn(async move {
            let report = scan_host(&host, &global).await;
            hosts.leave();
            drop(host);
            report
        }));
    }
    assert_eq!(consumed, 320);

    let mut good = 0;
    let mut resets = 0;
    let mut closed = 0;
    let mut connections = 0;
    for task in tasks {
        let report = task.await.unwrap();
        assert!(report.max_parallel <= 2, "{report:?}");
        connections += report.connections;
        match report.kind {
            Kind::Good => {
                good += 1;
                assert_eq!(report.connections, CHECKS, "{report:?}");
                assert_eq!(report.not_tested, 0, "{report:?}");
                assert_eq!(report.disabled, None, "{report:?}");
            }
            Kind::Resets => {
                resets += 1;
                // Пять сбросов размыкают breaker, три пробных соединения
                // исчерпывают циклы; остальные проверки не выполняются.
                assert_eq!(report.connections, 8, "{report:?}");
                assert_eq!(report.not_tested, 4, "{report:?}");
                assert_eq!(report.reason, Some(DisableReason::BlockedOrDown));
                assert_eq!(report.disabled, Some(DisableReason::BlockedOrDown));
            }
            Kind::Closed => {
                closed += 1;
                // Ранний выход: ровно одно соединение.
                assert_eq!(report.connections, 1, "{report:?}");
                assert_eq!(report.not_tested, 11, "{report:?}");
                assert_eq!(report.reason, Some(DisableReason::PortClosed));
                assert_eq!(report.disabled, Some(DisableReason::PortClosed));
            }
        }
    }
    assert_eq!(good, 256);
    assert_eq!(resets, 33);
    assert_eq!(closed, 31);
    assert_eq!(connections, 256 * CHECKS + 33 * 8 + 31);

    // Лимиты соблюдены.
    assert!(global.max() <= 8, "{}", global.max());
    assert!(global.max() >= 2, "{}", global.max());
    assert_eq!(hosts.max(), 6);

    // Состояние очищено.
    assert_eq!(limiter.active_hosts(), 0);
    assert_eq!(limiter.connections_in_use(), 0);
    assert_eq!(limiter.hosts_in_use(), 0);
    assert_eq!(limiter.connection_limit(), 8);

    // Счётчики сходятся с наблюдаемым.
    let stats = limiter.stats().snapshot();
    assert_eq!(usize::try_from(stats.permits).unwrap(), connections);
    assert!(stats.denied > 0);
    assert!(stats.host_slot.hits > 0);
    assert!(stats.delay.hits > 0);

    // Паузы breaker'а шли на приостановленных часах.
    assert!(started.elapsed() > Duration::from_secs(60));
}
