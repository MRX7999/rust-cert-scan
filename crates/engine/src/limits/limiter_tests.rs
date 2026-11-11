//! Тесты [`Limiter`]: все на приостановленных часах tokio, без сети.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::{Instant, sleep, timeout};

use super::backoff::{Effective, Outcome};
use super::breaker::{BreakerConfig, BreakerState, DisableReason, Reaction};
use super::jitter::JitterRange;
use super::limiter::{Denied, Limiter, LimitsConfig, UNLIMITED};
use super::stats::StageSnapshot;
use super::token_bucket::Rate;

const SEED: u64 = 7;

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
}

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

fn secs(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}

/// Конфигурация без единого ограничения: тест включает только то, что
/// проверяет.
fn open_config() -> LimitsConfig {
    LimitsConfig {
        max_connections: UNLIMITED,
        max_connections_per_host: UNLIMITED,
        max_hosts: UNLIMITED,
        rate: Rate::Unlimited,
        burst: 1,
        rate_per_host: Rate::Unlimited,
        burst_per_host: 1,
        jitter: JitterRange::DISABLED,
        ..LimitsConfig::default()
    }
}

fn limiter(config: LimitsConfig) -> Limiter {
    Limiter::seeded(config, SEED)
}

/// Счётчик одновременно удерживаемых разрешений с максимумом.
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

#[test]
fn defaults_follow_the_decisions() {
    let config = LimitsConfig::default();
    assert_eq!(config.max_connections, 64);
    assert_eq!(config.max_connections_per_host, 2);
    assert_eq!(config.max_hosts, 16);
    assert_eq!(config.rate, Rate::per_second(200));
    assert_eq!(config.rate_per_host, Rate::per_second(10));
    assert_eq!(config.jitter, JitterRange::up_to(ms(50)));

    let gentle = LimitsConfig::gentle();
    assert_eq!(gentle.max_connections_per_host, 1);
    assert_eq!(gentle.max_connections, config.max_connections);
    assert_eq!(gentle.max_hosts, config.max_hosts);
}

#[tokio::test(start_paused = true)]
async fn unlimited_configuration_never_waits() {
    let limiter = limiter(open_config());
    let host = limiter.host(ip(1)).await;
    let started = Instant::now();
    let mut permits = Vec::new();
    for _ in 0..100 {
        permits.push(host.acquire().await.unwrap());
    }
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(limiter.connections_in_use(), 100);
    drop(permits);
    assert_eq!(limiter.connections_in_use(), 0);
}

#[tokio::test(start_paused = true)]
async fn global_limit_caps_connections_across_hosts() {
    let limiter = limiter(LimitsConfig {
        max_connections: 3,
        ..open_config()
    });
    let gauge = Arc::new(Gauge::default());
    let mut tasks = Vec::new();
    for n in 1..=40 {
        let limiter = limiter.clone();
        let gauge = Arc::clone(&gauge);
        tasks.push(tokio::spawn(async move {
            let permit = limiter.acquire(ip(n)).await.unwrap();
            gauge.enter();
            sleep(ms(10)).await;
            gauge.leave();
            drop(permit);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(gauge.max(), 3);
    assert_eq!(limiter.connections_in_use(), 0);
}

#[tokio::test(start_paused = true)]
async fn host_limit_caps_connections_to_one_address() {
    let limiter = limiter(LimitsConfig {
        max_connections_per_host: 2,
        ..open_config()
    });
    let host = Arc::new(limiter.host(ip(1)).await);
    let gauge = Arc::new(Gauge::default());
    let mut tasks = Vec::new();
    for _ in 0..30 {
        let host = Arc::clone(&host);
        let gauge = Arc::clone(&gauge);
        tasks.push(tokio::spawn(async move {
            let permit = host.acquire().await.unwrap();
            gauge.enter();
            sleep(ms(10)).await;
            gauge.leave();
            drop(permit);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(gauge.max(), 2);
}

#[tokio::test(start_paused = true)]
async fn names_on_one_address_share_the_host_limit() {
    let limiter = limiter(LimitsConfig {
        max_connections_per_host: 1,
        ..open_config()
    });
    // Две цели (два имени) на одном адресе.
    let first = limiter.host(ip(1)).await;
    let second = limiter.host(ip(1)).await;
    assert_eq!(limiter.active_hosts(), 1);
    assert_eq!(limiter.hosts_in_use(), 2);

    let permit = first.acquire().await.unwrap();
    assert!(timeout(secs(1), second.acquire()).await.is_err());
    drop(permit);
    assert!(second.acquire().await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn host_slots_cap_hosts_scanned_in_parallel() {
    let limiter = limiter(LimitsConfig {
        max_hosts: 2,
        ..open_config()
    });
    let gauge = Arc::new(Gauge::default());
    let mut tasks = Vec::new();
    for n in 1..=10 {
        let limiter = limiter.clone();
        let gauge = Arc::clone(&gauge);
        tasks.push(tokio::spawn(async move {
            let host = limiter.host(ip(n)).await;
            gauge.enter();
            sleep(ms(10)).await;
            gauge.leave();
            drop(host);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(gauge.max(), 2);
    assert_eq!(limiter.hosts_in_use(), 0);
}

#[tokio::test(start_paused = true)]
async fn one_shot_permit_holds_the_host_slot() {
    let limiter = limiter(LimitsConfig {
        max_hosts: 1,
        ..open_config()
    });
    let permit = limiter.acquire(ip(1)).await.unwrap();
    assert_eq!(permit.addr(), ip(1));
    assert_eq!(limiter.hosts_in_use(), 1);
    assert!(timeout(secs(1), limiter.host(ip(2))).await.is_err());
    drop(permit);
    assert_eq!(limiter.hosts_in_use(), 0);
    assert_eq!(limiter.active_hosts(), 0);
}

#[tokio::test(start_paused = true)]
async fn all_levels_hold_together_with_a_thousand_tasks() {
    const HOSTS: u8 = 50;
    const PER_HOST: usize = 20;

    let limiter = limiter(LimitsConfig {
        max_connections: 5,
        max_connections_per_host: 2,
        max_hosts: 4,
        ..open_config()
    });
    let global = Arc::new(Gauge::default());
    let hosts = Arc::new(Gauge::default());
    let mut tasks = Vec::new();
    for n in 1..=HOSTS {
        let limiter = limiter.clone();
        let global = Arc::clone(&global);
        let hosts = Arc::clone(&hosts);
        tasks.push(tokio::spawn(async move {
            let host = Arc::new(limiter.host(ip(n)).await);
            hosts.enter();
            let per_host = Arc::new(Gauge::default());
            let mut connections = Vec::new();
            for _ in 0..PER_HOST {
                let host = Arc::clone(&host);
                let global = Arc::clone(&global);
                let per_host = Arc::clone(&per_host);
                connections.push(tokio::spawn(async move {
                    let permit = host.acquire().await.unwrap();
                    global.enter();
                    per_host.enter();
                    sleep(ms(10)).await;
                    per_host.leave();
                    global.leave();
                    permit.report(Outcome::ConditionMet);
                }));
            }
            for connection in connections {
                connection.await.unwrap();
            }
            hosts.leave();
            per_host.max()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 2);
    }
    assert_eq!(global.max(), 5);
    assert_eq!(hosts.max(), 4);
    assert_eq!(limiter.connections_in_use(), 0);
    assert_eq!(limiter.hosts_in_use(), 0);
    assert_eq!(limiter.active_hosts(), 0);
    assert_eq!(limiter.stats().snapshot().permits, 1000);
}

/// Моменты выдачи `count` разрешений, запрошенных одновременно для разных
/// хостов.
async fn grant_times(limiter: &Limiter, count: u8) -> Vec<Duration> {
    let started = Instant::now();
    let mut tasks = Vec::new();
    for n in 1..=count {
        let limiter = limiter.clone();
        tasks.push(tokio::spawn(async move {
            let permit = limiter.acquire(ip(n)).await.unwrap();
            let at = started.elapsed();
            drop(permit);
            at
        }));
    }
    let mut times = Vec::new();
    for task in tasks {
        times.push(task.await.unwrap());
    }
    times
}

fn granted_before(times: &[Duration], limit: Duration) -> usize {
    times.iter().filter(|at| **at < limit).count()
}

#[tokio::test(start_paused = true)]
async fn global_rate_limits_permits_per_second() {
    let limiter = limiter(LimitsConfig {
        rate: Rate::per_second(10),
        burst: 1,
        ..open_config()
    });
    let times = grant_times(&limiter, 30).await;
    assert_eq!(granted_before(&times, secs(1)), 10);
    assert_eq!(granted_before(&times, secs(2)), 20);
    assert_eq!(times.iter().max().copied(), Some(ms(2900)));
}

#[tokio::test(start_paused = true)]
async fn global_burst_is_granted_at_once() {
    let limiter = limiter(LimitsConfig {
        rate: Rate::per_second(10),
        burst: 5,
        ..open_config()
    });
    let times = grant_times(&limiter, 30).await;
    assert_eq!(granted_before(&times, ms(1)), 5);
    // Не больше burst + rate за секунду: пять сразу и по одному каждые
    // 100 мс.
    assert_eq!(granted_before(&times, secs(1)), 14);
}

#[tokio::test(start_paused = true)]
async fn host_rate_is_counted_per_address() {
    let limiter = limiter(LimitsConfig {
        rate_per_host: Rate::per_second(2),
        burst_per_host: 1,
        ..open_config()
    });
    let started = Instant::now();
    let mut tasks = Vec::new();
    for n in 1..=2 {
        let limiter = limiter.clone();
        tasks.push(tokio::spawn(async move {
            let host = limiter.host(ip(n)).await;
            let mut times = Vec::new();
            for _ in 0..5 {
                let permit = host.acquire().await.unwrap();
                times.push(started.elapsed());
                drop(permit);
            }
            times
        }));
    }
    for task in tasks {
        let times = task.await.unwrap();
        assert_eq!(granted_before(&times, secs(1)), 2);
        assert_eq!(granted_before(&times, secs(2)), 4);
        assert_eq!(times.last().copied(), Some(secs(2)));
    }
}

#[tokio::test(start_paused = true)]
async fn jitter_stays_in_range_and_is_reproducible() {
    let config = LimitsConfig {
        jitter: JitterRange {
            min: ms(10),
            max: ms(30),
        },
        ..open_config()
    };
    let mut runs = Vec::new();
    for _ in 0..2 {
        let limiter = Limiter::seeded(config, SEED);
        let host = limiter.host(ip(1)).await;
        let mut delays = Vec::new();
        for _ in 0..50 {
            let permit = host.acquire().await.unwrap();
            delays.push(permit.waited());
        }
        assert!(
            delays
                .iter()
                .all(|delay| *delay >= ms(10) && *delay <= ms(30))
        );
        let first = delays.first().copied();
        assert!(delays.iter().any(|delay| Some(*delay) != first));
        assert_eq!(limiter.stats().snapshot().delay.hits, 50);
        runs.push(delays);
    }
    assert_eq!(runs.first(), runs.last());

    let other = Limiter::seeded(config, SEED.wrapping_add(1));
    let host = other.host(ip(1)).await;
    let mut delays = Vec::new();
    for _ in 0..50 {
        delays.push(host.acquire().await.unwrap().waited());
    }
    assert_ne!(runs.first(), Some(&delays));
}

#[tokio::test(start_paused = true)]
async fn cancelled_wait_for_a_host_slot_leaks_nothing() {
    let limiter = limiter(LimitsConfig {
        max_hosts: 1,
        ..open_config()
    });
    let first = limiter.host(ip(1)).await;
    assert!(timeout(secs(1), limiter.host(ip(2))).await.is_err());
    assert_eq!(limiter.hosts_in_use(), 1);
    assert_eq!(limiter.active_hosts(), 1);
    drop(first);
    assert_eq!(limiter.hosts_in_use(), 0);

    let started = Instant::now();
    let second = limiter.host(ip(2)).await;
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(second.addr(), ip(2));
}

#[tokio::test(start_paused = true)]
async fn cancelled_wait_for_a_host_connection_leaks_nothing() {
    let limiter = limiter(LimitsConfig {
        max_connections_per_host: 1,
        ..open_config()
    });
    let host = limiter.host(ip(1)).await;
    let permit = host.acquire().await.unwrap();
    assert!(timeout(secs(1), host.acquire()).await.is_err());
    assert_eq!(limiter.connections_in_use(), 1);
    drop(permit);
    assert_eq!(limiter.connections_in_use(), 0);

    let started = Instant::now();
    let permit = host.acquire().await.unwrap();
    assert_eq!(started.elapsed(), Duration::ZERO);
    drop(permit);
}

#[tokio::test(start_paused = true)]
async fn cancelled_wait_for_a_host_token_consumes_nothing() {
    let limiter = limiter(LimitsConfig {
        rate_per_host: Rate::per_second(1),
        burst_per_host: 1,
        ..open_config()
    });
    let host = limiter.host(ip(1)).await;
    let started = Instant::now();
    drop(host.acquire().await.unwrap());
    assert!(timeout(ms(500), host.acquire()).await.is_err());
    assert_eq!(limiter.connections_in_use(), 0);

    // Токен не потерян и лишний не выдан: следующие — ровно через секунду.
    drop(host.acquire().await.unwrap());
    assert_eq!(started.elapsed(), secs(1));
    drop(host.acquire().await.unwrap());
    assert_eq!(started.elapsed(), secs(2));
}

#[tokio::test(start_paused = true)]
async fn cancelled_wait_for_a_global_token_refunds_the_host_token() {
    let limiter = limiter(LimitsConfig {
        rate: Rate::per_second(1),
        burst: 1,
        // Один токен хоста за десять секунд: потерянный токен был бы
        // заметен.
        rate_per_host: Rate::MilliPerSecond(100),
        burst_per_host: 1,
        ..open_config()
    });
    let first = limiter.host(ip(1)).await;
    let second = limiter.host(ip(2)).await;
    let started = Instant::now();
    drop(first.acquire().await.unwrap());

    // Токен второго хоста взят, глобального нет: ожидание сброшено.
    assert!(timeout(ms(500), second.acquire()).await.is_err());

    drop(second.acquire().await.unwrap());
    assert_eq!(started.elapsed(), secs(1));
}

#[tokio::test(start_paused = true)]
async fn cancelled_delay_refunds_both_tokens() {
    let limiter = limiter(LimitsConfig {
        rate: Rate::MilliPerSecond(100),
        burst: 1,
        rate_per_host: Rate::MilliPerSecond(100),
        burst_per_host: 1,
        jitter: JitterRange {
            min: ms(100),
            max: ms(100),
        },
        ..open_config()
    });
    let host = limiter.host(ip(1)).await;
    let started = Instant::now();
    assert!(timeout(ms(50), host.acquire()).await.is_err());

    // Оба токена возвращены: ждать приходится только задержку.
    drop(host.acquire().await.unwrap());
    assert_eq!(started.elapsed(), ms(150));
}

#[tokio::test(start_paused = true)]
async fn cancelled_wait_for_a_global_slot_leaks_nothing() {
    let limiter = limiter(LimitsConfig {
        max_connections: 1,
        rate_per_host: Rate::MilliPerSecond(100),
        burst_per_host: 1,
        ..open_config()
    });
    let first = limiter.host(ip(1)).await;
    let second = limiter.host(ip(2)).await;
    let started = Instant::now();
    let held = first.acquire().await.unwrap();

    assert!(timeout(secs(1), second.acquire()).await.is_err());
    assert_eq!(limiter.connections_in_use(), 1);
    drop(held);
    assert_eq!(limiter.connections_in_use(), 0);

    // Слот соединений второго хоста свободен, его токен возвращён.
    let permit = second.acquire().await.unwrap();
    assert_eq!(started.elapsed(), secs(1));
    assert_eq!(limiter.connections_in_use(), 1);
    drop(permit);
}

#[tokio::test(start_paused = true)]
async fn cancelled_or_dropped_probe_goes_to_the_next_caller() {
    let limiter = limiter(LimitsConfig {
        jitter: JitterRange {
            min: ms(100),
            max: ms(100),
        },
        breaker: BreakerConfig {
            failure_threshold: 1,
            ..BreakerConfig::default()
        },
        ..open_config()
    });
    let host = limiter.host(ip(1)).await;
    let permit = host.acquire().await.unwrap();
    assert_eq!(permit.report(Outcome::Reset), Reaction::Slow);
    assert_eq!(host.breaker_state(), BreakerState::Open);
    sleep(secs(5)).await;

    // Пробное соединение выдано и сброшено во время задержки.
    assert!(timeout(ms(50), host.acquire()).await.is_err());
    assert_eq!(host.breaker_state(), BreakerState::HalfOpen);

    let probe = host.acquire().await.unwrap();
    assert!(probe.is_probe());
    let busy = host.acquire().await;
    assert!(matches!(busy, Err(Denied::Wait(pause)) if pause == ms(250)));

    // Разрешение сброшено без исхода: пробное соединение возвращается.
    drop(probe);
    let probe = host.acquire().await.unwrap();
    assert!(probe.is_probe());
    assert_eq!(probe.report(Outcome::ConditionMet), Reaction::Recover);
    assert_eq!(host.breaker_state(), BreakerState::Closed);
}

#[tokio::test(start_paused = true)]
async fn busy_host_does_not_starve_another_host() {
    let limiter = limiter(LimitsConfig {
        max_connections: 2,
        max_connections_per_host: 2,
        ..open_config()
    });
    let started = Instant::now();
    let busy = Arc::new(limiter.host(ip(1)).await);
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let busy = Arc::clone(&busy);
        tasks.push(tokio::spawn(async move {
            let permit = busy.acquire().await.unwrap();
            sleep(ms(10)).await;
            drop(permit);
        }));
    }
    let other = {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            sleep(ms(1)).await;
            let permit = limiter.acquire(ip(2)).await.unwrap();
            let at = started.elapsed();
            drop(permit);
            at
        })
    };
    // Второй хост получает первый же освободившийся слот, хотя у первого
    // в очереди ещё восемнадцать задач.
    assert_eq!(other.await.unwrap(), ms(10));
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(started.elapsed(), ms(100));
}

#[tokio::test(start_paused = true)]
async fn host_state_is_removed_when_the_host_is_finished() {
    let limiter = limiter(open_config());
    for n in 1..=200 {
        let host = limiter.host(ip(n)).await;
        let permit = host.acquire().await.unwrap();
        assert_eq!(limiter.active_hosts(), 1);
        permit.report(Outcome::ConditionMet);
        drop(host);
        assert_eq!(limiter.active_hosts(), 0);
    }

    // Состояние живёт, пока есть хотя бы одно разрешение.
    let host = limiter.host(ip(1)).await;
    let permit = host.acquire().await.unwrap();
    drop(host);
    assert_eq!(limiter.active_hosts(), 1);
    assert_eq!(limiter.hosts_in_use(), 1);
    drop(permit);
    assert_eq!(limiter.active_hosts(), 0);
    assert_eq!(limiter.hosts_in_use(), 0);
}

#[tokio::test(start_paused = true)]
async fn overload_reduces_host_limits_and_successes_restore_them() {
    let limiter = limiter(LimitsConfig {
        max_connections_per_host: 4,
        rate_per_host: Rate::per_second(8),
        burst_per_host: 2,
        ..open_config()
    });
    let host = Arc::new(limiter.host(ip(1)).await);
    let configured = host.effective();
    assert_eq!(configured.connections, 4);

    let permit = host.acquire().await.unwrap();
    assert_eq!(permit.report(Outcome::Reset), Reaction::Slow);
    let reduced = Effective {
        connections: 2,
        rate: Rate::MilliPerSecond(4000),
        delay: ms(250),
    };
    assert_eq!(host.effective(), reduced);

    // Задержка backoff действует на следующее соединение; отказ сервера
    // ничего не меняет.
    let permit = host.acquire().await.unwrap();
    assert_eq!(permit.waited(), ms(250));
    assert_eq!(permit.report(Outcome::FatalAlert), Reaction::Keep);
    assert_eq!(host.effective(), reduced);

    // Действует сниженный лимит соединений.
    let gauge = Arc::new(Gauge::default());
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let host = Arc::clone(&host);
        let gauge = Arc::clone(&gauge);
        tasks.push(tokio::spawn(async move {
            let permit = host.acquire().await.unwrap();
            gauge.enter();
            sleep(secs(1)).await;
            gauge.leave();
            drop(permit);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(gauge.max(), 2);

    for _ in 0..8 {
        let permit = host.acquire().await.unwrap();
        assert_eq!(permit.report(Outcome::ConditionMet), Reaction::Recover);
    }
    assert_eq!(
        host.effective(),
        Effective {
            connections: 3,
            rate: Rate::MilliPerSecond(5000),
            delay: Duration::ZERO,
        }
    );
}

#[tokio::test(start_paused = true)]
async fn open_breaker_denies_with_a_pause_and_then_probes() {
    let limiter = limiter(LimitsConfig {
        breaker: BreakerConfig {
            failure_threshold: 2,
            ..BreakerConfig::default()
        },
        ..open_config()
    });
    let host = limiter.host(ip(1)).await;
    for _ in 0..2 {
        let permit = host.acquire().await.unwrap();
        assert_eq!(permit.report(Outcome::Reset), Reaction::Slow);
    }
    assert_eq!(host.breaker_state(), BreakerState::Open);

    let denied = host.acquire().await;
    assert!(matches!(denied, Err(Denied::Wait(pause)) if pause == secs(5)));
    assert_eq!(host.stats().snapshot().denied, 1);
    assert_eq!(limiter.stats().snapshot().denied, 1);
    assert_eq!(limiter.connections_in_use(), 0);

    let started = Instant::now();
    let probe = host.acquire_waiting().await.unwrap();
    assert!(probe.is_probe());
    // Пауза breaker'а и задержка backoff после двух сигналов перегрузки.
    assert_eq!(started.elapsed(), secs(5).saturating_add(ms(500)));
    assert_eq!(host.breaker_state(), BreakerState::HalfOpen);
    assert_eq!(probe.report(Outcome::ConditionMet), Reaction::Recover);
    assert_eq!(host.breaker_state(), BreakerState::Closed);
}

#[tokio::test(start_paused = true)]
async fn closed_port_disables_the_host_at_once() {
    let limiter = limiter(open_config());
    let host = limiter.host(ip(1)).await;
    let permit = host.acquire().await.unwrap();
    assert_eq!(permit.report(Outcome::ConnectRefused), Reaction::Keep);
    assert_eq!(host.disabled(), Some(DisableReason::PortClosed));

    let denied = host.acquire().await;
    assert!(matches!(
        denied,
        Err(Denied::Disabled(DisableReason::PortClosed))
    ));
    let started = Instant::now();
    assert_eq!(
        host.acquire_waiting().await.err(),
        Some(DisableReason::PortClosed)
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(limiter.connections_in_use(), 0);
}

#[tokio::test(start_paused = true)]
async fn waiter_is_denied_when_the_host_is_disabled_meanwhile() {
    let limiter = limiter(LimitsConfig {
        max_connections: 1,
        max_connections_per_host: 2,
        ..open_config()
    });
    let host = Arc::new(limiter.host(ip(1)).await);
    let first = host.acquire().await.unwrap();
    let waiter = {
        let host = Arc::clone(&host);
        tokio::spawn(async move { host.acquire().await.map(drop) })
    };
    sleep(ms(1)).await;

    first.report(Outcome::ConnectRefused);
    assert_eq!(
        waiter.await.unwrap(),
        Err(Denied::Disabled(DisableReason::PortClosed))
    );
    assert_eq!(limiter.connections_in_use(), 0);
}

#[tokio::test(start_paused = true)]
async fn local_exhaustion_lowers_the_global_limit_and_it_recovers() {
    let limiter = limiter(LimitsConfig {
        max_connections: 64,
        ..open_config()
    });
    let host = limiter.host(ip(1)).await;
    let configured = host.effective();
    assert_eq!(limiter.connection_limit(), 64);

    let permit = host.acquire().await.unwrap();
    assert_eq!(permit.report(Outcome::LocalExhaustion), Reaction::Local);
    assert_eq!(limiter.connection_limit(), 32);
    assert_eq!(limiter.guard_cuts(), 1);

    // Пачка ошибок одного всплеска — один сигнал.
    let permit = host.acquire().await.unwrap();
    permit.report(Outcome::LocalExhaustion);
    assert_eq!(limiter.connection_limit(), 32);
    assert_eq!(limiter.guard_cuts(), 1);

    sleep(secs(1)).await;
    let permit = host.acquire().await.unwrap();
    permit.report(Outcome::LocalExhaustion);
    assert_eq!(limiter.connection_limit(), 16);
    assert_eq!(limiter.guard_cuts(), 2);

    // Хост за нехватку локальных ресурсов не штрафуется.
    assert_eq!(host.effective(), configured);
    assert_eq!(host.breaker_state(), BreakerState::Closed);

    // Нижняя граница.
    for _ in 0..4 {
        sleep(secs(1)).await;
        let permit = host.acquire().await.unwrap();
        permit.report(Outcome::LocalExhaustion);
    }
    assert_eq!(limiter.connection_limit(), 4);

    // Восстановление: шаг на каждые 32 исхода без локальной ошибки.
    for _ in 0..31 {
        let permit = host.acquire().await.unwrap();
        permit.report(Outcome::FatalAlert);
    }
    assert_eq!(limiter.connection_limit(), 4);
    let permit = host.acquire().await.unwrap();
    permit.report(Outcome::FatalAlert);
    assert_eq!(limiter.connection_limit(), 8);
}

#[tokio::test(start_paused = true)]
async fn waits_are_counted_for_the_host_and_for_the_scan() {
    let limiter = limiter(LimitsConfig {
        max_connections_per_host: 1,
        ..open_config()
    });
    let host = Arc::new(limiter.host(ip(1)).await);
    let first = host.acquire().await.unwrap();
    let waiter = {
        let host = Arc::clone(&host);
        tokio::spawn(async move { host.acquire().await.map(drop) })
    };
    sleep(ms(10)).await;
    drop(first);
    assert_eq!(waiter.await.unwrap(), Ok(()));

    let expected = StageSnapshot {
        hits: 1,
        wait: ms(10),
    };
    let per_host = host.stats().snapshot();
    assert_eq!(per_host.host_connections, expected);
    assert_eq!(per_host.permits, 2);
    assert_eq!(per_host.total_wait, ms(10));
    assert_eq!(per_host.global_connections, StageSnapshot::default());

    let total = limiter.stats().snapshot();
    assert_eq!(total.host_connections, expected);
    assert_eq!(total.permits, 2);
}
