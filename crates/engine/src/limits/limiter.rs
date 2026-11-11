//! Единая точка получения разрешения на соединение.
//!
//! [`Limiter`] объединяет три уровня конкурентности, два rate limit,
//! jitter, AIMD и circuit breaker. Вызывающий получает [`HostHandle`] на
//! время работы с хостом, перед каждым соединением берёт [`Permit`], а после
//! соединения сообщает исход вызовом [`Permit::report`].
//!
//! # Ключ хоста
//!
//! Ключ состояния «на хост» — IP-адрес, на который фактически идёт
//! соединение, а не имя и не пара адрес-порт: несколько имён на одном
//! адресе (виртуальные хосты, CDN) делят один лимит и одну скорость и не
//! умножают нагрузку на сервер.
//!
//! # Порядок захвата
//!
//! 1. слот параллельно сканируемых хостов — [`Limiter::host`], один раз на
//!    хост; удерживается, пока живы [`HostHandle`] и выданные им разрешения;
//! 2. слот соединений хоста;
//! 3. решение breaker'а (без ожидания);
//! 4. токен rate limit хоста;
//! 5. токен глобального rate limit;
//! 6. задержка: пауза backoff плюс jitter;
//! 7. слот глобального лимита соединений;
//! 8. повторное решение breaker'а (без ожидания): за время ожидания хост
//!    мог быть разомкнут или отключён.
//!
//! Порядок отличается от ARCH 6.1 («глобальный rate → rate хоста → семафор
//! хоста → глобальный семафор»): токены берутся после слота хоста. Иначе
//! задача забирала бы токен задолго до соединения, пока стоит в очереди
//! хоста, и rate limit переставал бы ограничивать моменты соединений.
//!
//! # Почему нет взаимной блокировки
//!
//! Ресурсы захватываются всеми задачами в одном и том же порядке. Задача,
//! владеющая глобальным слотом (шаг 7), больше ничего не ждёт: она
//! соединяется и освобождает всё при drop разрешения, поэтому глобальный
//! слот всегда освобождается за конечное время. Ожидание токенов и
//! задержка (шаги 4 – 6) зависят только от часов. Слот хоста (шаг 2)
//! освобождается владельцем, который ждёт лишь часы и глобальный слот.
//! Цикла ожидания между задачами нет.
//!
//! Глобальный слот берётся последним намеренно: ожидание токена медленного
//! хоста не удерживает общую ёмкость.
//!
//! # Справедливость
//!
//! Очереди семафоров tokio и token bucket — FIFO. В очереди глобального
//! семафора от одного хоста стоит не больше задач, чем его лимит
//! соединений, поэтому хост с длинной очередью задач не вытесняет
//! остальные: задачи других хостов встают в ту же очередь и обслуживаются
//! в порядке прихода.
//!
//! # Отмена
//!
//! Сброс future [`HostHandle::acquire`] на любом шаге ничего не теряет:
//! слоты освобождаются при drop, уже выданные токены возвращаются в bucket,
//! пробное соединение half-open возвращается breaker'у.
//!
//! # Пробное соединение и ожидание breaker'а
//!
//! Пробное соединение half-open привязано к билету
//! ([`ProbeTicket`](super::breaker::ProbeTicket)): вернуть его или
//! засчитать его исход может только разрешение, которому оно выдано.
//! Исходы остальных соединений хоста пробное не освобождают, поэтому в
//! half-open одновременно существует не более одного пробного разрешения.
//!
//! [`HostHandle::acquire_waiting`] не опрашивает breaker по таймеру: у
//! состояния хоста есть счётчик изменений (`tokio::sync::watch`), который
//! растёт при замыкании, размыкании, отключении и возврате пробного.
//! Ожидающий просыпается по изменению счётчика либо по истечении паузы
//! размыкания. У каждого ожидающего свой приёмник с отметкой виденного
//! значения, поэтому отмена одного ожидания не теряет уведомление для
//! остальных, а изменение между отказом и началом ожидания не пропадает.
//!
//! # Память
//!
//! Состояние хоста создаётся при первом [`Limiter::host`] и удаляется,
//! когда не осталось ни [`HostHandle`], ни разрешений этого хоста. Размер
//! таблицы ограничен числом одновременно активных хостов.
//!
//! Чтобы следующая цель на тот же адрес не начинала с чистого листа,
//! отключение хоста с причиной уровня хоста (`blocked_or_down`) и
//! неистёкшая пауза размыкания запоминаются в ограниченной памяти
//! ([`HostMemory`], параметры — [`LimitsConfig::memory`]). Запись делается
//! при каждом изменении состояния breaker'а, а не при удалении состояния
//! хоста, поэтому окна между удалением и записью нет. Новое состояние
//! хоста создаётся из записи: отключённый хост сразу получает
//! [`Denied::Disabled`] с той же причиной и пометкой
//! [`Disablement::remembered`], приостановленный — [`Denied::Wait`] с
//! остатком паузы и прежним счётом циклов. Что не запоминается и почему —
//! в документации [`memory`](super::memory).
//!
//! # Защита сканирующей машины
//!
//! Исход [`Outcome::LocalExhaustion`] (нет дескрипторов, локальных портов,
//! памяти под сокет) делит глобальный лимит соединений на
//! [`GuardConfig::decrease_divisor`], но не чаще одного раза за
//! [`GuardConfig::cooldown`] и не ниже [`GuardConfig::min_connections`].
//! Каждые [`GuardConfig::recover_after`] исходов без такой ошибки лимит
//! растёт на [`GuardConfig::recover_step`] до настроенного значения.
//!
//! # Пример
//!
//! ```no_run
//! use engine::limits::{Denied, Limiter, Outcome};
//!
//! # async fn example(
//! #     limiter: &Limiter,
//! #     connector: &net::Connector,
//! #     target: &net::Target,
//! #     addr: std::net::IpAddr,
//! #     scope: &net::ConnStats,
//! #     hello: &[u8],
//! #     until: net::Until,
//! # ) {
//! // Один раз на хост: слот параллельно сканируемых хостов.
//! let host = limiter.host(addr).await;
//!
//! // Перед каждым соединением.
//! let permit = match host.acquire().await {
//!     Ok(permit) => permit,
//!     // Breaker разомкнут: повторить не раньше чем через `_pause`.
//!     Err(Denied::Wait(_pause)) => return,
//!     // Пробное соединение занято другой задачей; `acquire_waiting`
//!     // пережидает и паузу, и занятое пробное.
//!     Err(Denied::ProbeBusy) => return,
//!     // Хост отключён: оставшиеся проверки помечаются причиной.
//!     Err(Denied::Disabled(_reason)) => return,
//! };
//!
//! let outcome = match connector.connect(target, scope).await {
//!     Ok(conn) => {
//!         let transcript = net::send_and_collect(conn, hello, until).await;
//!         Outcome::from_stop(&transcript.stop)
//!     }
//!     Err(error) => Outcome::from_connect_error(&error),
//! };
//!
//! // Один вызов: исход учтён, слоты освобождены.
//! permit.report(outcome);
//! # }
//! ```

use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use super::backoff::{Aimd, AimdConfig, Effective, Outcome};
use super::breaker::{
    Breaker, BreakerConfig, BreakerMemo, BreakerState, Decision, DisableReason, ProbeTicket,
    Reaction,
};
use super::jitter::{Jitter, JitterRange, JitterSource, SplitMix64};
use super::memory::{HostMemory, MemoryConfig};
use super::semaphores::{AdjustableSemaphore, HostEntry, HostTable, SlotPermit};
use super::stats::{LimitStats, Stage};
use super::token_bucket::{Rate, Token, TokenBucket};

/// Значение лимита «без ограничения» для полей числа соединений и хостов.
pub const UNLIMITED: usize = usize::MAX;

/// Параметры защиты сканирующей машины; значения по умолчанию
/// предварительные (`docs/DECISIONS.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardConfig {
    /// Нижняя граница глобального лимита соединений; не выше настроенного
    /// лимита, ноль трактуется как 1.
    pub min_connections: usize,
    /// Во сколько раз уменьшается глобальный лимит; значение меньше 2
    /// трактуется как 2.
    pub decrease_divisor: u32,
    /// Наименьший интервал между уменьшениями: пачка ошибок от одного
    /// всплеска считается одним сигналом.
    pub cooldown: Duration,
    /// Сколько исходов без локальной ошибки дают один шаг восстановления;
    /// ноль трактуется как 1.
    pub recover_after: u32,
    /// Шаг восстановления глобального лимита; ноль трактуется как 1.
    pub recover_step: usize,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            min_connections: 4,
            decrease_divisor: 2,
            cooldown: Duration::from_secs(1),
            recover_after: 32,
            recover_step: 4,
        }
    }
}

/// Конфигурация лимитов. Числа соединений и хостов — из D-04, скорости и
/// jitter — из ARCH 6.1, остальное предварительное (`docs/DECISIONS.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitsConfig {
    /// Глобальный лимит одновременных соединений; [`UNLIMITED`] — без
    /// ограничения.
    pub max_connections: usize,
    /// Лимит одновременных соединений с одним адресом.
    pub max_connections_per_host: usize,
    /// Лимит параллельно сканируемых хостов.
    pub max_hosts: usize,
    /// Глобальная скорость соединений; [`Rate::Unlimited`] — без
    /// ограничения.
    pub rate: Rate,
    /// Burst глобального rate limit.
    pub burst: u32,
    /// Скорость соединений с одним адресом.
    pub rate_per_host: Rate,
    /// Burst rate limit хоста.
    pub burst_per_host: u32,
    /// Диапазон jitter перед соединением.
    pub jitter: JitterRange,
    /// Параметры AIMD.
    pub aimd: AimdConfig,
    /// Параметры circuit breaker'а.
    pub breaker: BreakerConfig,
    /// Параметры защиты сканирующей машины.
    pub guard: GuardConfig,
    /// Параметры памяти об отключённых хостах.
    pub memory: MemoryConfig,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_connections_per_host: 2,
            max_hosts: 16,
            rate: Rate::per_second(200),
            burst: 16,
            rate_per_host: Rate::per_second(10),
            burst_per_host: 2,
            jitter: JitterRange::up_to(Duration::from_millis(50)),
            aimd: AimdConfig::default(),
            breaker: BreakerConfig::default(),
            guard: GuardConfig::default(),
            memory: MemoryConfig::default(),
        }
    }
}

impl LimitsConfig {
    /// Пресет `gentle` (D-04): одно соединение на хост, остальное — по
    /// умолчанию.
    #[must_use]
    pub fn gentle() -> Self {
        Self {
            max_connections_per_host: 1,
            burst_per_host: 1,
            ..Self::default()
        }
    }
}

/// Сведения об отключении хоста.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disablement {
    /// Причина отключения.
    pub reason: DisableReason,
    /// Момент отключения.
    pub at: Instant,
    /// Истина, если решение взято из памяти об отключённых хостах: с этой
    /// целью соединений не было, хост отключён при работе с более ранней
    /// целью на тот же адрес.
    pub remembered: bool,
}

impl From<Disablement> for DisableReason {
    fn from(disablement: Disablement) -> Self {
        disablement.reason
    }
}

/// Отказ в разрешении на соединение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// Breaker хоста разомкнут: запрос повторить через указанное время.
    Wait(Duration),
    /// Пробное соединение half-open занято другой задачей: запрос
    /// повторить, когда состояние breaker'а изменится.
    /// [`HostHandle::acquire_waiting`] ждёт этого сам.
    ProbeBusy,
    /// Работа с хостом прекращена.
    Disabled(Disablement),
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wait(pause) => write!(f, "соединения приостановлены на {pause:?}"),
            Self::ProbeBusy => f.write_str("пробное соединение занято другой задачей"),
            Self::Disabled(disablement) => {
                write!(f, "хост отключён: {}", disablement.reason.label())?;
                if disablement.remembered {
                    f.write_str(" (решение из памяти об отключённых хостах)")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Denied {}

#[derive(Debug)]
struct GuardState {
    /// Момент последнего срабатывания защиты: уменьшения глобального
    /// лимита либо срабатывания на нижней границе.
    last_cut: Option<Instant>,
    /// Исходов без локальной ошибки с последнего шага.
    good: u32,
    /// Сколько раз глобальный лимит фактически уменьшался.
    cuts: u64,
    /// Сколько раз защита сработала без эффекта: лимит уже на нижней
    /// границе и не уменьшился.
    floor_hits: u64,
}

#[derive(Debug)]
struct Shared {
    config: LimitsConfig,
    /// Настроенный глобальный лимит после приведения к допустимому
    /// диапазону.
    configured_connections: usize,
    hosts: AdjustableSemaphore,
    connections: AdjustableSemaphore,
    bucket: TokenBucket,
    jitter: Jitter,
    table: HostTable<HostState>,
    memory: Arc<HostMemory>,
    stats: LimitStats,
    guard: Mutex<GuardState>,
}

impl Shared {
    fn guard(&self) -> MutexGuard<'_, GuardState> {
        self.guard.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Обратная связь глобального контура по реакции на исход.
    fn feedback(&self, reaction: Reaction, now: Instant) {
        let config = self.config.guard;
        let mut guard = self.guard();
        let current = self.connections.limit();
        if reaction == Reaction::Local {
            guard.good = 0;
            let cooling = guard
                .last_cut
                .is_some_and(|cut| now.saturating_duration_since(cut) < config.cooldown);
            if cooling {
                return;
            }
            let floor = config
                .min_connections
                .max(1)
                .min(self.configured_connections);
            let divisor = usize::try_from(config.decrease_divisor.max(2)).unwrap_or(2);
            let reduced = current
                .checked_div(divisor)
                .unwrap_or(floor)
                .max(floor)
                .min(current);
            guard.last_cut = Some(now);
            if reduced < current {
                self.connections.set_limit(reduced);
                guard.cuts = guard.cuts.saturating_add(1);
            } else {
                // Лимит уже на нижней границе: срабатывание без эффекта.
                guard.floor_hits = guard.floor_hits.saturating_add(1);
            }
        } else if current >= self.configured_connections {
            guard.good = 0;
        } else {
            guard.good = guard.good.saturating_add(1);
            if guard.good >= config.recover_after.max(1) {
                guard.good = 0;
                let raised = current
                    .saturating_add(config.recover_step.max(1))
                    .min(self.configured_connections);
                self.connections.set_limit(raised);
            }
        }
    }
}

#[derive(Debug)]
struct Control {
    aimd: Aimd,
    breaker: Breaker,
    /// Сведения об отключении, если хост отключён.
    disablement: Option<Disablement>,
}

/// Состояние одного хоста.
#[derive(Debug)]
struct HostState {
    addr: IpAddr,
    connections: AdjustableSemaphore,
    bucket: TokenBucket,
    control: Mutex<Control>,
    /// Счётчик изменений breaker'а для ожидающих разрешения.
    changes: watch::Sender<u64>,
    memory: Arc<HostMemory>,
    stats: LimitStats,
}

impl HostState {
    /// Состояние хоста `addr`: чистое либо восстановленное из памяти об
    /// отключённых хостах.
    fn new(shared: &Shared, addr: IpAddr) -> Self {
        let config = &shared.config;
        let (changes, _receiver) = watch::channel(0);
        let remembered = shared.memory.lookup(addr, Instant::now());
        let (breaker, disablement) = match remembered {
            Some(found) => {
                let disablement = match found.memo {
                    BreakerMemo::Disabled(reason) => Some(Disablement {
                        reason,
                        at: found.at,
                        remembered: true,
                    }),
                    BreakerMemo::Open { .. } => None,
                };
                (Breaker::restore(config.breaker, found.memo), disablement)
            }
            None => (Breaker::new(config.breaker), None),
        };
        Self {
            addr,
            connections: AdjustableSemaphore::new(config.max_connections_per_host),
            bucket: TokenBucket::new(config.rate_per_host, config.burst_per_host),
            control: Mutex::new(Control {
                aimd: Aimd::new(
                    config.aimd,
                    config.max_connections_per_host,
                    config.rate_per_host,
                ),
                breaker,
                disablement,
            }),
            changes,
            memory: Arc::clone(&shared.memory),
            stats: shared.stats.child(),
        }
    }

    fn control(&self) -> MutexGuard<'_, Control> {
        self.control.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Сведения об отключении для отказа с причиной `reason`.
    fn disablement(&self, reason: DisableReason) -> Disablement {
        // Запись появляется в `update` вместе с отключением; запасное
        // значение нужно только типам.
        self.control().disablement.unwrap_or(Disablement {
            reason,
            at: Instant::now(),
            remembered: false,
        })
    }

    /// Выполняет `action` под замком. Если после него изменился
    /// [`Breaker::revision`], снимок breaker'а записывается в память об
    /// отключённых хостах (либо запись стирается, если запоминать нечего),
    /// а ожидающие разрешения получают уведомление — после освобождения
    /// замка.
    fn update<R>(&self, action: impl FnOnce(&mut Control) -> R) -> R {
        let (result, changed) = {
            let mut control = self.control();
            let before = control.breaker.revision();
            let result = action(&mut control);
            let changed = control.breaker.revision() != before;
            if changed {
                let now = Instant::now();
                if control.disablement.is_none() {
                    control.disablement = control.breaker.disabled().map(|reason| Disablement {
                        reason,
                        at: now,
                        remembered: false,
                    });
                }
                // Под замком состояния: записи одного хоста попадают в
                // память в том же порядке, в каком менялось состояние.
                match control.breaker.memo() {
                    Some(memo) => self.memory.remember(self.addr, memo, now),
                    None => self.memory.forget(self.addr),
                }
            }
            (result, changed)
        };
        if changed {
            self.changes
                .send_modify(|version| *version = version.wrapping_add(1));
        }
        result
    }
}

/// Ждёт следующего изменения счётчика состояния хоста.
async fn wait_for_change(changes: &mut watch::Receiver<u64>) {
    if changes.changed().await.is_err() {
        // Отправитель живёт в состоянии хоста, которое удерживает сам
        // ожидающий, поэтому канал не закрывается. Ветка недостижима;
        // вечное ожидание вместо паники.
        std::future::pending::<()>().await;
    }
}

/// Работа с одним хостом: слот хостов и ссылка на состояние.
#[derive(Debug)]
struct Session {
    shared: Arc<Shared>,
    entry: Arc<HostEntry<HostState>>,
    _slot: SlotPermit,
}

/// Ждёт слот семафора; ожидание учитывается на этапе `stage`.
async fn acquire_slot(
    semaphore: &AdjustableSemaphore,
    stats: &LimitStats,
    stage: Stage,
) -> SlotPermit {
    if let Some(permit) = semaphore.try_acquire() {
        return permit;
    }
    let started = Instant::now();
    let permit = semaphore.acquire().await;
    stats.record_wait(stage, started.elapsed());
    permit
}

/// Точка получения разрешений; описание — в документации модуля.
/// Клонирование даёт ссылку на то же состояние.
#[derive(Debug, Clone)]
pub struct Limiter {
    shared: Arc<Shared>,
}

impl Limiter {
    /// Лимиты с jitter на [`SplitMix64`] с seed из системных часов.
    #[must_use]
    pub fn new(config: LimitsConfig) -> Self {
        Self::with_jitter_source(config, Box::new(SplitMix64::from_clock()))
    }

    /// Лимиты с jitter на [`SplitMix64`] с заданным seed.
    #[must_use]
    pub fn seeded(config: LimitsConfig, seed: u64) -> Self {
        Self::with_jitter_source(config, Box::new(SplitMix64::new(seed)))
    }

    /// Лимиты с заданным источником случайности для jitter.
    #[must_use]
    pub fn with_jitter_source(config: LimitsConfig, source: Box<dyn JitterSource>) -> Self {
        let connections = AdjustableSemaphore::new(config.max_connections);
        Self {
            shared: Arc::new(Shared {
                config,
                configured_connections: connections.limit(),
                hosts: AdjustableSemaphore::new(config.max_hosts),
                connections,
                bucket: TokenBucket::new(config.rate, config.burst),
                jitter: Jitter::new(config.jitter, source),
                table: HostTable::new(),
                memory: Arc::new(HostMemory::new(config.memory)),
                stats: LimitStats::new(),
                guard: Mutex::new(GuardState {
                    last_cut: None,
                    good: 0,
                    cuts: 0,
                    floor_hits: 0,
                }),
            }),
        }
    }

    /// Конфигурация, с которой созданы лимиты.
    #[must_use]
    pub fn config(&self) -> &LimitsConfig {
        &self.shared.config
    }

    /// Начинает работу с хостом `addr`: ждёт слот параллельно сканируемых
    /// хостов и возвращает его владельца. Сброс future ничего не
    /// захватывает.
    pub async fn host(&self, addr: IpAddr) -> HostHandle {
        let shared = &self.shared;
        let slot = acquire_slot(&shared.hosts, &shared.stats, Stage::HostSlot).await;
        let entry = shared
            .table
            .get_or_create(addr, || HostState::new(shared, addr));
        HostHandle {
            session: Arc::new(Session {
                shared: Arc::clone(shared),
                entry,
                _slot: slot,
            }),
        }
    }

    /// Разрешение на одно соединение с хостом `addr` без отдельного
    /// [`HostHandle`]: слот хостов удерживается самим разрешением.
    ///
    /// # Errors
    ///
    /// [`Denied`], если breaker хоста не выдаёт соединений.
    pub async fn acquire(&self, addr: IpAddr) -> Result<Permit, Denied> {
        self.host(addr).await.acquire().await
    }

    /// Счётчики ожидания по всему скану.
    #[must_use]
    pub fn stats(&self) -> &LimitStats {
        &self.shared.stats
    }

    /// Число хостов, для которых сейчас хранится состояние.
    #[must_use]
    pub fn active_hosts(&self) -> usize {
        self.shared.table.len()
    }

    /// Число занятых слотов параллельно сканируемых хостов.
    #[must_use]
    pub fn hosts_in_use(&self) -> usize {
        self.shared.hosts.in_use()
    }

    /// Число занятых слотов глобального лимита соединений.
    #[must_use]
    pub fn connections_in_use(&self) -> usize {
        self.shared.connections.in_use()
    }

    /// Действующий глобальный лимит соединений: настроенный либо временно
    /// сниженный защитой сканирующей машины.
    #[must_use]
    pub fn connection_limit(&self) -> usize {
        self.shared.connections.limit()
    }

    /// Сколько раз защита сканирующей машины фактически снизила глобальный
    /// лимит.
    #[must_use]
    pub fn guard_cuts(&self) -> u64 {
        self.shared.guard().cuts
    }

    /// Сколько раз защита сканирующей машины сработала без эффекта: лимит
    /// уже был на нижней границе ([`GuardConfig::min_connections`]) и не
    /// уменьшился. Срабатывания внутри [`GuardConfig::cooldown`] не
    /// считаются ни здесь, ни в [`Limiter::guard_cuts`].
    #[must_use]
    pub fn guard_floor_hits(&self) -> u64 {
        self.shared.guard().floor_hits
    }

    /// Число адресов в памяти об отключённых хостах.
    #[must_use]
    pub fn remembered_hosts(&self) -> usize {
        self.shared.memory.len()
    }

    /// Сколько записей памяти об отключённых хостах вытеснено из-за
    /// переполнения.
    #[must_use]
    pub fn memory_evictions(&self) -> u64 {
        self.shared.memory.evicted()
    }
}

/// Владелец слота хостов: через него берутся разрешения на соединения с
/// хостом. Слот освобождается, когда сброшены и владелец, и все выданные им
/// разрешения.
#[derive(Debug)]
pub struct HostHandle {
    session: Arc<Session>,
}

impl HostHandle {
    /// Адрес хоста — ключ лимитов.
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.session.entry.key()
    }

    /// Счётчики ожидания этого хоста.
    #[must_use]
    pub fn stats(&self) -> &LimitStats {
        &self.session.entry.stats
    }

    /// Действующие ограничения хоста с учётом AIMD.
    #[must_use]
    pub fn effective(&self) -> Effective {
        self.session.entry.control().aimd.effective()
    }

    /// Состояние breaker'а хоста.
    #[must_use]
    pub fn breaker_state(&self) -> BreakerState {
        self.session.entry.control().breaker.state()
    }

    /// Причина отключения, если хост отключён.
    #[must_use]
    pub fn disabled(&self) -> Option<DisableReason> {
        self.session.entry.control().breaker.disabled()
    }

    /// Сведения об отключении, если хост отключён: причина, момент и
    /// признак решения из памяти.
    #[must_use]
    pub fn disablement(&self) -> Option<Disablement> {
        let control = self.session.entry.control();
        control.breaker.disabled().map(|reason| {
            control.disablement.unwrap_or(Disablement {
                reason,
                at: Instant::now(),
                remembered: false,
            })
        })
    }

    /// Разрешение на одно соединение; порядок захвата — в документации
    /// модуля. Сброс future ничего не теряет.
    ///
    /// # Errors
    ///
    /// [`Denied::Wait`], если breaker разомкнут; [`Denied::Disabled`], если
    /// работа с хостом прекращена.
    pub async fn acquire(&self) -> Result<Permit, Denied> {
        let started = Instant::now();
        let session = &self.session;
        let shared = &session.shared;
        let host = &session.entry;
        let stats = &host.stats;

        let disabled = host.control().breaker.disabled();
        if let Some(reason) = disabled {
            stats.record_denied();
            return Err(Denied::Disabled(host.disablement(reason)));
        }

        let host_slot = acquire_slot(&host.connections, stats, Stage::HostConnections).await;
        let mut pending = Pending {
            session: Arc::clone(session),
            host_slot: Some(host_slot),
            host_token: None,
            global_token: None,
            probe: None,
        };
        pending.decide()?;

        let (token, waited) = host.bucket.take_token().await;
        pending.host_token = Some(token);
        if !waited.is_zero() {
            stats.record_wait(Stage::HostRate, waited);
        }

        let (token, waited) = shared.bucket.take_token().await;
        pending.global_token = Some(token);
        if !waited.is_zero() {
            stats.record_wait(Stage::GlobalRate, waited);
        }

        let backoff = host.control().aimd.effective().delay;
        let delay = backoff.saturating_add(shared.jitter.next_delay());
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
            stats.record_wait(Stage::Delay, delay);
        }

        let global_slot = acquire_slot(&shared.connections, stats, Stage::GlobalConnections).await;
        // Пробное с действующим билетом повторного решения не требует.
        // Обычному захвату и пробному с устаревшим билетом (за время
        // ожидания breaker закрылся или разомкнулся заново) оно нужно.
        if !pending.holds_current_probe() {
            pending.probe = None;
            pending.decide()?;
        }

        let waited = started.elapsed();
        stats.record_permit(waited);
        Ok(pending.into_permit(global_slot, waited))
    }

    /// То же, что [`HostHandle::acquire`], но пауза breaker'а и занятое
    /// пробное соединение пережидаются внутри вызова: до изменения
    /// состояния breaker'а либо до истечения паузы, без опроса по таймеру.
    /// Сброс future не теряет уведомление для остальных ожидающих.
    ///
    /// # Errors
    ///
    /// Сведения об отключении, если работа с хостом прекращена.
    pub async fn acquire_waiting(&self) -> Result<Permit, Disablement> {
        let mut changes = self.session.entry.changes.subscribe();
        loop {
            // Отметка до запроса: изменение, случившееся после неё, будет
            // замечено ожиданием ниже, даже если оно произошло раньше, чем
            // ожидание началось.
            let _seen = *changes.borrow_and_update();
            match self.acquire().await {
                Ok(permit) => return Ok(permit),
                Err(Denied::Wait(pause)) => {
                    let _woken = tokio::time::timeout(pause, wait_for_change(&mut changes)).await;
                }
                Err(Denied::ProbeBusy) => wait_for_change(&mut changes).await,
                Err(Denied::Disabled(disablement)) => return Err(disablement),
            }
        }
    }
}

/// Незавершённый захват: при drop возвращает всё, что успел взять.
#[derive(Debug)]
struct Pending {
    session: Arc<Session>,
    host_slot: Option<SlotPermit>,
    /// Квитанция токена хоста, если он уже взят.
    host_token: Option<Token>,
    /// Квитанция глобального токена, если он уже взят.
    global_token: Option<Token>,
    /// Билет пробного соединения, если захват его получил.
    probe: Option<ProbeTicket>,
}

impl Pending {
    /// Спрашивает breaker; при отказе учитывает его в счётчиках.
    fn decide(&mut self) -> Result<(), Denied> {
        let host = &self.session.entry;
        let (decision, ticket) = host.update(|control| {
            let decision = control.breaker.decision(Instant::now());
            (decision, control.breaker.probe_ticket())
        });
        match decision {
            Decision::Allowed { probe } => {
                self.probe = if probe { ticket } else { None };
                Ok(())
            }
            Decision::Wait(pause) => {
                host.stats.record_denied();
                Err(Denied::Wait(pause))
            }
            Decision::ProbeBusy => {
                host.stats.record_denied();
                Err(Denied::ProbeBusy)
            }
            Decision::Disabled(reason) => {
                host.stats.record_denied();
                Err(Denied::Disabled(host.disablement(reason)))
            }
        }
    }

    /// Истина, если захват держит пробное соединение и его билет ещё
    /// действует.
    fn holds_current_probe(&self) -> bool {
        self.probe.is_some_and(|ticket| {
            self.session.entry.control().breaker.probe_ticket() == Some(ticket)
        })
    }

    /// Захват завершён: всё взятое переходит разрешению.
    fn into_permit(mut self, global_slot: SlotPermit, waited: Duration) -> Permit {
        self.host_token = None;
        self.global_token = None;
        Permit {
            session: Arc::clone(&self.session),
            _host_slot: self.host_slot.take(),
            _global_slot: global_slot,
            probe: self.probe.take(),
            waited,
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(token) = self.host_token.take() {
            self.session.entry.bucket.refund(token);
        }
        if let Some(token) = self.global_token.take() {
            self.session.shared.bucket.refund(token);
        }
        if let Some(ticket) = self.probe.take() {
            self.session
                .entry
                .update(|control| control.breaker.abandon_probe(ticket));
        }
    }
}

/// Разрешение на одно соединение. Удерживает слот соединений хоста,
/// глобальный слот и слот хостов; всё освобождается при drop — после
/// закрытия сокета.
#[derive(Debug)]
pub struct Permit {
    session: Arc<Session>,
    _host_slot: Option<SlotPermit>,
    _global_slot: SlotPermit,
    /// Билет пробного соединения half-open, если разрешение пробное.
    probe: Option<ProbeTicket>,
    waited: Duration,
}

impl Permit {
    /// Адрес хоста, для которого выдано разрешение.
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.session.entry.key()
    }

    /// Истина для разрешения, выданного как пробное соединение half-open.
    #[must_use]
    pub fn is_probe(&self) -> bool {
        self.probe.is_some()
    }

    /// Сколько времени прошло от запроса разрешения до выдачи.
    #[must_use]
    pub fn waited(&self) -> Duration {
        self.waited
    }

    /// Сообщает исход соединения или обмена и освобождает слоты. Исход
    /// учитывают breaker и AIMD хоста и глобальный контур. Исход пробного
    /// разрешения решает судьбу half-open; исход обычного пробное
    /// соединение не освобождает. Разрешение, сброшенное без этого вызова,
    /// ни на что не влияет: соединение считается несостоявшимся.
    pub fn report(mut self, outcome: Outcome) -> Reaction {
        // Пробное соединение завершается исходом: в `Drop` возвращать его
        // уже не нужно.
        let ticket = self.probe.take();
        let now = Instant::now();
        let host = &self.session.entry;
        let reaction = host.update(|control| {
            let reaction = match ticket {
                Some(ticket) => control.breaker.record_probe(ticket, outcome, now),
                None => control.breaker.record(outcome, now),
            };
            let effective = match reaction {
                Reaction::Slow => Some(control.aimd.on_overload()),
                Reaction::Recover => Some(control.aimd.on_success()),
                Reaction::Keep | Reaction::Local => None,
            };
            if let Some(effective) = effective {
                host.connections.set_limit(effective.connections);
                host.bucket.set_rate(effective.rate);
            }
            reaction
        });
        self.session.shared.feedback(reaction, now);
        reaction
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(ticket) = self.probe.take() {
            self.session
                .entry
                .update(|control| control.breaker.abandon_probe(ticket));
        }
    }
}
