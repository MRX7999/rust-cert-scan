//! Circuit breaker на хост и ранний выход.
//!
//! [`Breaker`] — чистый автомат без часов и ввода-вывода: текущее время
//! передаётся аргументом, поэтому тесты не ждут. На вход идут исходы
//! соединений и обменов ([`Outcome`]), на выход — решение для очередного
//! соединения ([`Decision`]) и реакция для AIMD ([`Reaction`]).
//!
//! # Состояния
//!
//! | Состояние | Новые соединения | Переход |
//! |---|---|---|
//! | closed | разрешены | [`BreakerConfig::failure_threshold`] неуспехов подряд → open |
//! | open | [`Decision::Wait`] до конца паузы | пауза истекла → half-open |
//! | half-open | одно пробное, остальным [`Decision::ProbeBusy`] | ответ сервера → closed; неуспех пробного → open с более длинной паузой |
//! | disabled | [`Decision::Disabled`] с причиной | окончательное |
//!
//! Пауза первого размыкания — [`BreakerConfig::open_initial`], каждая
//! следующая длиннее в [`BreakerConfig::open_multiplier`] раз, но не больше
//! [`BreakerConfig::open_max`]. Размыканий подряд допускается
//! [`BreakerConfig::max_cycles`]; следующее отключает хост с причиной
//! [`DisableReason::BlockedOrDown`]. Закрытие breaker'а обнуляет счёт
//! циклов.
//!
//! # Что считается неуспехом
//!
//! Сигнал исхода берётся из [`Outcome::signal`] — таблица там же.
//!
//! - `Overload` — неуспех.
//! - `Success` и `Neutral` — сервер ответил: серия неуспехов прерывается,
//!   half-open закрывается. Отказ сервера в протоколе или шифре (fatal
//!   alert, закрытие на границе сообщений) — штатный результат
//!   сканирования и breaker не размыкает никогда.
//! - `AmbiguousEof` (EOF до первого байта): первые
//!   `ambiguous_eof_threshold - 1` подряд не меняют ничего — так старые
//!   стеки отвечают на неподдерживаемый hello. Начиная с
//!   [`BreakerConfig::ambiguous_eof_threshold`]-го подряд каждый считается
//!   неуспехом: серия без единого ответа похожа на блокировку. Любой другой
//!   исход, кроме `Local`, серию EOF обнуляет. Пробное соединение в
//!   half-open, закончившееся таким EOF, — неуспех сразу.
//! - `Refused`: до первого установленного соединения — закрытый порт
//!   (ранний выход), после — неуспех.
//! - `NotTls`: до первого ответа TLS — ранний выход, после — как `Neutral`.
//! - `Unresolved` — ранний выход.
//! - `Local` — нехватка ресурсов сканирующей машины: хост не штрафуется;
//!   если исход принадлежит пробному соединению, оно возвращается
//!   следующему желающему.
//!
//! # Пробное соединение и исходы во время half-open
//!
//! Инвариант: в состоянии half-open одновременно выдано не более одного
//! пробного соединения, какие бы исходы ни сообщались параллельно.
//!
//! Каждая выдача пробного получает билет [`ProbeTicket`] — номер выдачи.
//! Вернуть пробное ([`Breaker::abandon_probe`]) или засчитать его исход
//! ([`Breaker::record_probe`]) может только владелец действующего билета.
//! [`Breaker::record`] — исход обычного соединения; в half-open это всегда
//! «старое» соединение, выданное до размыкания (новых обычных half-open не
//! выдаёт), и пробное оно не возвращает никогда.
//!
//! | Сигнал исхода | Исход пробного | Исход старого соединения |
//! |---|---|---|
//! | `Success`, `Neutral`, `NotTls` после ответа TLS | closed, счёт циклов обнулён | closed, счёт циклов обнулён: сервер ответил; билет пробного устаревает, его исход будет учтён как обычный |
//! | `Overload`, `Refused` после установленного соединения | open с более длинной паузой либо отключение | состояние не меняется: решает только пробное; AIMD получает [`Reaction::Slow`] |
//! | `AmbiguousEof` | неуспех сразу: open | серия EOF растёт, состояние не меняется |
//! | `Local` | пробное возвращается, half-open сохраняется | ничего не меняется, пробное остаётся в полёте |
//! | ранний выход (`Refused` до первого соединения, `NotTls` до первого ответа, `Unresolved`) | отключение; если остались повторы — пробное возвращается | отключение; если остались повторы — ничего не меняется |
//!
//! Устаревший билет (breaker успел закрыться или разомкнуться заново)
//! ничего не возвращает: [`Breaker::abandon_probe`] с ним — пустая
//! операция, [`Breaker::record_probe`] учитывает исход как обычный. Поэтому
//! пробное соединение прошлого цикла не может освободить пробное текущего.
//!
//! # Уведомление ожидающих
//!
//! [`Breaker::revision`] растёт при каждом изменении, после которого
//! отказ [`Decision::Wait`] или [`Decision::ProbeBusy`] может смениться
//! другим решением: замыкание, размыкание, отключение, возврат пробного.
//! Вызывающий код сравнивает значение до и после операции и будит
//! ожидающих; опроса по таймеру нет.
//!
//! # Ранний выход
//!
//! Закрытый порт, неразрешившееся имя и не-TLS ответ отключают хост без
//! пауз. Число повторов перед отключением —
//! [`BreakerConfig::early_exit_retries`], по умолчанию ноль: одна попытка
//! (ARCH 6.3).

use std::time::Duration;

use tokio::time::Instant;

use super::backoff::{Outcome, Signal};

/// Параметры circuit breaker'а; значения по умолчанию предварительные
/// (`docs/DECISIONS.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerConfig {
    /// Сколько неуспехов подряд размыкают breaker; ноль трактуется как 1.
    pub failure_threshold: u32,
    /// С какого по счёту EOF до первого байта подряд он считается
    /// неуспехом; ноль трактуется как 1.
    pub ambiguous_eof_threshold: u32,
    /// Пауза после первого размыкания.
    pub open_initial: Duration,
    /// Во сколько раз пауза растёт с каждым следующим размыканием; ноль
    /// трактуется как 1 (пауза не растёт).
    pub open_multiplier: u32,
    /// Верхняя граница паузы.
    pub open_max: Duration,
    /// Сколько размыканий подряд допускается; следующее отключает хост.
    /// Ноль — хост отключается при первом размыкании.
    pub max_cycles: u32,
    /// Сколько повторов допускается перед ранним выходом.
    pub early_exit_retries: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            ambiguous_eof_threshold: 3,
            open_initial: Duration::from_secs(5),
            open_multiplier: 2,
            open_max: Duration::from_secs(60),
            max_cycles: 3,
            early_exit_retries: 0,
        }
    }
}

/// Причина, по которой работа с хостом прекращена.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisableReason {
    /// Имя не разрешилось.
    Unresolved,
    /// Порт закрыт: отказ в соединении до первого установленного.
    PortClosed,
    /// Сервис отвечает не по TLS.
    NotTls,
    /// Хост перестал отвечать либо блокирует сканер: breaker исчерпал
    /// циклы.
    BlockedOrDown,
}

impl DisableReason {
    /// Все причины.
    pub const ALL: [Self; REASONS] = [
        Self::Unresolved,
        Self::PortClosed,
        Self::NotTls,
        Self::BlockedOrDown,
    ];

    /// Истина, если причина относится к адресу хоста целиком, а не к
    /// порту или имени цели. Только такие причины запоминаются на адрес
    /// (`crate::limits::memory`): закрытый порт, не-TLS сервис и
    /// неразрешившееся имя ничего не говорят о других портах и именах
    /// того же адреса.
    #[must_use]
    pub fn is_host_wide(self) -> bool {
        matches!(self, Self::BlockedOrDown)
    }

    /// Метка для вывода; совпадает со статусами цели из плана.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unresolved => "unresolved",
            Self::PortClosed => "unreachable",
            Self::NotTls => "not_tls",
            Self::BlockedOrDown => "blocked_or_down",
        }
    }
}

/// Число вариантов [`DisableReason`].
const REASONS: usize = 4;

/// Билет пробного соединения half-open: номер выдачи. Действует, пока
/// breaker остаётся в том же half-open и пробное не возвращено.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProbeTicket(u64);

/// Решение о новом соединении с хостом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Соединение разрешено.
    Allowed {
        /// Истина для пробного соединения half-open. Его билет —
        /// [`Breaker::probe_ticket`] сразу после решения. Если пробное не
        /// состоится, его нужно вернуть вызовом
        /// [`Breaker::abandon_probe`]; исход сообщается через
        /// [`Breaker::record_probe`].
        probe: bool,
    },
    /// Пауза после размыкания: запрос повторить через указанное время
    /// либо раньше, если изменится [`Breaker::revision`].
    Wait(Duration),
    /// Пробное соединение half-open занято другой задачей: запрос
    /// повторить, когда изменится [`Breaker::revision`].
    ProbeBusy,
    /// Работа с хостом прекращена.
    Disabled(DisableReason),
}

/// Снимок состояния breaker'а для памяти об отключённых хостах
/// (`crate::limits::memory`): то, что должна унаследовать следующая цель на
/// тот же адрес.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerMemo {
    /// Хост отключён с причиной уровня хоста.
    Disabled(DisableReason),
    /// Breaker разомкнут.
    Open {
        /// Конец паузы.
        until: Instant,
        /// Сколько раз подряд breaker размыкался.
        cycles: u32,
    },
}

/// Что исход значит для AIMD хоста и глобального контура.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reaction {
    /// Успех: шаг к восстановлению скорости.
    Recover,
    /// Ничего не менять.
    Keep,
    /// Неуспех: замедлиться.
    Slow,
    /// Нехватка ресурсов сканирующей машины: сигнал глобальному контуру.
    Local,
}

/// Состояние breaker'а для счётчиков и вывода.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BreakerState {
    /// Соединения разрешены.
    Closed,
    /// Пауза.
    Open,
    /// Идёт или ожидается пробное соединение.
    HalfOpen,
    /// Работа с хостом прекращена.
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Closed,
    Open { until: Instant },
    HalfOpen { probe_in_flight: bool },
    Disabled(DisableReason),
}

/// Circuit breaker одного хоста; описание — в документации модуля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breaker {
    config: BreakerConfig,
    state: State,
    /// Неуспехов подряд.
    failures: u32,
    /// EOF до первого байта подряд.
    eof_streak: u32,
    /// Исходов раннего выхода подряд.
    early_failures: u32,
    /// Размыканий подряд.
    cycles: u32,
    /// Хотя бы одно соединение было установлено.
    connected: bool,
    /// Сервер хотя бы раз ответил по TLS.
    responded: bool,
    /// Номер последней выдачи пробного соединения.
    epoch: u64,
    /// Счётчик изменений, о которых нужно уведомить ожидающих.
    revision: u64,
}

/// Истина для исходов этапа установления соединения.
fn is_connect_stage(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::ConnectUnresolved
            | Outcome::ConnectRefused
            | Outcome::ConnectReset
            | Outcome::ConnectTimeout
            | Outcome::ConnectUnreachable
            | Outcome::ConnectOther
            | Outcome::LocalExhaustion
    )
}

impl Breaker {
    /// Замкнутый breaker.
    #[must_use]
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            state: State::Closed,
            failures: 0,
            eof_streak: 0,
            early_failures: 0,
            cycles: 0,
            connected: false,
            responded: false,
            epoch: 0,
            revision: 0,
        }
    }

    /// Текущее состояние.
    #[must_use]
    pub fn state(&self) -> BreakerState {
        match self.state {
            State::Closed => BreakerState::Closed,
            State::Open { .. } => BreakerState::Open,
            State::HalfOpen { .. } => BreakerState::HalfOpen,
            State::Disabled(_) => BreakerState::Disabled,
        }
    }

    /// Причина отключения, если хост отключён.
    #[must_use]
    pub fn disabled(&self) -> Option<DisableReason> {
        match self.state {
            State::Disabled(reason) => Some(reason),
            _ => None,
        }
    }

    /// Сколько раз подряд breaker размыкался.
    #[must_use]
    pub fn cycles(&self) -> u32 {
        self.cycles
    }

    /// Снимок для памяти об отключённых хостах: отключение с причиной
    /// уровня хоста либо пауза размыкания. `None` — запоминать нечего:
    /// breaker замкнут, в half-open (пауза истекла) либо отключён по
    /// причине, относящейся к порту или имени.
    #[must_use]
    pub fn memo(&self) -> Option<BreakerMemo> {
        match self.state {
            State::Disabled(reason) if reason.is_host_wide() => Some(BreakerMemo::Disabled(reason)),
            State::Open { until } => Some(BreakerMemo::Open {
                until,
                cycles: self.cycles,
            }),
            State::Closed | State::HalfOpen { .. } | State::Disabled(_) => None,
        }
    }

    /// Breaker, восстановленный из снимка: отключённый с той же причиной
    /// либо разомкнутый с той же паузой и тем же счётом циклов. История
    /// соединений (было ли установленное соединение, отвечал ли сервер по
    /// TLS) не восстанавливается: она относится к порту прежней цели.
    #[must_use]
    pub fn restore(config: BreakerConfig, memo: BreakerMemo) -> Self {
        let mut breaker = Self::new(config);
        match memo {
            BreakerMemo::Disabled(reason) => breaker.state = State::Disabled(reason),
            BreakerMemo::Open { until, cycles } => {
                breaker.state = State::Open { until };
                breaker.cycles = cycles;
            }
        }
        breaker
    }

    /// Счётчик изменений, после которых отказ в соединении может смениться
    /// другим решением; см. «Уведомление ожидающих» в документации модуля.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Решение о новом соединении в момент `now`. Истёкшая пауза переводит
    /// breaker в half-open и выдаёт пробное соединение вызывающему; билет
    /// выданного пробного — [`Breaker::probe_ticket`].
    pub fn decision(&mut self, now: Instant) -> Decision {
        match self.state {
            State::Closed => Decision::Allowed { probe: false },
            State::Disabled(reason) => Decision::Disabled(reason),
            State::Open { until } => match until.checked_duration_since(now) {
                Some(left) if !left.is_zero() => Decision::Wait(left),
                _ => self.issue_probe(),
            },
            State::HalfOpen { probe_in_flight } => {
                if probe_in_flight {
                    Decision::ProbeBusy
                } else {
                    self.issue_probe()
                }
            }
        }
    }

    /// Выдаёт пробное соединение с новым билетом.
    fn issue_probe(&mut self) -> Decision {
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::HalfOpen {
            probe_in_flight: true,
        };
        Decision::Allowed { probe: true }
    }

    /// Билет пробного соединения, которое сейчас в полёте; `None`, если
    /// breaker не в half-open либо пробное свободно.
    #[must_use]
    pub fn probe_ticket(&self) -> Option<ProbeTicket> {
        match self.state {
            State::HalfOpen {
                probe_in_flight: true,
            } => Some(ProbeTicket(self.epoch)),
            _ => None,
        }
    }

    /// Истина, если `ticket` — билет пробного, которое сейчас в полёте.
    fn owns_probe(&self, ticket: ProbeTicket) -> bool {
        self.probe_ticket() == Some(ticket)
    }

    /// Освобождает пробное соединение для следующего желающего.
    fn release_probe(&mut self) {
        if let State::HalfOpen {
            probe_in_flight: true,
        } = self.state
        {
            self.state = State::HalfOpen {
                probe_in_flight: false,
            };
            self.changed();
        }
    }

    /// Отмечает изменение, о котором нужно уведомить ожидающих.
    fn changed(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    /// Возвращает пробное соединение half-open: оно не состоялось (отмена
    /// до connect, разрешение сброшено без исхода). Действует только с
    /// билетом пробного, которое сейчас в полёте; с устаревшим билетом и в
    /// остальных состояниях ничего не делает.
    pub fn abandon_probe(&mut self, ticket: ProbeTicket) {
        if self.owns_probe(ticket) {
            self.release_probe();
        }
    }

    /// Учитывает исход обычного соединения или обмена, завершившегося в
    /// момент `now`, и возвращает реакцию для AIMD. Пробное соединение
    /// half-open такой исход не возвращает и не заменяет; таблица — в
    /// документации модуля. Исходы, пришедшие после отключения хоста,
    /// игнорируются.
    pub fn record(&mut self, outcome: Outcome, now: Instant) -> Reaction {
        self.apply(outcome, now, false)
    }

    /// Учитывает исход пробного соединения с билетом `ticket`. Если билет
    /// устарел (breaker успел закрыться, разомкнуться заново или пробное
    /// уже возвращено), исход учитывается как обычный.
    pub fn record_probe(
        &mut self,
        ticket: ProbeTicket,
        outcome: Outcome,
        now: Instant,
    ) -> Reaction {
        let probe = self.owns_probe(ticket);
        self.apply(outcome, now, probe)
    }

    /// Общая часть учёта исхода; `probe` — исход принадлежит пробному
    /// соединению, которое сейчас в полёте.
    fn apply(&mut self, outcome: Outcome, now: Instant, probe: bool) -> Reaction {
        if matches!(self.state, State::Disabled(_)) {
            return Reaction::Keep;
        }
        if !is_connect_stage(outcome) {
            self.connected = true;
        }
        match outcome.signal() {
            Signal::Local => {
                if probe {
                    self.release_probe();
                }
                Reaction::Local
            }
            Signal::Success => {
                self.alive();
                Reaction::Recover
            }
            Signal::Neutral => {
                self.alive();
                Reaction::Keep
            }
            Signal::NotTls => {
                if self.responded {
                    self.alive();
                    Reaction::Keep
                } else {
                    self.early_exit(DisableReason::NotTls, probe)
                }
            }
            Signal::Unresolved => self.early_exit(DisableReason::Unresolved, probe),
            Signal::Refused => {
                if self.connected {
                    self.eof_streak = 0;
                    self.failure(now, probe)
                } else {
                    self.early_exit(DisableReason::PortClosed, probe)
                }
            }
            Signal::AmbiguousEof => {
                self.eof_streak = self.eof_streak.saturating_add(1);
                let series = self.eof_streak >= self.config.ambiguous_eof_threshold.max(1);
                if series || probe {
                    self.failure(now, probe)
                } else {
                    Reaction::Keep
                }
            }
            Signal::Overload => {
                self.eof_streak = 0;
                self.failure(now, probe)
            }
        }
    }

    /// Сервер ответил по TLS: серии обнуляются, half-open закрывается.
    /// Билет пробного, если оно было в полёте, после этого устаревает.
    fn alive(&mut self) {
        self.responded = true;
        self.failures = 0;
        self.eof_streak = 0;
        self.early_failures = 0;
        if let State::HalfOpen { .. } = self.state {
            self.state = State::Closed;
            self.cycles = 0;
            self.changed();
        }
    }

    /// Исход раннего выхода: хост отключается, когда повторы исчерпаны.
    /// Пока повторы остаются, пробное соединение возвращает только его
    /// собственный исход.
    fn early_exit(&mut self, reason: DisableReason, probe: bool) -> Reaction {
        self.early_failures = self.early_failures.saturating_add(1);
        if self.early_failures > self.config.early_exit_retries {
            self.state = State::Disabled(reason);
            self.changed();
        } else if probe {
            self.release_probe();
        }
        Reaction::Keep
    }

    /// Неуспех: в closed копится до порога; в half-open размыкает только
    /// неуспех пробного; в open и в half-open исход старого соединения,
    /// начатого до размыкания, состояние не меняет.
    fn failure(&mut self, now: Instant, probe: bool) -> Reaction {
        match self.state {
            State::Closed => {
                self.failures = self.failures.saturating_add(1);
                if self.failures >= self.config.failure_threshold.max(1) {
                    self.open(now);
                }
            }
            State::HalfOpen { .. } => {
                if probe {
                    self.open(now);
                }
            }
            State::Open { .. } | State::Disabled(_) => {}
        }
        Reaction::Slow
    }

    /// Размыкание: очередная пауза либо окончательное отключение.
    fn open(&mut self, now: Instant) {
        self.failures = 0;
        self.cycles = self.cycles.saturating_add(1);
        self.changed();
        if self.cycles > self.config.max_cycles {
            self.state = State::Disabled(DisableReason::BlockedOrDown);
            return;
        }
        let factor = self
            .config
            .open_multiplier
            .max(1)
            .saturating_pow(self.cycles.saturating_sub(1));
        let pause = self
            .config
            .open_initial
            .saturating_mul(factor)
            .min(self.config.open_max);
        self.state = State::Open {
            until: now.checked_add(pause).unwrap_or(now),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD: u32 = 5;
    const ALLOWED: Decision = Decision::Allowed { probe: false };
    const PROBE: Decision = Decision::Allowed { probe: true };

    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn breaker() -> Breaker {
        Breaker::new(BreakerConfig::default())
    }

    /// Билет пробного соединения, которое сейчас в полёте.
    fn ticket(breaker: &Breaker) -> ProbeTicket {
        breaker.probe_ticket().unwrap()
    }

    /// Сообщает исход пробного соединения, которое сейчас в полёте.
    fn record_probe(breaker: &mut Breaker, outcome: Outcome, now: Instant) -> Reaction {
        let ticket = ticket(breaker);
        breaker.record_probe(ticket, outcome, now)
    }

    /// Breaker, у которого уже было удачное соединение.
    fn warmed_up(now: Instant) -> Breaker {
        let mut breaker = breaker();
        assert_eq!(
            breaker.record(Outcome::ConditionMet, now),
            Reaction::Recover
        );
        breaker
    }

    /// Серия сбросов, размыкающая замкнутый breaker.
    fn trip(breaker: &mut Breaker, now: Instant) {
        for _ in 0..THRESHOLD {
            assert_eq!(breaker.record(Outcome::Reset, now), Reaction::Slow);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn closed_breaker_opens_after_the_threshold_of_failures() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        assert_eq!(breaker.decision(start), ALLOWED);

        for _ in 1..THRESHOLD {
            assert_eq!(breaker.record(Outcome::Reset, start), Reaction::Slow);
            assert_eq!(breaker.state(), BreakerState::Closed);
            assert_eq!(breaker.decision(start), ALLOWED);
        }
        assert_eq!(breaker.record(Outcome::Reset, start), Reaction::Slow);
        assert_eq!(breaker.state(), BreakerState::Open);
        assert_eq!(breaker.cycles(), 1);
        assert_eq!(breaker.decision(start), Decision::Wait(secs(5)));
        // Оставшееся время паузы убывает.
        assert_eq!(breaker.decision(start + secs(3)), Decision::Wait(secs(2)));
        assert_eq!(breaker.disabled(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn every_overload_outcome_counts_as_a_failure() {
        let start = Instant::now();
        let overload: Vec<Outcome> = Outcome::ALL
            .into_iter()
            .filter(|outcome| outcome.signal() == Signal::Overload)
            .collect();
        assert!(!overload.is_empty());
        for outcome in overload {
            let mut breaker = warmed_up(start);
            for _ in 0..THRESHOLD {
                assert_eq!(breaker.record(outcome, start), Reaction::Slow);
            }
            assert_eq!(breaker.state(), BreakerState::Open, "{}", outcome.label());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn server_response_interrupts_the_failure_series() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        for _ in 1..THRESHOLD {
            breaker.record(Outcome::Reset, start);
        }
        // Alert — сервер жив: счёт неуспехов начинается заново.
        assert_eq!(breaker.record(Outcome::FatalAlert, start), Reaction::Keep);
        for _ in 1..THRESHOLD {
            breaker.record(Outcome::Reset, start);
        }
        assert_eq!(breaker.state(), BreakerState::Closed);
        breaker.record(Outcome::Reset, start);
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    #[tokio::test(start_paused = true)]
    async fn server_refusals_never_open_the_breaker() {
        let start = Instant::now();
        let regular = [
            Outcome::FatalAlert,
            Outcome::EofAtMessageBoundary,
            Outcome::Parse,
            Outcome::LimitExceeded,
            Outcome::Deadline,
        ];
        let mut breaker = breaker();
        for _ in 0..200 {
            for outcome in regular {
                assert_eq!(breaker.record(outcome, start), Reaction::Keep);
            }
        }
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert_eq!(breaker.cycles(), 0);
        assert_eq!(breaker.decision(start), ALLOWED);
    }

    #[tokio::test(start_paused = true)]
    async fn half_open_gives_one_probe_and_success_closes() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        trip(&mut breaker, start);

        let after_pause = start + secs(5);
        assert_eq!(breaker.decision(after_pause), PROBE);
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        // Пробное соединение одно: остальные ждут.
        assert_eq!(breaker.decision(after_pause), Decision::ProbeBusy);
        assert_eq!(breaker.decision(after_pause), Decision::ProbeBusy);

        assert_eq!(
            record_probe(&mut breaker, Outcome::ConditionMet, after_pause),
            Reaction::Recover
        );
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert_eq!(breaker.cycles(), 0);
        assert_eq!(breaker.decision(after_pause), ALLOWED);

        // После закрытия порог и первая пауза — как в начале.
        trip(&mut breaker, after_pause);
        assert_eq!(breaker.decision(after_pause), Decision::Wait(secs(5)));
    }

    #[tokio::test(start_paused = true)]
    async fn alert_on_the_probe_closes_the_breaker() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        trip(&mut breaker, start);
        assert_eq!(breaker.decision(start + secs(5)), PROBE);
        assert_eq!(
            record_probe(&mut breaker, Outcome::FatalAlert, start + secs(5)),
            Reaction::Keep
        );
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_probes_lengthen_the_pause_and_then_disable_the_host() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        trip(&mut breaker, start);
        assert_eq!(breaker.decision(start), Decision::Wait(secs(5)));

        // Вторая пауза — 10 с.
        let second = start + secs(5);
        assert_eq!(breaker.decision(second), PROBE);
        assert_eq!(
            record_probe(&mut breaker, Outcome::Reset, second),
            Reaction::Slow
        );
        assert_eq!(breaker.state(), BreakerState::Open);
        assert_eq!(breaker.cycles(), 2);
        assert_eq!(breaker.decision(second), Decision::Wait(secs(10)));

        // Третья — 20 с.
        let third = second + secs(10);
        assert_eq!(breaker.decision(third), PROBE);
        record_probe(&mut breaker, Outcome::HandshakeTimeout, third);
        assert_eq!(breaker.cycles(), 3);
        assert_eq!(breaker.decision(third), Decision::Wait(secs(20)));

        // Четвёртое размыкание — хост отключён окончательно.
        let fourth = third + secs(20);
        assert_eq!(breaker.decision(fourth), PROBE);
        record_probe(&mut breaker, Outcome::ConnectTimeout, fourth);
        assert_eq!(breaker.state(), BreakerState::Disabled);
        assert_eq!(breaker.disabled(), Some(DisableReason::BlockedOrDown));
        assert_eq!(
            breaker.decision(fourth),
            Decision::Disabled(DisableReason::BlockedOrDown)
        );

        // Поздние исходы отключённый хост не оживляют.
        assert_eq!(
            breaker.record(Outcome::ConditionMet, fourth),
            Reaction::Keep
        );
        assert_eq!(
            breaker.decision(fourth + secs(3600)),
            Decision::Disabled(DisableReason::BlockedOrDown)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pause_is_capped_and_zero_cycles_disable_at_once() {
        let start = Instant::now();
        let capped = BreakerConfig {
            open_max: secs(8),
            max_cycles: 4,
            ..BreakerConfig::default()
        };
        let mut breaker = Breaker::new(capped);
        breaker.record(Outcome::ConditionMet, start);
        trip(&mut breaker, start);
        assert_eq!(breaker.decision(start), Decision::Wait(secs(5)));
        let mut now = start + secs(5);
        for _ in 0..3 {
            assert_eq!(breaker.decision(now), PROBE);
            record_probe(&mut breaker, Outcome::Reset, now);
            // 10 с и больше упираются в потолок 8 с.
            assert_eq!(breaker.decision(now), Decision::Wait(secs(8)));
            now += secs(8);
        }

        let strict = BreakerConfig {
            max_cycles: 0,
            ..BreakerConfig::default()
        };
        let mut breaker = Breaker::new(strict);
        breaker.record(Outcome::ConditionMet, start);
        trip(&mut breaker, start);
        assert_eq!(breaker.disabled(), Some(DisableReason::BlockedOrDown));
    }

    #[tokio::test(start_paused = true)]
    async fn outcomes_during_the_pause_do_not_extend_it() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        trip(&mut breaker, start);
        // Исходы соединений, начатых до размыкания.
        for _ in 0..20 {
            breaker.record(Outcome::Reset, start + secs(1));
        }
        assert_eq!(breaker.cycles(), 1);
        assert_eq!(breaker.decision(start + secs(1)), Decision::Wait(secs(4)));
    }

    #[tokio::test(start_paused = true)]
    async fn early_exit_on_the_first_connection() {
        let start = Instant::now();
        let cases = [
            (Outcome::ConnectRefused, DisableReason::PortClosed),
            (Outcome::ConnectUnresolved, DisableReason::Unresolved),
            (Outcome::NotTls, DisableReason::NotTls),
        ];
        for (outcome, reason) in cases {
            let mut breaker = breaker();
            assert_eq!(breaker.record(outcome, start), Reaction::Keep);
            assert_eq!(breaker.state(), BreakerState::Disabled);
            assert_eq!(breaker.disabled(), Some(reason));
            // Без пауз: решение окончательное сразу.
            assert_eq!(breaker.decision(start), Decision::Disabled(reason));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn early_exit_honours_the_configured_retries() {
        let start = Instant::now();
        let config = BreakerConfig {
            early_exit_retries: 1,
            ..BreakerConfig::default()
        };
        let mut breaker = Breaker::new(config);
        breaker.record(Outcome::ConnectRefused, start);
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert_eq!(breaker.decision(start), ALLOWED);
        breaker.record(Outcome::ConnectRefused, start);
        assert_eq!(breaker.disabled(), Some(DisableReason::PortClosed));
    }

    #[tokio::test(start_paused = true)]
    async fn refused_after_an_established_connection_is_overload() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        assert_eq!(
            breaker.record(Outcome::ConnectRefused, start),
            Reaction::Slow
        );
        assert_eq!(breaker.state(), BreakerState::Closed);
        for _ in 1..THRESHOLD {
            breaker.record(Outcome::ConnectRefused, start);
        }
        assert_eq!(breaker.state(), BreakerState::Open);
        assert_eq!(breaker.disabled(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn not_tls_after_a_tls_response_is_neutral() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        for _ in 0..50 {
            assert_eq!(breaker.record(Outcome::NotTls, start), Reaction::Keep);
        }
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn single_eof_before_first_byte_is_neutral_but_a_series_is_not() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);

        // Два подряд — штатный отказ старого стека.
        assert_eq!(
            breaker.record(Outcome::EofBeforeFirstByte, start),
            Reaction::Keep
        );
        assert_eq!(
            breaker.record(Outcome::EofBeforeFirstByte, start),
            Reaction::Keep
        );
        // Ответ сервера обнуляет серию.
        breaker.record(Outcome::FatalAlert, start);
        assert_eq!(
            breaker.record(Outcome::EofBeforeFirstByte, start),
            Reaction::Keep
        );
        assert_eq!(
            breaker.record(Outcome::EofBeforeFirstByte, start),
            Reaction::Keep
        );

        // Третий подряд и дальше — неуспехи: пять неуспехов размыкают.
        for _ in 1..THRESHOLD {
            assert_eq!(
                breaker.record(Outcome::EofBeforeFirstByte, start),
                Reaction::Slow
            );
            assert_eq!(breaker.state(), BreakerState::Closed);
        }
        assert_eq!(
            breaker.record(Outcome::EofBeforeFirstByte, start),
            Reaction::Slow
        );
        assert_eq!(breaker.state(), BreakerState::Open);

        // Пробное соединение с таким EOF — неуспех сразу.
        assert_eq!(breaker.decision(start + secs(5)), PROBE);
        record_probe(&mut breaker, Outcome::ConditionMet, start + secs(5));
        trip(&mut breaker, start + secs(5));
        assert_eq!(breaker.decision(start + secs(10)), PROBE);
        assert_eq!(
            record_probe(&mut breaker, Outcome::EofBeforeFirstByte, start + secs(10)),
            Reaction::Slow
        );
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    #[tokio::test(start_paused = true)]
    async fn local_exhaustion_does_not_penalise_the_host() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        for _ in 0..100 {
            assert_eq!(
                breaker.record(Outcome::LocalExhaustion, start),
                Reaction::Local
            );
        }
        assert_eq!(breaker.state(), BreakerState::Closed);

        // В half-open такой исход самого пробного соединения возвращает
        // его следующему желающему.
        trip(&mut breaker, start);
        let after_pause = start + secs(5);
        assert_eq!(breaker.decision(after_pause), PROBE);
        assert_eq!(
            record_probe(&mut breaker, Outcome::LocalExhaustion, after_pause),
            Reaction::Local
        );
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        assert_eq!(breaker.probe_ticket(), None);
        assert_eq!(breaker.decision(after_pause), PROBE);
    }

    /// A1: нехватка локальных ресурсов у старого соединения не освобождает
    /// пробное, которое ещё в полёте.
    #[tokio::test(start_paused = true)]
    async fn local_exhaustion_of_an_old_connection_keeps_the_probe_in_flight() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        trip(&mut breaker, start);
        let after_pause = start + secs(5);
        assert_eq!(breaker.decision(after_pause), PROBE);
        let probe = ticket(&breaker);

        for _ in 0..10 {
            assert_eq!(
                breaker.record(Outcome::LocalExhaustion, after_pause),
                Reaction::Local
            );
            assert_eq!(breaker.state(), BreakerState::HalfOpen);
            assert_eq!(breaker.probe_ticket(), Some(probe));
            assert_eq!(breaker.decision(after_pause), Decision::ProbeBusy);
        }

        assert_eq!(
            breaker.record_probe(probe, Outcome::ConditionMet, after_pause),
            Reaction::Recover
        );
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn overload_of_an_old_connection_does_not_reopen_half_open() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        trip(&mut breaker, start);
        let after_pause = start + secs(5);
        assert_eq!(breaker.decision(after_pause), PROBE);
        let probe = ticket(&breaker);

        // Соединения, начатые до размыкания, заканчиваются уже в half-open:
        // AIMD замедляется, но решает только пробное.
        let old = [
            Outcome::Reset,
            Outcome::ReadTimeout,
            Outcome::ConnectRefused,
            Outcome::EofBeforeFirstByte,
            Outcome::EofBeforeFirstByte,
            Outcome::EofBeforeFirstByte,
        ];
        for outcome in old {
            breaker.record(outcome, after_pause);
            assert_eq!(
                breaker.state(),
                BreakerState::HalfOpen,
                "{}",
                outcome.label()
            );
            assert_eq!(breaker.cycles(), 1);
            assert_eq!(breaker.probe_ticket(), Some(probe));
            assert_eq!(breaker.decision(after_pause), Decision::ProbeBusy);
        }
        assert_eq!(breaker.record(Outcome::Reset, after_pause), Reaction::Slow);

        // Неуспех самого пробного размыкает со следующей паузой.
        assert_eq!(
            breaker.record_probe(probe, Outcome::Reset, after_pause),
            Reaction::Slow
        );
        assert_eq!(breaker.state(), BreakerState::Open);
        assert_eq!(breaker.cycles(), 2);
        assert_eq!(breaker.decision(after_pause), Decision::Wait(secs(10)));
    }

    #[tokio::test(start_paused = true)]
    async fn response_on_an_old_connection_closes_and_outdates_the_probe_ticket() {
        let start = Instant::now();
        for outcome in [Outcome::ConditionMet, Outcome::FatalAlert, Outcome::NotTls] {
            let mut breaker = warmed_up(start);
            trip(&mut breaker, start);
            let after_pause = start + secs(5);
            assert_eq!(breaker.decision(after_pause), PROBE);
            let stale = ticket(&breaker);

            // Сервер ответил по старому соединению: breaker замкнут.
            breaker.record(outcome, after_pause);
            assert_eq!(breaker.state(), BreakerState::Closed, "{}", outcome.label());
            assert_eq!(breaker.cycles(), 0);
            assert_eq!(breaker.probe_ticket(), None);
            assert_eq!(breaker.decision(after_pause), ALLOWED);

            // Исход бывшего пробного учитывается как обычный: один неуспех
            // замкнутый breaker не размыкает.
            assert_eq!(
                breaker.record_probe(stale, Outcome::Reset, after_pause),
                Reaction::Slow
            );
            assert_eq!(breaker.state(), BreakerState::Closed);

            // Новый цикл: пробное с новым билетом; устаревший билет его не
            // освобождает и не решает его судьбу.
            trip(&mut breaker, after_pause);
            let next_pause = after_pause + secs(5);
            assert_eq!(breaker.decision(next_pause), PROBE);
            let current = ticket(&breaker);
            assert_ne!(current, stale);
            breaker.abandon_probe(stale);
            assert_eq!(breaker.decision(next_pause), Decision::ProbeBusy);
            assert_eq!(
                breaker.record_probe(stale, Outcome::LocalExhaustion, next_pause),
                Reaction::Local
            );
            assert_eq!(breaker.probe_ticket(), Some(current));
            assert_eq!(
                breaker.record_probe(stale, Outcome::Reset, next_pause),
                Reaction::Slow
            );
            assert_eq!(breaker.state(), BreakerState::HalfOpen);
            assert_eq!(breaker.decision(next_pause), Decision::ProbeBusy);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn early_exit_retry_releases_the_probe_only_for_its_own_outcome() {
        let start = Instant::now();
        let config = BreakerConfig {
            early_exit_retries: 1,
            ..BreakerConfig::default()
        };
        let after_pause = start + secs(5);

        // Размыкание таймаутами connect: ни одного установленного
        // соединения, отказ остаётся ранним выходом.
        let tripped = || {
            let mut breaker = Breaker::new(config);
            for _ in 0..THRESHOLD {
                breaker.record(Outcome::ConnectTimeout, start);
            }
            assert_eq!(breaker.decision(after_pause), PROBE);
            breaker
        };

        // Отказ старого соединения: повтор ещё есть, пробное не тронуто.
        let mut breaker = tripped();
        let probe = ticket(&breaker);
        assert_eq!(
            breaker.record(Outcome::ConnectRefused, after_pause),
            Reaction::Keep
        );
        assert_eq!(breaker.probe_ticket(), Some(probe));
        assert_eq!(breaker.decision(after_pause), Decision::ProbeBusy);
        // Повторы исчерпаны: хост отключён, кто бы ни сообщил исход.
        breaker.record(Outcome::ConnectRefused, after_pause);
        assert_eq!(breaker.disabled(), Some(DisableReason::PortClosed));
        assert_eq!(
            breaker.decision(after_pause),
            Decision::Disabled(DisableReason::PortClosed)
        );

        // Тот же отказ на самом пробном: оно возвращается.
        let mut breaker = tripped();
        assert_eq!(
            record_probe(&mut breaker, Outcome::ConnectRefused, after_pause),
            Reaction::Keep
        );
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        assert_eq!(breaker.decision(after_pause), PROBE);
    }

    #[tokio::test(start_paused = true)]
    async fn abandoned_probe_goes_to_the_next_caller() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        assert_eq!(breaker.probe_ticket(), None);

        trip(&mut breaker, start);
        let after_pause = start + secs(5);
        assert_eq!(breaker.decision(after_pause), PROBE);
        let first = ticket(&breaker);
        assert_eq!(breaker.decision(after_pause), Decision::ProbeBusy);
        breaker.abandon_probe(first);
        assert_eq!(breaker.decision(after_pause), PROBE);
        assert_eq!(breaker.cycles(), 1);

        // Повторный возврат тем же билетом новое пробное не освобождает.
        let second = ticket(&breaker);
        assert_ne!(first, second);
        breaker.abandon_probe(first);
        assert_eq!(breaker.decision(after_pause), Decision::ProbeBusy);

        // В замкнутом состоянии возврат ничего не меняет.
        breaker.record_probe(second, Outcome::ConditionMet, after_pause);
        breaker.abandon_probe(second);
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn revision_changes_only_when_waiters_may_get_a_new_decision() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        let initial = breaker.revision();

        // Исходы, не меняющие решение, ожидающих не будят.
        breaker.record(Outcome::FatalAlert, start);
        breaker.record(Outcome::Reset, start);
        breaker.record(Outcome::LocalExhaustion, start);
        assert_eq!(breaker.revision(), initial);

        // Размыкание.
        trip(&mut breaker, start);
        let opened = breaker.revision();
        assert_ne!(opened, initial);

        // Выдача пробного никого не будит: ждать по-прежнему нужно.
        let after_pause = start + secs(5);
        assert_eq!(breaker.decision(after_pause), PROBE);
        assert_eq!(breaker.decision(after_pause), Decision::ProbeBusy);
        breaker.record(Outcome::LocalExhaustion, after_pause);
        breaker.record(Outcome::Reset, after_pause);
        assert_eq!(breaker.revision(), opened);

        // Возврат пробного.
        let probe = ticket(&breaker);
        breaker.abandon_probe(probe);
        let released = breaker.revision();
        assert_ne!(released, opened);
        breaker.abandon_probe(probe);
        assert_eq!(breaker.revision(), released);

        // Замыкание.
        assert_eq!(breaker.decision(after_pause), PROBE);
        record_probe(&mut breaker, Outcome::ConditionMet, after_pause);
        let closed = breaker.revision();
        assert_ne!(closed, released);

        // Отключение.
        let mut fresh = Breaker::new(BreakerConfig::default());
        let before = fresh.revision();
        fresh.record(Outcome::ConnectRefused, start);
        assert_eq!(fresh.disabled(), Some(DisableReason::PortClosed));
        assert_ne!(fresh.revision(), before);
    }

    #[tokio::test(start_paused = true)]
    async fn memo_keeps_only_what_the_next_target_must_inherit() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        assert_eq!(breaker.memo(), None, "замкнутый breaker");

        // Пауза размыкания с числом циклов.
        trip(&mut breaker, start);
        assert_eq!(
            breaker.memo(),
            Some(BreakerMemo::Open {
                until: start + secs(5),
                cycles: 1,
            })
        );

        // Half-open: пауза истекла, запоминать нечего.
        let after_pause = start + secs(5);
        assert_eq!(breaker.decision(after_pause), PROBE);
        assert_eq!(breaker.memo(), None);

        // Отключение по исчерпании циклов — причина уровня хоста.
        let strict = BreakerConfig {
            max_cycles: 0,
            ..BreakerConfig::default()
        };
        let mut breaker = Breaker::new(strict);
        breaker.record(Outcome::ConditionMet, start);
        trip(&mut breaker, start);
        assert_eq!(
            breaker.memo(),
            Some(BreakerMemo::Disabled(DisableReason::BlockedOrDown))
        );

        // Причины, относящиеся к порту или имени, на адрес не запоминаются.
        let port_level = [
            Outcome::ConnectRefused,
            Outcome::ConnectUnresolved,
            Outcome::NotTls,
        ];
        for outcome in port_level {
            let mut breaker = Breaker::new(BreakerConfig::default());
            breaker.record(outcome, start);
            assert_eq!(breaker.state(), BreakerState::Disabled);
            assert_eq!(breaker.memo(), None, "{}", outcome.label());
        }
        let host_wide: Vec<DisableReason> = DisableReason::ALL
            .into_iter()
            .filter(|reason| reason.is_host_wide())
            .collect();
        assert_eq!(host_wide, vec![DisableReason::BlockedOrDown]);
    }

    #[tokio::test(start_paused = true)]
    async fn restored_breaker_continues_from_the_snapshot() {
        let start = Instant::now();
        let config = BreakerConfig::default();

        let disabled =
            Breaker::restore(config, BreakerMemo::Disabled(DisableReason::BlockedOrDown));
        assert_eq!(disabled.disabled(), Some(DisableReason::BlockedOrDown));
        assert_eq!(
            disabled.memo(),
            Some(BreakerMemo::Disabled(DisableReason::BlockedOrDown))
        );

        // Пауза третьего цикла: неуспех пробного после неё отключает хост,
        // как если бы состояние не терялось.
        let memo = BreakerMemo::Open {
            until: start + secs(20),
            cycles: 3,
        };
        let mut breaker = Breaker::restore(config, memo);
        assert_eq!(breaker.state(), BreakerState::Open);
        assert_eq!(breaker.cycles(), 3);
        assert_eq!(breaker.memo(), Some(memo));
        assert_eq!(breaker.decision(start + secs(4)), Decision::Wait(secs(16)));
        assert_eq!(breaker.decision(start + secs(20)), PROBE);
        record_probe(&mut breaker, Outcome::ConnectTimeout, start + secs(20));
        assert_eq!(breaker.disabled(), Some(DisableReason::BlockedOrDown));

        // Ответ на пробное замыкает восстановленный breaker.
        let mut breaker = Breaker::restore(config, memo);
        assert_eq!(breaker.decision(start + secs(20)), PROBE);
        record_probe(&mut breaker, Outcome::FatalAlert, start + secs(20));
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert_eq!(breaker.cycles(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn degenerate_thresholds_are_clamped() {
        let start = Instant::now();
        let config = BreakerConfig {
            failure_threshold: 0,
            ambiguous_eof_threshold: 0,
            open_multiplier: 0,
            ..BreakerConfig::default()
        };
        let mut breaker = Breaker::new(config);
        breaker.record(Outcome::ConditionMet, start);
        // Порог 0 трактуется как 1: первый же EOF до первого байта — неуспех
        // и размыкание.
        assert_eq!(
            breaker.record(Outcome::EofBeforeFirstByte, start),
            Reaction::Slow
        );
        assert_eq!(breaker.decision(start), Decision::Wait(secs(5)));
        // Множитель 0 трактуется как 1: пауза не растёт.
        assert_eq!(breaker.decision(start + secs(5)), PROBE);
        record_probe(&mut breaker, Outcome::Reset, start + secs(5));
        assert_eq!(breaker.decision(start + secs(5)), Decision::Wait(secs(5)));
    }

    #[test]
    fn reason_labels_are_distinct_and_match_the_plan() {
        let mut labels: Vec<&str> = DisableReason::ALL
            .into_iter()
            .map(DisableReason::label)
            .collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), REASONS);
        assert_eq!(DisableReason::PortClosed.label(), "unreachable");
        assert_eq!(DisableReason::NotTls.label(), "not_tls");
        assert_eq!(DisableReason::BlockedOrDown.label(), "blocked_or_down");
    }
}
