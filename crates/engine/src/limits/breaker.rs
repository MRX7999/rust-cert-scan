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
//! | half-open | одно пробное, остальным [`Decision::Wait`] | ответ сервера → closed; неуспех → open с более длинной паузой |
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
//! - `Local` — нехватка ресурсов сканирующей машины: хост не штрафуется,
//!   пробное соединение возвращается следующему желающему.
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
    /// Через сколько повторить запрос решения, пока пробное соединение
    /// half-open занято другой задачей.
    pub half_open_poll: Duration,
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
            half_open_poll: Duration::from_millis(250),
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

/// Решение о новом соединении с хостом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Соединение разрешено.
    Allowed {
        /// Истина для пробного соединения half-open. Если оно не
        /// состоится, его нужно вернуть вызовом
        /// [`Breaker::abandon_probe`].
        probe: bool,
    },
    /// Соединения временно не выдаются; запрос повторить через указанное
    /// время.
    Wait(Duration),
    /// Работа с хостом прекращена.
    Disabled(DisableReason),
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

    /// Решение о новом соединении в момент `now`. Истёкшая пауза переводит
    /// breaker в half-open и выдаёт пробное соединение вызывающему.
    pub fn decision(&mut self, now: Instant) -> Decision {
        match self.state {
            State::Closed => Decision::Allowed { probe: false },
            State::Disabled(reason) => Decision::Disabled(reason),
            State::Open { until } => match until.checked_duration_since(now) {
                Some(left) if !left.is_zero() => Decision::Wait(left),
                _ => {
                    self.state = State::HalfOpen {
                        probe_in_flight: true,
                    };
                    Decision::Allowed { probe: true }
                }
            },
            State::HalfOpen { probe_in_flight } => {
                if probe_in_flight {
                    Decision::Wait(self.config.half_open_poll)
                } else {
                    self.state = State::HalfOpen {
                        probe_in_flight: true,
                    };
                    Decision::Allowed { probe: true }
                }
            }
        }
    }

    /// Возвращает пробное соединение half-open: оно не состоялось (отмена
    /// до connect) либо закончилось исходом, который ничего не говорит о
    /// хосте. В остальных состояниях ничего не делает.
    pub fn abandon_probe(&mut self) {
        if let State::HalfOpen { .. } = self.state {
            self.state = State::HalfOpen {
                probe_in_flight: false,
            };
        }
    }

    /// Учитывает исход соединения или обмена, завершившегося в момент
    /// `now`, и возвращает реакцию для AIMD. Исходы, пришедшие после
    /// отключения хоста, игнорируются.
    pub fn record(&mut self, outcome: Outcome, now: Instant) -> Reaction {
        if matches!(self.state, State::Disabled(_)) {
            return Reaction::Keep;
        }
        if !is_connect_stage(outcome) {
            self.connected = true;
        }
        match outcome.signal() {
            Signal::Local => {
                self.abandon_probe();
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
                    self.early_exit(DisableReason::NotTls)
                }
            }
            Signal::Unresolved => self.early_exit(DisableReason::Unresolved),
            Signal::Refused => {
                if self.connected {
                    self.eof_streak = 0;
                    self.failure(now)
                } else {
                    self.early_exit(DisableReason::PortClosed)
                }
            }
            Signal::AmbiguousEof => {
                self.eof_streak = self.eof_streak.saturating_add(1);
                let series = self.eof_streak >= self.config.ambiguous_eof_threshold.max(1);
                let probing = matches!(self.state, State::HalfOpen { .. });
                if series || probing {
                    self.failure(now)
                } else {
                    Reaction::Keep
                }
            }
            Signal::Overload => {
                self.eof_streak = 0;
                self.failure(now)
            }
        }
    }

    /// Сервер ответил по TLS: серии обнуляются, half-open закрывается.
    fn alive(&mut self) {
        self.responded = true;
        self.failures = 0;
        self.eof_streak = 0;
        self.early_failures = 0;
        if let State::HalfOpen { .. } = self.state {
            self.state = State::Closed;
            self.cycles = 0;
        }
    }

    /// Исход раннего выхода: хост отключается, когда повторы исчерпаны.
    fn early_exit(&mut self, reason: DisableReason) -> Reaction {
        self.early_failures = self.early_failures.saturating_add(1);
        if self.early_failures > self.config.early_exit_retries {
            self.state = State::Disabled(reason);
        } else {
            self.abandon_probe();
        }
        Reaction::Keep
    }

    /// Неуспех: в closed копится до порога, в half-open размыкает сразу, в
    /// open (исход соединения, начатого до размыкания) ничего не меняет.
    fn failure(&mut self, now: Instant) -> Reaction {
        self.failures = self.failures.saturating_add(1);
        match self.state {
            State::Closed => {
                if self.failures >= self.config.failure_threshold.max(1) {
                    self.open(now);
                }
            }
            State::HalfOpen { .. } => self.open(now),
            State::Open { .. } | State::Disabled(_) => {}
        }
        Reaction::Slow
    }

    /// Размыкание: очередная пауза либо окончательное отключение.
    fn open(&mut self, now: Instant) {
        self.failures = 0;
        self.cycles = self.cycles.saturating_add(1);
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
    const POLL: Duration = Duration::from_millis(250);
    const ALLOWED: Decision = Decision::Allowed { probe: false };
    const PROBE: Decision = Decision::Allowed { probe: true };

    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn breaker() -> Breaker {
        Breaker::new(BreakerConfig::default())
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
        assert_eq!(breaker.decision(after_pause), Decision::Wait(POLL));
        assert_eq!(breaker.decision(after_pause), Decision::Wait(POLL));

        assert_eq!(
            breaker.record(Outcome::ConditionMet, after_pause),
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
            breaker.record(Outcome::FatalAlert, start + secs(5)),
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
        assert_eq!(breaker.record(Outcome::Reset, second), Reaction::Slow);
        assert_eq!(breaker.state(), BreakerState::Open);
        assert_eq!(breaker.cycles(), 2);
        assert_eq!(breaker.decision(second), Decision::Wait(secs(10)));

        // Третья — 20 с.
        let third = second + secs(10);
        assert_eq!(breaker.decision(third), PROBE);
        breaker.record(Outcome::HandshakeTimeout, third);
        assert_eq!(breaker.cycles(), 3);
        assert_eq!(breaker.decision(third), Decision::Wait(secs(20)));

        // Четвёртое размыкание — хост отключён окончательно.
        let fourth = third + secs(20);
        assert_eq!(breaker.decision(fourth), PROBE);
        breaker.record(Outcome::ConnectTimeout, fourth);
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
            breaker.record(Outcome::Reset, now);
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
        breaker.record(Outcome::ConditionMet, start + secs(5));
        trip(&mut breaker, start + secs(5));
        assert_eq!(breaker.decision(start + secs(10)), PROBE);
        assert_eq!(
            breaker.record(Outcome::EofBeforeFirstByte, start + secs(10)),
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

        // В half-open такой исход возвращает пробное соединение.
        trip(&mut breaker, start);
        let after_pause = start + secs(5);
        assert_eq!(breaker.decision(after_pause), PROBE);
        assert_eq!(
            breaker.record(Outcome::LocalExhaustion, after_pause),
            Reaction::Local
        );
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        assert_eq!(breaker.decision(after_pause), PROBE);
    }

    #[tokio::test(start_paused = true)]
    async fn abandoned_probe_goes_to_the_next_caller() {
        let start = Instant::now();
        let mut breaker = warmed_up(start);
        // В замкнутом состоянии вызов ничего не меняет.
        breaker.abandon_probe();
        assert_eq!(breaker.state(), BreakerState::Closed);

        trip(&mut breaker, start);
        let after_pause = start + secs(5);
        assert_eq!(breaker.decision(after_pause), PROBE);
        assert_eq!(breaker.decision(after_pause), Decision::Wait(POLL));
        breaker.abandon_probe();
        assert_eq!(breaker.decision(after_pause), PROBE);
        assert_eq!(breaker.cycles(), 1);
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
        breaker.record(Outcome::Reset, start + secs(5));
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
