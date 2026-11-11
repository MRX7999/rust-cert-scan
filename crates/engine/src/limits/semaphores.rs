//! Семафор с изменяемым лимитом и таблица состояния хостов.
//!
//! # [`AdjustableSemaphore`]
//!
//! Обёртка над `tokio::sync::Semaphore`: очередь ожидающих — FIFO, сброс
//! ожидающего future ничего не захватывает (свойства семафора tokio).
//! Добавлено изменение лимита на ходу — оно нужно адаптивному backoff и
//! глобальной защите сканирующей машины:
//!
//! - повышение лимита добавляет слоты;
//! - понижение сначала забирает свободные слоты, а если их не хватило,
//!   записывает остаток в «долг»: очередные освобождаемые слоты не
//!   возвращаются в семафор, пока долг не погашен. Уже выданные разрешения
//!   не отзываются.
//!
//! Инвариант: `выдано + свободно = лимит + долг`.
//!
//! # [`HostTable`]
//!
//! Состояние на хост создаётся лениво при первом обращении и живёт, пока на
//! него есть сильные ссылки. Таблица хранит слабые ссылки; запись удаляется
//! в `Drop` последней сильной. Поэтому размер таблицы равен числу хостов, с
//! которыми сейчас идёт работа, и не зависит от числа целей в скане.

use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Семафор с изменяемым лимитом; описание — в документации модуля.
#[derive(Debug, Clone)]
pub struct AdjustableSemaphore {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    semaphore: Arc<Semaphore>,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Действующий лимит.
    limit: usize,
    /// Сколько выданных слотов нужно изъять при освобождении.
    debt: usize,
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Приводит лимит к допустимому диапазону: не меньше 1 и не больше
/// наибольшего числа слотов семафора tokio.
fn clamp_limit(limit: usize) -> usize {
    limit.clamp(1, Semaphore::MAX_PERMITS)
}

impl AdjustableSemaphore {
    /// Семафор с лимитом `limit`; значение меньше 1 трактуется как 1,
    /// слишком большое — как наибольшее допустимое (практически «без
    /// ограничения»).
    #[must_use]
    pub fn new(limit: usize) -> Self {
        let limit = clamp_limit(limit);
        Self {
            inner: Arc::new(Inner {
                semaphore: Arc::new(Semaphore::new(limit)),
                state: Mutex::new(State { limit, debt: 0 }),
            }),
        }
    }

    /// Действующий лимит.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.inner.state().limit
    }

    /// Число выданных и ещё не освобождённых разрешений.
    #[must_use]
    pub fn in_use(&self) -> usize {
        let state = self.inner.state();
        state
            .limit
            .saturating_add(state.debt)
            .saturating_sub(self.inner.semaphore.available_permits())
    }

    /// Меняет лимит; значение приводится к допустимому диапазону. Выданные
    /// разрешения не отзываются: при понижении новые разрешения не
    /// выдаются, пока число выданных не опустится ниже нового лимита.
    pub fn set_limit(&self, limit: usize) {
        let limit = clamp_limit(limit);
        let mut state = self.inner.state();
        if limit >= state.limit {
            let raise = limit.saturating_sub(state.limit);
            let repaid = raise.min(state.debt);
            state.debt = state.debt.saturating_sub(repaid);
            let added = raise.saturating_sub(repaid);
            if added > 0 {
                self.inner.semaphore.add_permits(added);
            }
        } else {
            let lower = state.limit.saturating_sub(limit);
            let taken = self.inner.semaphore.forget_permits(lower);
            state.debt = state.debt.saturating_add(lower.saturating_sub(taken));
        }
        state.limit = limit;
    }

    /// Разрешение без ожидания; `None`, если свободных слотов нет.
    #[must_use]
    pub fn try_acquire(&self) -> Option<SlotPermit> {
        let permit = Arc::clone(&self.inner.semaphore).try_acquire_owned().ok()?;
        Some(self.wrap(permit))
    }

    /// Ждёт свободный слот. Ожидающие обслуживаются в порядке прихода;
    /// сброс future ничего не захватывает.
    pub async fn acquire(&self) -> SlotPermit {
        match Arc::clone(&self.inner.semaphore).acquire_owned().await {
            Ok(permit) => self.wrap(permit),
            // Семафор не закрывается никогда: `close` нигде не вызывается.
            // Ветка недостижима; вечное ожидание вместо паники.
            Err(_closed) => std::future::pending().await,
        }
    }

    fn wrap(&self, permit: OwnedSemaphorePermit) -> SlotPermit {
        SlotPermit {
            permit: Some(permit),
            owner: Arc::clone(&self.inner),
        }
    }
}

/// Разрешение [`AdjustableSemaphore`]; слот освобождается при drop.
#[derive(Debug)]
pub struct SlotPermit {
    permit: Option<OwnedSemaphorePermit>,
    owner: Arc<Inner>,
}

impl Drop for SlotPermit {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let mut state = self.owner.state();
        if state.debt > 0 {
            // Лимит был понижен, пока слот был занят: слот изымается.
            state.debt = state.debt.saturating_sub(1);
            permit.forget();
        } else {
            // Возврат под замком: иначе параллельное понижение лимита
            // могло бы учесть этот слот дважды.
            drop(permit);
        }
    }
}

/// Таблица состояния хостов; описание — в документации модуля.
#[derive(Debug)]
pub struct HostTable<T> {
    inner: Arc<TableInner<T>>,
}

#[derive(Debug)]
struct TableInner<T> {
    map: Mutex<HashMap<IpAddr, Weak<HostEntry<T>>>>,
}

impl<T> TableInner<T> {
    fn map(&self) -> MutexGuard<'_, HashMap<IpAddr, Weak<HostEntry<T>>>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Состояние одного хоста в [`HostTable`]; разыменовывается в `T`. При
/// drop последней ссылки запись удаляется из таблицы.
#[derive(Debug)]
pub struct HostEntry<T> {
    key: IpAddr,
    table: Arc<TableInner<T>>,
    value: T,
}

impl<T> HostEntry<T> {
    /// Адрес хоста — ключ записи.
    #[must_use]
    pub fn key(&self) -> IpAddr {
        self.key
    }
}

impl<T> Deref for HostEntry<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> Drop for HostEntry<T> {
    fn drop(&mut self) {
        let mut map = self.table.map();
        // Пока этот drop ждал замок, другая задача могла создать для того
        // же адреса новую запись — её удалять нельзя. Запись удаляется,
        // только если её слабая ссылка мертва (то есть указывает на нас).
        let dead = map
            .get(&self.key)
            .is_some_and(|entry| entry.strong_count() == 0);
        if dead {
            map.remove(&self.key);
        }
    }
}

impl<T> Default for HostTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> HostTable<T> {
    /// Пустая таблица.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TableInner {
                map: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Состояние хоста `key`: существующее либо созданное вызовом `create`.
    pub fn get_or_create(&self, key: IpAddr, create: impl FnOnce() -> T) -> Arc<HostEntry<T>> {
        let mut map = self.inner.map();
        if let Some(existing) = map.get(&key).and_then(Weak::upgrade) {
            return existing;
        }
        let entry = Arc::new(HostEntry {
            key,
            table: Arc::clone(&self.inner),
            value: create(),
        });
        map.insert(key, Arc::downgrade(&entry));
        entry
    }

    /// Состояние хоста `key`, если с ним сейчас идёт работа.
    #[must_use]
    pub fn get(&self, key: IpAddr) -> Option<Arc<HostEntry<T>>> {
        self.inner.map().get(&key).and_then(Weak::upgrade)
    }

    /// Число хостов, с которыми сейчас идёт работа.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.map().len()
    }

    /// Истина, если активных хостов нет.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.map().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn permits_are_limited_and_released_on_drop() {
        let semaphore = AdjustableSemaphore::new(2);
        assert_eq!(semaphore.limit(), 2);
        let first = semaphore.try_acquire().unwrap();
        let second = semaphore.try_acquire().unwrap();
        assert_eq!(semaphore.in_use(), 2);
        assert!(semaphore.try_acquire().is_none());

        drop(first);
        assert_eq!(semaphore.in_use(), 1);
        let third = semaphore.try_acquire().unwrap();
        assert!(semaphore.try_acquire().is_none());
        drop((second, third));
        assert_eq!(semaphore.in_use(), 0);
    }

    #[test]
    fn zero_limit_is_treated_as_one_and_huge_limit_is_clamped() {
        let semaphore = AdjustableSemaphore::new(0);
        assert_eq!(semaphore.limit(), 1);
        let _permit = semaphore.try_acquire().unwrap();
        assert!(semaphore.try_acquire().is_none());
        semaphore.set_limit(0);
        assert_eq!(semaphore.limit(), 1);

        let unlimited = AdjustableSemaphore::new(usize::MAX);
        assert_eq!(unlimited.limit(), Semaphore::MAX_PERMITS);
    }

    #[test]
    fn lowering_takes_free_slots_first() {
        let semaphore = AdjustableSemaphore::new(4);
        let held = semaphore.try_acquire().unwrap();
        semaphore.set_limit(2);
        assert_eq!(semaphore.limit(), 2);
        assert_eq!(semaphore.in_use(), 1);
        let second = semaphore.try_acquire().unwrap();
        assert!(semaphore.try_acquire().is_none());
        drop((held, second));
        assert_eq!(semaphore.in_use(), 0);
    }

    #[test]
    fn lowering_below_the_number_in_use_creates_debt() {
        let semaphore = AdjustableSemaphore::new(4);
        let mut held: Vec<SlotPermit> = (0..4).map(|_| semaphore.try_acquire().unwrap()).collect();
        semaphore.set_limit(1);
        assert_eq!(semaphore.in_use(), 4, "выданные разрешения не отзываются");

        // Три освобождения гасят долг, новых слотов не появляется.
        for expected_in_use in (1..=3_usize).rev() {
            drop(held.pop());
            assert_eq!(semaphore.in_use(), expected_in_use);
            assert!(semaphore.try_acquire().is_none());
        }
        // Четвёртое освобождение возвращает единственный слот.
        drop(held.pop());
        assert_eq!(semaphore.in_use(), 0);
        let only = semaphore.try_acquire().unwrap();
        assert!(semaphore.try_acquire().is_none());
        drop(only);
    }

    #[test]
    fn raising_repays_debt_before_adding_slots() {
        let semaphore = AdjustableSemaphore::new(4);
        let held: Vec<SlotPermit> = (0..4).map(|_| semaphore.try_acquire().unwrap()).collect();
        semaphore.set_limit(1);
        // Долг 3. Подъём до 3 гасит два слота долга и ничего не добавляет.
        semaphore.set_limit(3);
        assert_eq!(semaphore.limit(), 3);
        assert_eq!(semaphore.in_use(), 4);
        assert!(semaphore.try_acquire().is_none());
        // Подъём до 5 гасит остаток долга и добавляет один слот.
        semaphore.set_limit(5);
        let extra = semaphore.try_acquire().unwrap();
        assert!(semaphore.try_acquire().is_none());
        assert_eq!(semaphore.in_use(), 5);
        drop(held);
        drop(extra);
        assert_eq!(semaphore.in_use(), 0);
        let all: Vec<SlotPermit> = (0..5).map(|_| semaphore.try_acquire().unwrap()).collect();
        assert!(semaphore.try_acquire().is_none());
        drop(all);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_wait_does_not_leak_a_slot() {
        let semaphore = AdjustableSemaphore::new(1);
        let held = semaphore.acquire().await;

        let waiting = tokio::time::timeout(Duration::from_secs(1), semaphore.acquire()).await;
        assert!(waiting.is_err(), "ожидание прервано таймаутом");
        assert_eq!(semaphore.in_use(), 1);

        drop(held);
        assert_eq!(semaphore.in_use(), 0);
        let again = tokio::time::timeout(Duration::from_secs(1), semaphore.acquire()).await;
        assert!(again.is_ok(), "слот свободен после отмены");
    }

    #[tokio::test(start_paused = true)]
    async fn waiters_get_slots_in_arrival_order() {
        let semaphore = AdjustableSemaphore::new(1);
        let held = semaphore.acquire().await;
        let order = Arc::new(Mutex::new(Vec::new()));

        let mut tasks = Vec::new();
        for id in 0..5_u32 {
            let semaphore = semaphore.clone();
            let order = Arc::clone(&order);
            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await;
                order.lock().unwrap().push(id);
            }));
            tokio::task::yield_now().await;
        }
        drop(held);
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(*order.lock().unwrap(), (0..5).collect::<Vec<u32>>());
    }

    #[test]
    fn host_state_is_created_lazily_and_shared() {
        let table: HostTable<u32> = HostTable::new();
        assert!(table.is_empty());
        assert!(table.get(ip(1)).is_none());

        let mut created = 0_u32;
        let first = table.get_or_create(ip(1), || {
            created += 1;
            7
        });
        let again = table.get_or_create(ip(1), || {
            created += 1;
            8
        });
        assert_eq!(created, 1, "состояние создаётся один раз");
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(**first, 7);
        assert_eq!(first.key(), ip(1));
        assert_eq!(table.len(), 1);
        assert!(table.get(ip(1)).is_some());

        let other = table.get_or_create(ip(2), || 9);
        assert_eq!(**other, 9);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn host_state_is_removed_with_the_last_reference() {
        let table: HostTable<u32> = HostTable::new();
        let first = table.get_or_create(ip(1), || 1);
        let alias = Arc::clone(&first);
        let other = table.get_or_create(ip(2), || 2);

        drop(first);
        assert_eq!(table.len(), 2, "на хост ещё есть ссылка");
        drop(alias);
        assert_eq!(table.len(), 1);
        assert!(table.get(ip(1)).is_none());

        // Повторное обращение создаёт состояние заново.
        let recreated = table.get_or_create(ip(1), || 10);
        assert_eq!(**recreated, 10);
        drop(recreated);
        drop(other);
        assert!(table.is_empty());
    }

    #[test]
    fn table_does_not_grow_with_the_number_of_finished_hosts() {
        let table: HostTable<u64> = HostTable::new();
        let mut peak = 0_usize;
        for index in 0..100_000_u32 {
            let address = IpAddr::V4(Ipv4Addr::from(0x0A00_0000_u32 + index));
            let entry = table.get_or_create(address, || u64::from(index));
            peak = peak.max(table.len());
            drop(entry);
        }
        assert_eq!(peak, 1);
        assert!(table.is_empty());
    }
}
