//! Разрешение имён: trait [`Resolver`], системный резолвер и кэш [`DnsCache`].
//!
//! # Резолвер
//!
//! [`SystemResolver`] обращается к системному резолверу через
//! [`tokio::net::lookup_host`] (внутри — `getaddrinfo` в блокирующем пуле
//! tokio); отдельного DNS-крейта нет. Резолвер спрятан за trait'ом, чтобы
//! тесты работали без сети и чтобы позже его можно было заменить.
//!
//! # Кэш
//!
//! Системный резолвер TTL не отдаёт, поэтому время жизни записи задаётся
//! конфигурацией: [`DnsCacheConfig::positive_ttl`] для успешных ответов и
//! меньшее [`DnsCacheConfig::negative_ttl`] для отказов (включая таймаут
//! резолва и пустой ответ). Значения по умолчанию предварительные —
//! `docs/DECISIONS.md`, D-17.
//!
//! Размер кэша ограничен [`DnsCacheConfig::capacity`]. При переполнении
//! сначала удаляются истёкшие записи, затем — запись с самым ранним сроком
//! истечения. Резолвы, которые ещё выполняются, не вытесняются: если места
//! нет, новый ответ просто не кэшируется.
//!
//! Параллельные запросы одного имени ждут один и тот же резолв: запись
//! попадает в таблицу до обращения к резолверу, и все запросы сходятся на
//! одной ячейке [`OnceCell`]. Если запрос, начавший резолв, отменён, резолв
//! заново начинает один из ожидающих; два обращения к резолверу одновременно
//! не выполняются никогда.
//!
//! Кэш хранит адреса обоих семейств в порядке, в котором их вернул резолвер
//! (системный резолвер уже упорядочил их по RFC 6724); фильтр по семейству
//! применяется после кэша, в [`DnsCache::resolve_target`], и этот порядок
//! сохраняет.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::OnceCell;
use tokio::time::Instant;

/// Число записей кэша по умолчанию (предварительное значение, D-17).
pub const DEFAULT_DNS_CACHE_CAPACITY: usize = 1024;

/// Время жизни успешного ответа по умолчанию (предварительное значение,
/// D-17).
pub const DEFAULT_DNS_TTL: Duration = Duration::from_secs(300);

/// Время жизни отрицательного ответа по умолчанию (предварительное
/// значение, D-17).
pub const DEFAULT_DNS_NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// Таймаут одного обращения к резолверу по умолчанию (предварительное
/// значение, D-17).
pub const DEFAULT_DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Будущее результата [`Resolver::resolve`].
pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Источник адресов для имени.
pub trait Resolver: fmt::Debug + Send + Sync {
    /// Возвращает адреса `host` в порядке предпочтения. Пустой список
    /// допустим и трактуется кэшем как отрицательный ответ.
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a>;
}

/// Системный резолвер (`getaddrinfo` через [`tokio::net::lookup_host`]).
///
/// Идентификатор зоны IPv6-адреса (`%eth0`) теряется: наружу отдаётся
/// только [`IpAddr`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, 0_u16)).await?;
            Ok(addrs.map(|addr| addr.ip()).collect())
        })
    }
}

/// Семейство адресов, с которым разрешено соединяться.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AddressFamily {
    /// Оба семейства, в порядке резолвера.
    #[default]
    Any,
    /// Только IPv4 (`-4`).
    V4Only,
    /// Только IPv6 (`-6`).
    V6Only,
}

impl AddressFamily {
    /// Истина, если адрес принадлежит разрешённому семейству.
    #[must_use]
    pub fn allows(self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::V4Only => ip.is_ipv4(),
            Self::V6Only => ip.is_ipv6(),
        }
    }
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Any => "IPv4 или IPv6",
            Self::V4Only => "IPv4",
            Self::V6Only => "IPv6",
        })
    }
}

/// Разрешено ли обращаться к резолверу.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DnsMode {
    /// Имена разрешаются резолвером.
    #[default]
    System,
    /// Резолвер не используется (`--dns none`): цель должна быть
    /// IP-литералом либо иметь IP override.
    Disabled,
}

/// Параметры разрешения одной цели.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResolveOptions {
    /// Разрешённое семейство адресов.
    pub family: AddressFamily,
    /// Режим резолва.
    pub mode: DnsMode,
    /// Соединяться с этим адресом, не разрешая имя (`--ip`). Имя цели при
    /// этом остаётся прежним и идёт в SNI.
    pub ip_override: Option<IpAddr>,
}

/// Ошибка разрешения имени.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Резолвер вернул ошибку.
    LookupFailed {
        /// Имя, которое разрешалось.
        host: String,
        /// Вид исходной ошибки.
        kind: io::ErrorKind,
        /// Текст исходной ошибки.
        message: String,
    },
    /// Резолвер не ответил за отведённое время.
    TimedOut {
        /// Имя, которое разрешалось.
        host: String,
        /// Истёкший таймаут.
        timeout: Duration,
    },
    /// Резолвер ответил пустым списком адресов.
    NoAddresses {
        /// Имя, которое разрешалось.
        host: String,
    },
    /// Адреса есть, но ни один не принадлежит разрешённому семейству; то же
    /// для IP-литерала и IP override не того семейства.
    FamilyMismatch {
        /// Имя или адрес цели.
        host: String,
        /// Разрешённое семейство.
        family: AddressFamily,
    },
    /// Резолв отключён (`--dns none`), а цель — не IP-литерал.
    ResolutionDisabled {
        /// Имя цели.
        host: String,
    },
}

impl DnsError {
    /// Имя или адрес, к которому относится ошибка.
    #[must_use]
    pub fn host(&self) -> &str {
        match self {
            Self::LookupFailed { host, .. }
            | Self::TimedOut { host, .. }
            | Self::NoAddresses { host }
            | Self::FamilyMismatch { host, .. }
            | Self::ResolutionDisabled { host } => host,
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LookupFailed {
                host,
                kind,
                message,
            } => write!(f, "резолв имени `{host}`: {message} ({kind:?})"),
            Self::TimedOut { host, timeout } => write!(
                f,
                "резолв имени `{host}`: нет ответа за {} мс",
                timeout.as_millis()
            ),
            Self::NoAddresses { host } => {
                write!(f, "резолв имени `{host}`: резолвер не вернул адресов")
            }
            Self::FamilyMismatch { host, family } => write!(
                f,
                "резолв имени `{host}`: нет адресов разрешённого семейства ({family})"
            ),
            Self::ResolutionDisabled { host } => write!(
                f,
                "резолв имени `{host}`: резолв отключён, нужен IP-литерал или IP override"
            ),
        }
    }
}

impl std::error::Error for DnsError {}

/// Разбирает IP-литерал: `192.0.2.1`, `2001:db8::1` или `[2001:db8::1]`.
#[must_use]
pub fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let bare = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse().ok()
}

/// Настройки [`DnsCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsCacheConfig {
    /// Наибольшее число записей; 0 отключает кэширование (параллельные
    /// запросы тогда не объединяются).
    pub capacity: usize,
    /// Время жизни успешного ответа.
    pub positive_ttl: Duration,
    /// Время жизни отрицательного ответа.
    pub negative_ttl: Duration,
    /// Таймаут одного обращения к резолверу.
    pub lookup_timeout: Duration,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_DNS_CACHE_CAPACITY,
            positive_ttl: DEFAULT_DNS_TTL,
            negative_ttl: DEFAULT_DNS_NEGATIVE_TTL,
            lookup_timeout: DEFAULT_DNS_LOOKUP_TIMEOUT,
        }
    }
}

/// Завершённый резолв и срок его годности.
#[derive(Debug)]
struct Outcome {
    result: Result<Arc<[IpAddr]>, DnsError>,
    /// `None` — срок не представим в `Instant`, запись не истекает.
    expires_at: Option<Instant>,
}

/// Запись кэша: ячейка заполняется один раз, первым завершившимся резолвом.
#[derive(Debug, Default)]
struct Entry {
    cell: OnceCell<Outcome>,
}

impl Entry {
    /// Истина, если резолв завершён и срок годности ответа вышел.
    fn is_expired(&self, now: Instant) -> bool {
        self.cell
            .get()
            .and_then(|outcome| outcome.expires_at)
            .is_some_and(|at| now >= at)
    }
}

/// Ограниченный кэш ответов резолвера; описание — в документации модуля.
#[derive(Debug)]
pub struct DnsCache {
    resolver: Arc<dyn Resolver>,
    config: DnsCacheConfig,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

impl DnsCache {
    /// Кэш поверх заданного резолвера.
    #[must_use]
    pub fn new(resolver: Arc<dyn Resolver>, config: DnsCacheConfig) -> Self {
        Self {
            resolver,
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Кэш поверх системного резолвера с настройками по умолчанию.
    #[must_use]
    pub fn system() -> Self {
        Self::new(Arc::new(SystemResolver), DnsCacheConfig::default())
    }

    /// Настройки кэша.
    #[must_use]
    pub fn config(&self) -> &DnsCacheConfig {
        &self.config
    }

    /// Число записей в таблице, считая истёкшие, но ещё не удалённые, и
    /// резолвы, которые ещё выполняются.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table().len()
    }

    /// Истина, если таблица пуста.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table().is_empty()
    }

    /// Адреса цели с учётом IP override, IP-литерала, режима резолва и
    /// семейства адресов. Порядок адресов — порядок резолвера.
    ///
    /// IP override и IP-литерал резолвер не вызывают.
    ///
    /// # Errors
    ///
    /// - [`DnsError::FamilyMismatch`], если IP override, IP-литерал либо все
    ///   адреса имени не принадлежат разрешённому семейству;
    /// - [`DnsError::ResolutionDisabled`], если резолв отключён, а цель — имя;
    /// - ошибки [`DnsCache::lookup`].
    pub async fn resolve_target(
        &self,
        host: &str,
        options: &ResolveOptions,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let literal = options.ip_override.or_else(|| parse_ip_literal(host));
        if let Some(ip) = literal {
            return if options.family.allows(ip) {
                Ok(vec![ip])
            } else {
                Err(DnsError::FamilyMismatch {
                    host: host.to_owned(),
                    family: options.family,
                })
            };
        }
        if options.mode == DnsMode::Disabled {
            return Err(DnsError::ResolutionDisabled {
                host: host.to_owned(),
            });
        }
        let all = self.lookup(host).await?;
        let allowed: Vec<IpAddr> = all
            .iter()
            .copied()
            .filter(|ip| options.family.allows(*ip))
            .collect();
        if allowed.is_empty() {
            return Err(DnsError::FamilyMismatch {
                host: host.to_owned(),
                family: options.family,
            });
        }
        Ok(allowed)
    }

    /// Все адреса имени: из кэша либо от резолвера. Имя сравнивается без
    /// учёта регистра ASCII.
    ///
    /// # Errors
    ///
    /// [`DnsError::LookupFailed`], [`DnsError::TimedOut`] или
    /// [`DnsError::NoAddresses`]; отрицательный ответ кэшируется на
    /// [`DnsCacheConfig::negative_ttl`].
    pub async fn lookup(&self, host: &str) -> Result<Arc<[IpAddr]>, DnsError> {
        let entry = self.entry_for(&host.to_ascii_lowercase());
        let outcome = entry.cell.get_or_init(|| self.resolve_uncached(host)).await;
        outcome.result.clone()
    }

    fn table(&self) -> MutexGuard<'_, HashMap<String, Arc<Entry>>> {
        // Под замком нет кода, способного запаниковать на полпути изменения
        // таблицы, поэтому «отравленный» замок безопасно использовать дальше.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Действующая запись для ключа либо новая, по возможности помещённая
    /// в таблицу.
    fn entry_for(&self, key: &str) -> Arc<Entry> {
        let now = Instant::now();
        let mut table = self.table();
        let live = table
            .get(key)
            .filter(|entry| !entry.is_expired(now))
            .map(Arc::clone);
        if let Some(entry) = live {
            return entry;
        }
        table.remove(key);

        let entry = Arc::new(Entry::default());
        if table.len() >= self.config.capacity {
            evict(&mut table, now);
        }
        if table.len() < self.config.capacity {
            table.insert(key.to_owned(), Arc::clone(&entry));
        }
        entry
    }

    async fn resolve_uncached(&self, host: &str) -> Outcome {
        let lookup = self.resolver.resolve(host);
        let result = match tokio::time::timeout(self.config.lookup_timeout, lookup).await {
            Err(_elapsed) => Err(DnsError::TimedOut {
                host: host.to_owned(),
                timeout: self.config.lookup_timeout,
            }),
            Ok(Err(error)) => Err(DnsError::LookupFailed {
                host: host.to_owned(),
                kind: error.kind(),
                message: error.to_string(),
            }),
            Ok(Ok(addrs)) => {
                let mut unique: Vec<IpAddr> = Vec::with_capacity(addrs.len());
                for ip in addrs {
                    if !unique.contains(&ip) {
                        unique.push(ip);
                    }
                }
                if unique.is_empty() {
                    Err(DnsError::NoAddresses {
                        host: host.to_owned(),
                    })
                } else {
                    Ok(Arc::from(unique))
                }
            }
        };
        let ttl = if result.is_ok() {
            self.config.positive_ttl
        } else {
            self.config.negative_ttl
        };
        Outcome {
            result,
            expires_at: Instant::now().checked_add(ttl),
        }
    }
}

/// Освобождает место в заполненной таблице: удаляет истёкшие и брошенные
/// записи, а если их нет — завершённую запись с самым ранним сроком.
fn evict(table: &mut HashMap<String, Arc<Entry>>, now: Instant) {
    let before = table.len();
    table.retain(|_, entry| {
        // Брошенная запись: резолв не завершён и его никто не ждёт (запрос,
        // начавший его, отменён).
        let abandoned = entry.cell.get().is_none() && Arc::strong_count(entry) == 1;
        !abandoned && !entry.is_expired(now)
    });
    if table.len() < before {
        return;
    }
    let victim = table
        .iter()
        .filter_map(|(key, entry)| {
            let outcome = entry.cell.get()?;
            // Неистекающие записи вытесняются последними.
            Some(((outcome.expires_at.is_none(), outcome.expires_at), key))
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, key)| key.clone());
    if let Some(key) = victim {
        table.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const V4_A: &str = "192.0.2.10";
    const V4_B: &str = "192.0.2.11";
    const V6_A: &str = "2001:db8::10";

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// Резолвер с заранее заданными ответами и счётчиком обращений.
    #[derive(Debug, Default)]
    struct FakeResolver {
        calls: AtomicUsize,
        answers: HashMap<String, Vec<IpAddr>>,
        delay: Duration,
    }

    impl FakeResolver {
        fn with(mut self, host: &str, addrs: &[&str]) -> Self {
            self.answers
                .insert(host.to_owned(), addrs.iter().map(|a| ip(a)).collect());
            self
        }

        fn delayed(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Resolver for FakeResolver {
        fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }
                self.answers.get(host).cloned().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "имя не существует (тест)")
                })
            })
        }
    }

    fn cache_with(resolver: FakeResolver, config: DnsCacheConfig) -> (Arc<FakeResolver>, DnsCache) {
        let resolver = Arc::new(resolver);
        let shared: Arc<dyn Resolver> = resolver.clone();
        (resolver, DnsCache::new(shared, config))
    }

    fn config() -> DnsCacheConfig {
        DnsCacheConfig {
            capacity: 8,
            positive_ttl: Duration::from_secs(60),
            negative_ttl: Duration::from_secs(10),
            lookup_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn defaults_are_the_documented_constants() {
        let defaults = DnsCacheConfig::default();
        assert_eq!(defaults.capacity, 1024);
        assert_eq!(defaults.positive_ttl, Duration::from_secs(300));
        assert_eq!(defaults.negative_ttl, Duration::from_secs(30));
        assert_eq!(defaults.lookup_timeout, Duration::from_secs(5));
        assert!(defaults.negative_ttl < defaults.positive_ttl);
        assert!(DnsCache::system().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn second_lookup_is_served_from_cache() {
        let (resolver, cache) = cache_with(
            FakeResolver::default().with("a.test", &[V4_A, V6_A]),
            config(),
        );

        let first = cache.lookup("a.test").await.unwrap();
        let second = cache.lookup("a.test").await.unwrap();
        assert_eq!(&*first, &[ip(V4_A), ip(V6_A)]);
        assert_eq!(first, second);
        assert_eq!(resolver.calls(), 1);
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn host_name_is_case_insensitive_and_addresses_are_deduplicated() {
        let resolver = FakeResolver::default()
            .with("a.test", &[V4_A, V4_A, V6_A, V4_A])
            .with("A.Test", &[V4_A, V4_A, V6_A, V4_A]);
        let (resolver, cache) = cache_with(resolver, config());

        let lower = cache.lookup("a.test").await.unwrap();
        let mixed = cache.lookup("A.Test").await.unwrap();
        assert_eq!(&*lower, &[ip(V4_A), ip(V6_A)]);
        assert_eq!(lower, mixed);
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn positive_entry_expires_after_ttl() {
        let (resolver, cache) =
            cache_with(FakeResolver::default().with("a.test", &[V4_A]), config());

        cache.lookup("a.test").await.unwrap();
        tokio::time::advance(Duration::from_secs(59)).await;
        cache.lookup("a.test").await.unwrap();
        assert_eq!(
            resolver.calls(),
            1,
            "до истечения TTL ответ берётся из кэша"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        cache.lookup("a.test").await.unwrap();
        assert_eq!(
            resolver.calls(),
            2,
            "после истечения TTL имя разрешается заново"
        );
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn negative_answer_is_cached_for_the_shorter_ttl() {
        let (resolver, cache) = cache_with(FakeResolver::default(), config());

        let error = cache.lookup("missing.test").await.unwrap_err();
        assert!(matches!(
            &error,
            DnsError::LookupFailed { host, kind: io::ErrorKind::NotFound, .. } if host == "missing.test"
        ));
        assert!(error.to_string().contains("missing.test"), "{error}");
        assert_eq!(error.host(), "missing.test");

        tokio::time::advance(Duration::from_secs(9)).await;
        assert_eq!(cache.lookup("missing.test").await.unwrap_err(), error);
        assert_eq!(resolver.calls(), 1, "отказ взят из кэша");

        // Отрицательный TTL (10 с) короче положительного (60 с).
        tokio::time::advance(Duration::from_secs(1)).await;
        cache.lookup("missing.test").await.unwrap_err();
        assert_eq!(resolver.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn empty_answer_is_a_negative_answer() {
        let (resolver, cache) =
            cache_with(FakeResolver::default().with("empty.test", &[]), config());

        let error = cache.lookup("empty.test").await.unwrap_err();
        assert_eq!(
            error,
            DnsError::NoAddresses {
                host: "empty.test".to_owned()
            }
        );
        cache.lookup("empty.test").await.unwrap_err();
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_resolver_times_out_and_the_timeout_is_cached() {
        let resolver = FakeResolver::default()
            .with("slow.test", &[V4_A])
            .delayed(Duration::from_secs(60));
        let (resolver, cache) = cache_with(resolver, config());

        let started = Instant::now();
        let error = cache.lookup("slow.test").await.unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert_eq!(
            error,
            DnsError::TimedOut {
                host: "slow.test".to_owned(),
                timeout: Duration::from_secs(5),
            }
        );
        assert!(error.to_string().contains("5000"), "{error}");

        assert_eq!(cache.lookup("slow.test").await.unwrap_err(), error);
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn full_cache_evicts_the_entry_closest_to_expiry() {
        let resolver = FakeResolver::default()
            .with("a.test", &[V4_A])
            .with("b.test", &[V4_B])
            .with("c.test", &[V6_A]);
        let (resolver, cache) = cache_with(
            resolver,
            DnsCacheConfig {
                capacity: 2,
                ..config()
            },
        );

        cache.lookup("a.test").await.unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        cache.lookup("b.test").await.unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        cache.lookup("c.test").await.unwrap();
        assert_eq!(cache.len(), 2, "размер не превышает capacity");
        assert_eq!(resolver.calls(), 3);

        // b и c остались, a вытеснена как самая старая.
        cache.lookup("b.test").await.unwrap();
        cache.lookup("c.test").await.unwrap();
        assert_eq!(resolver.calls(), 3);
        cache.lookup("a.test").await.unwrap();
        assert_eq!(resolver.calls(), 4);
        assert_eq!(cache.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_entries_are_evicted_before_live_ones() {
        let resolver = FakeResolver::default()
            .with("a.test", &[V4_A])
            .with("c.test", &[V6_A]);
        let (resolver, cache) = cache_with(
            resolver,
            DnsCacheConfig {
                capacity: 2,
                ..config()
            },
        );

        // Отказ живёт 10 с, успешный ответ — 60 с.
        cache.lookup("missing.test").await.unwrap_err();
        cache.lookup("a.test").await.unwrap();
        tokio::time::advance(Duration::from_secs(11)).await;
        cache.lookup("c.test").await.unwrap();
        assert_eq!(cache.len(), 2);

        cache.lookup("a.test").await.unwrap();
        assert_eq!(resolver.calls(), 3, "живая запись a.test не вытеснена");
    }

    #[tokio::test(start_paused = true)]
    async fn zero_capacity_disables_caching() {
        let (resolver, cache) = cache_with(
            FakeResolver::default().with("a.test", &[V4_A]),
            DnsCacheConfig {
                capacity: 0,
                ..config()
            },
        );

        cache.lookup("a.test").await.unwrap();
        cache.lookup("a.test").await.unwrap();
        assert_eq!(resolver.calls(), 2);
        assert!(cache.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_lookups_share_one_resolver_call() {
        let resolver = FakeResolver::default()
            .with("a.test", &[V4_A])
            .delayed(Duration::from_millis(50));
        let (resolver, cache) = cache_with(resolver, config());
        let cache = Arc::new(cache);

        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let cache = Arc::clone(&cache);
                tokio::spawn(async move { cache.lookup("a.test").await })
            })
            .collect();
        for task in tasks {
            let addrs = task.await.unwrap().unwrap();
            assert_eq!(&*addrs, &[ip(V4_A)]);
        }
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_failures_share_one_resolver_call() {
        let resolver = FakeResolver::default().delayed(Duration::from_millis(50));
        let (resolver, cache) = cache_with(resolver, config());
        let cache = Arc::new(cache);

        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let cache = Arc::clone(&cache);
                tokio::spawn(async move { cache.lookup("missing.test").await })
            })
            .collect();
        for task in tasks {
            assert!(task.await.unwrap().is_err());
        }
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_lookup_does_not_poison_the_entry() {
        let resolver = FakeResolver::default()
            .with("a.test", &[V4_A])
            .delayed(Duration::from_millis(50));
        let (resolver, cache) = cache_with(resolver, config());

        // Первый запрос отменяется посреди резолва.
        let cancelled =
            tokio::time::timeout(Duration::from_millis(10), cache.lookup("a.test")).await;
        assert!(cancelled.is_err());

        let addrs = cache.lookup("a.test").await.unwrap();
        assert_eq!(&*addrs, &[ip(V4_A)]);
        assert_eq!(resolver.calls(), 2);
        cache.lookup("a.test").await.unwrap();
        assert_eq!(resolver.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn address_family_modes_filter_and_keep_resolver_order() {
        let resolver = FakeResolver::default()
            .with("dual.test", &[V6_A, V4_A, V4_B])
            .with("v4.test", &[V4_A]);
        let (resolver, cache) = cache_with(resolver, config());

        let any = ResolveOptions::default();
        let v4 = ResolveOptions {
            family: AddressFamily::V4Only,
            ..any
        };
        let v6 = ResolveOptions {
            family: AddressFamily::V6Only,
            ..any
        };

        assert_eq!(
            cache.resolve_target("dual.test", &any).await.unwrap(),
            vec![ip(V6_A), ip(V4_A), ip(V4_B)]
        );
        assert_eq!(
            cache.resolve_target("dual.test", &v4).await.unwrap(),
            vec![ip(V4_A), ip(V4_B)]
        );
        assert_eq!(
            cache.resolve_target("dual.test", &v6).await.unwrap(),
            vec![ip(V6_A)]
        );
        assert_eq!(resolver.calls(), 1, "фильтр применяется после кэша");

        let error = cache.resolve_target("v4.test", &v6).await.unwrap_err();
        assert_eq!(
            error,
            DnsError::FamilyMismatch {
                host: "v4.test".to_owned(),
                family: AddressFamily::V6Only,
            }
        );
        assert!(error.to_string().contains("IPv6"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn ip_literal_and_ip_override_bypass_the_resolver() {
        let (resolver, cache) =
            cache_with(FakeResolver::default().with("a.test", &[V4_A]), config());
        let any = ResolveOptions::default();

        assert_eq!(
            cache.resolve_target(V4_B, &any).await.unwrap(),
            vec![ip(V4_B)]
        );
        assert_eq!(
            cache.resolve_target("[2001:db8::10]", &any).await.unwrap(),
            vec![ip(V6_A)]
        );

        let overridden = ResolveOptions {
            ip_override: Some(ip(V4_B)),
            ..any
        };
        assert_eq!(
            cache.resolve_target("a.test", &overridden).await.unwrap(),
            vec![ip(V4_B)]
        );
        assert_eq!(resolver.calls(), 0);
        assert!(cache.is_empty());

        // Семейство проверяется и для литерала, и для override.
        let v6_only = ResolveOptions {
            family: AddressFamily::V6Only,
            ..any
        };
        assert!(matches!(
            cache.resolve_target(V4_B, &v6_only).await,
            Err(DnsError::FamilyMismatch { .. })
        ));
        let v6_only_overridden = ResolveOptions {
            ip_override: Some(ip(V4_B)),
            ..v6_only
        };
        assert!(matches!(
            cache.resolve_target("a.test", &v6_only_overridden).await,
            Err(DnsError::FamilyMismatch { .. })
        ));
        assert_eq!(resolver.calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_dns_accepts_only_literals_and_overrides() {
        let (resolver, cache) =
            cache_with(FakeResolver::default().with("a.test", &[V4_A]), config());
        let disabled = ResolveOptions {
            mode: DnsMode::Disabled,
            ..ResolveOptions::default()
        };

        let error = cache.resolve_target("a.test", &disabled).await.unwrap_err();
        assert_eq!(
            error,
            DnsError::ResolutionDisabled {
                host: "a.test".to_owned()
            }
        );
        assert!(error.to_string().contains("a.test"), "{error}");

        assert_eq!(
            cache.resolve_target(V4_A, &disabled).await.unwrap(),
            vec![ip(V4_A)]
        );
        let overridden = ResolveOptions {
            ip_override: Some(ip(V6_A)),
            ..disabled
        };
        assert_eq!(
            cache.resolve_target("a.test", &overridden).await.unwrap(),
            vec![ip(V6_A)]
        );
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn ip_literal_parsing() {
        assert_eq!(parse_ip_literal("127.0.0.1"), Some(ip("127.0.0.1")));
        assert_eq!(parse_ip_literal("::1"), Some(ip("::1")));
        assert_eq!(parse_ip_literal("[::1]"), Some(ip("::1")));
        assert_eq!(parse_ip_literal("example.test"), None);
        assert_eq!(parse_ip_literal("[::1"), None);
        assert_eq!(parse_ip_literal("999.0.0.1"), None);
        assert_eq!(parse_ip_literal(""), None);
    }

    #[test]
    fn address_family_allows() {
        assert!(AddressFamily::Any.allows(ip(V4_A)));
        assert!(AddressFamily::Any.allows(ip(V6_A)));
        assert!(AddressFamily::V4Only.allows(ip(V4_A)));
        assert!(!AddressFamily::V4Only.allows(ip(V6_A)));
        assert!(AddressFamily::V6Only.allows(ip(V6_A)));
        assert!(!AddressFamily::V6Only.allows(ip(V4_A)));
    }
}
