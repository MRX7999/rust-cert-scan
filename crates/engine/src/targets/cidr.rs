//! CIDR: ленивое разворачивание диапазона адресов.
//!
//! [`Cidr`] хранит адрес сети и длину префикса; [`Cidr::addresses`] отдаёт
//! итератор-счётчик, поэтому память не зависит от размера сети: `/8` и
//! `/64` занимают столько же, сколько `/32`.
//!
//! Правила:
//!
//! - запись с ненулевыми битами хоста (`10.0.0.5/24`) принимается и
//!   приводится к адресу сети (`10.0.0.0/24`);
//! - выдаются все адреса диапазона по возрастанию, включая адрес сети и
//!   широковещательный: сканер не знает, как диапазон разбит на подсети у
//!   владельца, а для `/31` и `/32` (RFC 3021) оба адреса — обычные хосты;
//! - число адресов ограничено пределом, который передаёт вызывающий:
//!   опечатка в длине префикса не должна запускать скан миллиардов
//!   адресов. Значение по умолчанию — [`DEFAULT_MAX_CIDR_ADDRESSES`].

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Предел числа адресов одной сети по умолчанию: 2^20 (IPv4 `/12`, IPv6
/// `/108`). Предварительное значение (`docs/DECISIONS.md`).
pub const DEFAULT_MAX_CIDR_ADDRESSES: u64 = 1_048_576;

/// Бит в адресе IPv4.
const V4_BITS: u8 = 32;
/// Бит в адресе IPv6.
const V6_BITS: u8 = 128;

/// Сеть в записи CIDR; описание — в документации модуля.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

/// Сеть больше допустимого предела.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkTooLarge {
    /// Число бит хоста: в сети 2 в этой степени адресов.
    pub host_bits: u32,
    /// Действующий предел числа адресов.
    pub limit: u64,
}

impl fmt::Display for NetworkTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "в сети 2^{} адресов, предел — {}",
            self.host_bits, self.limit
        )
    }
}

impl std::error::Error for NetworkTooLarge {}

fn to_value(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn to_addr(value: u128, v4: bool) -> IpAddr {
    if v4 {
        IpAddr::V4(Ipv4Addr::from(u32::try_from(value).unwrap_or(u32::MAX)))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    }
}

/// Маска бит хоста: `host_bits` младших единиц.
fn host_mask(host_bits: u32) -> u128 {
    1_u128
        .checked_shl(host_bits)
        .map_or(u128::MAX, |bit| bit.wrapping_sub(1))
}

impl Cidr {
    /// Сеть, содержащая `addr`, с префиксом длиной `prefix`; биты хоста
    /// обнуляются. `None`, если префикс длиннее адреса (больше 32 для IPv4,
    /// больше 128 для IPv6).
    #[must_use]
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let bits = if addr.is_ipv4() { V4_BITS } else { V6_BITS };
        if prefix > bits {
            return None;
        }
        let host_bits = u32::from(bits.saturating_sub(prefix));
        let network = to_value(addr) & !host_mask(host_bits);
        Some(Self {
            network: to_addr(network, addr.is_ipv4()),
            prefix,
        })
    }

    /// Адрес сети — первый адрес диапазона.
    #[must_use]
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// Длина префикса.
    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Число бит хоста.
    #[must_use]
    pub fn host_bits(&self) -> u32 {
        let bits = if self.network.is_ipv4() {
            V4_BITS
        } else {
            V6_BITS
        };
        u32::from(bits.saturating_sub(self.prefix))
    }

    /// Число адресов в сети; `None` для `::/0` (2^128 не помещается в
    /// `u128`).
    #[must_use]
    pub fn address_count(&self) -> Option<u128> {
        1_u128.checked_shl(self.host_bits())
    }

    /// Последний адрес диапазона.
    #[must_use]
    pub fn last(&self) -> IpAddr {
        let value = to_value(self.network) | host_mask(self.host_bits());
        to_addr(value, self.network.is_ipv4())
    }

    /// Ленивый перебор адресов сети по возрастанию.
    ///
    /// # Errors
    ///
    /// [`NetworkTooLarge`], если адресов больше `limit`.
    pub fn addresses(&self, limit: u64) -> Result<CidrAddresses, NetworkTooLarge> {
        let too_large = NetworkTooLarge {
            host_bits: self.host_bits(),
            limit,
        };
        let count = self.address_count().ok_or(too_large)?;
        if count > u128::from(limit) {
            return Err(too_large);
        }
        Ok(CidrAddresses {
            next: to_value(self.network),
            remaining: count,
            v4: self.network.is_ipv4(),
        })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Итератор адресов сети: хранит следующий адрес и число оставшихся.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrAddresses {
    next: u128,
    remaining: u128,
    v4: bool,
}

impl CidrAddresses {
    /// Сколько адресов ещё не выдано.
    #[must_use]
    pub fn remaining(&self) -> u128 {
        self.remaining
    }
}

impl Iterator for CidrAddresses {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        if self.remaining == 0 {
            return None;
        }
        let addr = to_addr(self.next, self.v4);
        self.next = self.next.wrapping_add(1);
        self.remaining = self.remaining.saturating_sub(1);
        Some(addr)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match usize::try_from(self.remaining) {
            Ok(exact) => (exact, Some(exact)),
            Err(_) => (usize::MAX, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_LIMIT: u64 = u64::MAX;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(text: &str) -> IpAddr {
        IpAddr::V6(text.parse().unwrap())
    }

    fn cidr(addr: IpAddr, prefix: u8) -> Cidr {
        Cidr::new(addr, prefix).unwrap()
    }

    #[test]
    fn slash_32_is_one_address() {
        let net = cidr(v4(192, 0, 2, 7), 32);
        let all: Vec<IpAddr> = net.addresses(1).unwrap().collect();
        assert_eq!(all, vec![v4(192, 0, 2, 7)]);
        assert_eq!(net.address_count(), Some(1));
        assert_eq!(net.last(), v4(192, 0, 2, 7));
    }

    #[test]
    fn slash_31_is_two_addresses() {
        let net = cidr(v4(192, 0, 2, 6), 31);
        let all: Vec<IpAddr> = net.addresses(2).unwrap().collect();
        assert_eq!(all, vec![v4(192, 0, 2, 6), v4(192, 0, 2, 7)]);
    }

    #[test]
    fn slash_24_includes_network_and_broadcast() {
        let net = cidr(v4(10, 1, 2, 0), 24);
        let all: Vec<IpAddr> = net.addresses(DEFAULT_MAX_CIDR_ADDRESSES).unwrap().collect();
        assert_eq!(all.len(), 256);
        assert_eq!(all.first().copied(), Some(v4(10, 1, 2, 0)));
        assert_eq!(all.last().copied(), Some(v4(10, 1, 2, 255)));
        assert_eq!(net.last(), v4(10, 1, 2, 255));
        assert_eq!(all.get(1).copied(), Some(v4(10, 1, 2, 1)));
    }

    #[test]
    fn host_bits_are_cleared() {
        let net = cidr(v4(10, 1, 2, 77), 24);
        assert_eq!(net.network(), v4(10, 1, 2, 0));
        assert_eq!(net.prefix(), 24);
        assert_eq!(net.to_string(), "10.1.2.0/24");
        assert_eq!(net, cidr(v4(10, 1, 2, 0), 24));
    }

    #[test]
    fn slash_0_is_rejected_by_the_limit() {
        let net = cidr(v4(203, 0, 113, 1), 0);
        assert_eq!(net.network(), v4(0, 0, 0, 0));
        assert_eq!(net.address_count(), Some(4_294_967_296));
        let error = net.addresses(DEFAULT_MAX_CIDR_ADDRESSES).unwrap_err();
        assert_eq!(
            error,
            NetworkTooLarge {
                host_bits: 32,
                limit: DEFAULT_MAX_CIDR_ADDRESSES,
            }
        );
        assert_eq!(error.to_string(), "в сети 2^32 адресов, предел — 1048576");
    }

    #[test]
    fn slash_0_with_a_raised_limit_is_lazy() {
        let net = cidr(v4(0, 0, 0, 0), 0);
        let mut addresses = net.addresses(NO_LIMIT).unwrap();
        assert_eq!(addresses.remaining(), 4_294_967_296);
        assert_eq!(addresses.next(), Some(v4(0, 0, 0, 0)));
        assert_eq!(addresses.next(), Some(v4(0, 0, 0, 1)));
        assert_eq!(addresses.remaining(), 4_294_967_294);
        assert_eq!(net.last(), v4(255, 255, 255, 255));
    }

    #[test]
    fn slash_8_does_not_materialise() {
        let net = cidr(v4(10, 0, 0, 0), 8);
        assert_eq!(net.address_count(), Some(16_777_216));
        assert!(net.addresses(DEFAULT_MAX_CIDR_ADDRESSES).is_err());
        let addresses = net.addresses(16_777_216).unwrap();
        // Состояние итератора — два числа и флаг, каким бы ни был диапазон.
        assert!(std::mem::size_of_val(&addresses) <= 48);
        let head: Vec<IpAddr> = addresses.take(3).collect();
        assert_eq!(
            head,
            vec![v4(10, 0, 0, 0), v4(10, 0, 0, 1), v4(10, 0, 0, 2)]
        );
        assert_eq!(net.last(), v4(10, 255, 255, 255));
    }

    #[test]
    fn limit_is_inclusive() {
        let net = cidr(v4(10, 0, 0, 0), 24);
        assert!(net.addresses(256).is_ok());
        assert!(net.addresses(255).is_err());
    }

    #[test]
    fn exhausted_iterator_stays_exhausted() {
        let mut addresses = cidr(v4(255, 255, 255, 255), 32).addresses(1).unwrap();
        assert_eq!(addresses.size_hint(), (1, Some(1)));
        assert_eq!(addresses.next(), Some(v4(255, 255, 255, 255)));
        assert_eq!(addresses.next(), None);
        assert_eq!(addresses.next(), None);
        assert_eq!(addresses.size_hint(), (0, Some(0)));
    }

    #[test]
    fn ipv6_slash_128_is_one_address() {
        let net = cidr(v6("2001:db8::1"), 128);
        let all: Vec<IpAddr> = net.addresses(1).unwrap().collect();
        assert_eq!(all, vec![v6("2001:db8::1")]);
    }

    #[test]
    fn ipv6_slash_120_counts_256_addresses() {
        let net = cidr(v6("2001:db8::abcd"), 120);
        assert_eq!(net.network(), v6("2001:db8::ab00"));
        let addresses = net.addresses(DEFAULT_MAX_CIDR_ADDRESSES).unwrap();
        assert_eq!(addresses.clone().count(), 256);
        assert_eq!(addresses.clone().next(), Some(v6("2001:db8::ab00")));
        assert_eq!(addresses.last(), Some(v6("2001:db8::abff")));
        assert_eq!(net.to_string(), "2001:db8::ab00/120");
    }

    #[test]
    fn ipv6_slash_64_is_rejected_by_any_limit() {
        let net = cidr(v6("2001:db8::"), 64);
        assert_eq!(net.address_count(), Some(18_446_744_073_709_551_616));
        let error = net.addresses(DEFAULT_MAX_CIDR_ADDRESSES).unwrap_err();
        assert_eq!(error.host_bits, 64);
        // 2^64 адресов больше наибольшего предела.
        assert!(net.addresses(NO_LIMIT).is_err());
        assert_eq!(net.last(), v6("2001:db8::ffff:ffff:ffff:ffff"));
    }

    #[test]
    fn ipv6_slash_0_has_no_countable_size() {
        let net = cidr(v6("2001:db8::1"), 0);
        assert_eq!(net.network(), v6("::"));
        assert_eq!(net.address_count(), None);
        assert_eq!(net.addresses(NO_LIMIT).unwrap_err().host_bits, 128);
        assert_eq!(net.last(), v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    }

    #[test]
    fn prefix_longer_than_the_address_is_rejected() {
        assert_eq!(Cidr::new(v4(10, 0, 0, 0), 33), None);
        assert_eq!(Cidr::new(v6("::1"), 129), None);
        assert!(Cidr::new(v4(10, 0, 0, 0), 32).is_some());
        assert!(Cidr::new(v6("::1"), 128).is_some());
    }
}
