use crate::WartsSized;
use deku::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A network address, or a reference to a previously seen one.
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use warts::Address;
/// // Rust to Warts:
/// let address = Address::from(Ipv4Addr::new(192, 2, 0, 1));
/// // Warts to Rust:
/// let ip = IpAddr::from(address);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian", type = "u8")]
pub enum Address {
    // NOTE: We use the length field as a type tag.
    #[deku(id = "0")]
    Reference(u32),
    #[deku(id = "4")]
    IPv4(u8, Ipv4Addr),
    #[deku(id = "16")]
    IPv6(u8, Ipv6Addr),
    #[deku(id = "6")]
    Ethernet(u8, [u8; 6]),
    #[deku(id = "8")]
    FireWire(u8, [u8; 8]),
}

impl From<Ipv4Addr> for Address {
    fn from(x: Ipv4Addr) -> Self {
        Self::IPv4(1, x)
    }
}

impl From<Ipv6Addr> for Address {
    fn from(x: Ipv6Addr) -> Self {
        Self::IPv6(2, x)
    }
}

impl From<[u8; 6]> for Address {
    fn from(x: [u8; 6]) -> Self {
        Self::Ethernet(3, x)
    }
}

impl From<[u8; 8]> for Address {
    fn from(x: [u8; 8]) -> Self {
        Self::FireWire(4, x)
    }
}

impl From<Address> for IpAddr {
    fn from(x: Address) -> Self {
        match x {
            Address::IPv4(1, addr) => IpAddr::from(addr),
            Address::IPv6(2, addr) => IpAddr::from(addr),
            _ => panic!("not an IP address"),
        }
    }
}

impl WartsSized for Address {
    fn warts_size(&self) -> usize {
        match self {
            Address::Reference(_) => 5,
            Address::IPv4(_, _) => 6,
            Address::IPv6(_, _) => 18,
            Address::Ethernet(_, _) => 7,
            Address::FireWire(_, _) => 9,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Address;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn from_ipv4() {
        let addr = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(IpAddr::from(Address::from(addr)), addr);
    }

    #[test]
    fn from_ipv6() {
        let addr = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
        assert_eq!(IpAddr::from(Address::from(addr)), addr);
    }
}
