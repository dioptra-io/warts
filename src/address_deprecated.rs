use crate::Address;
use deku::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A network address.
#[derive(Copy, Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct AddressDeprecated {
    pub length: u32,
    pub id_mod: u8,
    pub address: AddressDeprecatedValue,
}

#[derive(Copy, Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian", type = "u8")]
pub enum AddressDeprecatedValue {
    #[deku(id = "0x01")]
    IPv4(Ipv4Addr),
    #[deku(id = "0x02")]
    IPv6(Ipv6Addr),
    #[deku(id = "0x03")]
    Ethernet([u8; 6]),
    #[deku(id = "0x04")]
    FireWire([u8; 8]),
}

impl From<AddressDeprecated> for Address {
    fn from(x: AddressDeprecated) -> Self {
        match x.address {
            AddressDeprecatedValue::IPv4(addr) => Address::IPv4(1, addr),
            AddressDeprecatedValue::IPv6(addr) => Address::IPv6(2, addr),
            AddressDeprecatedValue::Ethernet(addr) => Address::Ethernet(3, addr),
            AddressDeprecatedValue::FireWire(addr) => Address::FireWire(4, addr),
        }
    }
}
