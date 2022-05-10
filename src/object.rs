use crate::{
    Address, AddressDeprecated, CycleStart, CycleStop, List, MultipathTraceroute, Ping, Traceroute,
};
use deku::prelude::*;

/// A warts object.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big", magic = b"\x12\x05", type = "u16")]
pub enum Object {
    #[deku(id = "0x0001")]
    List(List),
    /// A start record denotes the starting point for a new cycle.
    #[deku(id = "0x0002")]
    CycleStart(CycleStart),
    /// A definition record declares a cycle record whose corresponding start record is in a different file.
    #[deku(id = "0x0003")]
    CycleDefinition(CycleStart),
    /// A cycle stop record denotes the end point for a cycle.
    #[deku(id = "0x0004")]
    CycleStop(CycleStop),
    /// A network address (deprecated).
    #[deku(id = "0x0005")]
    Address(AddressDeprecated),
    /// Traceroute structures consist of traceroute parameters, hop records, and an optional series
    /// of additional data types for special types of traceroute invocation.
    #[deku(id = "0x0006")]
    Traceroute(Traceroute),
    /// Ping structures consist of ping parameters and responses.
    #[deku(id = "0x0007")]
    Ping(Ping),
    /// MDA traceroute
    #[deku(id = "0x0008")]
    MultipathTraceroute(MultipathTraceroute),
}

impl Object {
    // TODO: from_stream/iter/next
    // https://github.com/sharksforarms/deku/issues/105

    pub fn all_from_bytes(data: &[u8]) -> Vec<Self> {
        let mut objects = Vec::new();
        let mut ret = Self::from_bytes((data, 0)).unwrap();
        objects.push(ret.1);
        while !ret.0 .0.is_empty() {
            ret = Object::from_bytes(ret.0).unwrap();
            objects.push(ret.1);
        }
        objects
    }

    pub fn dereference(&mut self) {
        let mut table = Vec::new();
        match self {
            Object::Traceroute(t) => {
                if let Some(addr) = t.src_addr {
                    table.push(addr);
                }
                if let Some(addr) = t.dst_addr {
                    table.push(addr);
                }
                for hop in t.hops.iter_mut() {
                    if let Some(address) = hop.addr {
                        table.push(address);
                    }
                }
            }
            Object::MultipathTraceroute(_) => todo!(),
            _ => {}
        }
        self.dereference_with_table(&table);
    }

    pub fn dereference_with_table(&mut self, table: &[Address]) {
        match self {
            Object::Traceroute(t) => {
                if let Some(id) = t.src_addr_id {
                    t.src_addr = Some(table[id as usize - 1])
                }
                if let Some(id) = t.dst_addr_id {
                    t.dst_addr = Some(table[id as usize - 1])
                }
                for mut hop in t.hops.iter_mut() {
                    if let Some(Address::Reference(id)) = hop.addr {
                        hop.addr = Some(table[id as usize]);
                    } else if let Some(id) = hop.addr_id {
                        hop.addr = Some(table[id as usize - 1])
                    }
                }
            }
            Object::MultipathTraceroute(_) => todo!(),
            _ => {}
        }
    }
}
