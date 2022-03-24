use crate::{
    Address, Flags, MultipathTraceLink, MultipathTraceNode, PingProbe, PingStopReason, Timeval,
    TraceProbe, TraceStopReason, TraceType,
};
use deku::prelude::*;
use std::ffi::CString;

/// A warts object.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big", magic = b"\x12\x05", type = "u16")]
pub enum Object {
    #[deku(id = "0x0001")]
    List {
        length: u32,
        /// List ID assigned by warts from a counter.
        list_id: u32,
        /// List ID assigned by a person.
        list_id_human: u32,
        /// List Name assigned by a person.
        name: CString,
        /// Flags.
        flags: Flags,
        /// Parameter length (optional, included if any flags are set).
        #[deku(cond = "flags.any()")]
        param_length: Option<u16>,
        /// Description, included if flag 1 is set.
        #[deku(cond = "flags.get(1)")]
        description: Option<CString>,
        /// Monitor name, included if flag 2 is set.
        #[deku(cond = "flags.get(2)")]
        monitor_name: Option<CString>,
    },
    /// A start record denotes the starting point for a new cycle.
    #[deku(id = "0x0002")]
    CycleStart {
        length: u32,
        /// Cycle ID, assigned by warts from a counter.
        cycle_id: u32,
        /// List ID, referencing the list this cycle is over.
        list_id: u32,
        /// Cycle ID, assigned by a human.
        cycle_id_human: u32,
        /// Start time of the cycle, seconds since Unix epoch.
        start_time: u32,
        /// Flags.
        flags: Flags,
        /// Parameter length, included if any flags are set.
        #[deku(cond = "flags.any()")]
        param_length: Option<u16>,
        /// Stop time of the cycle in seconds since Unix epoch, included if flag 1 is set.
        #[deku(cond = "flags.get(1)")]
        stop_time: Option<u32>,
        /// Hostname at cycle start point, included if flag 2 is set.
        #[deku(cond = "flags.get(2)")]
        hostname: Option<CString>,
    },
    /// A definition record declares a cycle record whose corresponding start record is in a different file.
    #[deku(id = "0x0003")]
    CycleDefinition {
        length: u32,
        /// Cycle ID, assigned by warts from a counter.
        cycle_id: u32,
        /// List ID, referencing the list this cycle is over.
        list_id: u32,
        /// Cycle ID, assigned by a human.
        cycle_id_human: u32,
        /// Start time of the cycle, seconds since Unix epoch.
        start_time: u32,
        /// Flags.
        flags: Flags,
        /// Parameter length, included if any flags are set.
        #[deku(cond = "flags.any()")]
        param_length: Option<u16>,
        /// Stop time of the cycle in seconds since Unix epoch, included if flag 1 is set.
        #[deku(cond = "flags.get(1)")]
        stop_time: Option<u32>,
        /// Hostname at cycle start point, included if flag 2 is set.
        #[deku(cond = "flags.get(2)")]
        hostname: Option<CString>,
    },
    /// A cycle stop record denotes the end point for a cycle.
    #[deku(id = "0x0004")]
    CycleStop {
        length: u32,
        /// Cycle ID, assigned by warts from a counter, referencing the cycle structure that is being updated.
        cycle_id: u32,
        /// Stop time of the cycle, seconds since Unix epoch.
        stop_time: u32,
        /// Flags. Currently set to zero.
        flags: Flags,
    },
    /// Traceroute structures consist of traceroute parameters, hop records, and an optional series
    /// of additional data types for special types of traceroute invocation.
    #[deku(id = "0x0006")]
    Traceroute {
        length: u32,
        /// Flags describing traceroute parameters and high-level outcomes.
        flags: Flags,
        /// Parameter length, included if any flags are set.
        #[deku(cond = "flags.any()")]
        param_length: Option<u16>,
        /// List ID assigned by warts, included if flag 1 is set.
        #[deku(cond = "flags.get(1)")]
        list_id: Option<u32>,
        /// Cycle ID assigned by warts, included if flag 2 is set.
        #[deku(cond = "flags.get(2)")]
        cycle_id: Option<u32>,
        /// Src IP address ID assigned by warts, included if flag 3 is set.
        #[deku(cond = "flags.get(3)")]
        src_addr_id: Option<u32>,
        /// Dst IP address ID assigned by warts, included if flag 4 is set.
        #[deku(cond = "flags.get(4)")]
        dst_addr_id: Option<u32>,
        /// Time traceroute commenced, included if flag 5 is set.
        #[deku(cond = "flags.get(5)")]
        start_time: Option<Timeval>,
        #[deku(cond = "flags.get(6)")]
        /// Stop reason, included if flag 6 is set.
        stop_reason: Option<TraceStopReason>,
        /// Stop data, included if flag 7 is set.
        #[deku(cond = "flags.get(7)")]
        stop_data: Option<u8>,
        /// Trace flags, included if flag 8 is set.
        #[deku(cond = "flags.get(8)")]
        trace_flags: Option<Flags>,
        /// Attempts, included if flag 9 is set.
        #[deku(cond = "flags.get(9)")]
        attempts: Option<u8>,
        /// Hoplimit, included if flag 10 is set.
        #[deku(cond = "flags.get(10)")]
        hop_limit: Option<u8>,
        /// Trace type, included if flag 11 is set.
        #[deku(cond = "flags.get(11)")]
        trace_type: Option<TraceType>,
        /// Probe size, included if flag 12 is set.
        #[deku(cond = "flags.get(12)")]
        probe_size: Option<u16>,
        /// Source port, included if flag 13 is set.
        #[deku(cond = "flags.get(13)")]
        src_port: Option<u16>,
        /// Destination port, included if flag 14 is set.
        #[deku(cond = "flags.get(14)")]
        dst_port: Option<u16>,
        /// TTL of first probe, included if flag 15 is set.
        #[deku(cond = "flags.get(15)")]
        first_ttl: Option<u8>,
        /// IP ToS set in probe packets, included if flag 16 is set.
        #[deku(cond = "flags.get(16)")]
        ip_tos: Option<u8>,
        /// Timeout length for each probe in seconds, included if flag 17 is set.
        #[deku(cond = "flags.get(17)")]
        timeout_sec: Option<u8>,
        /// How many loops are allowed before probing halts, included if flag 18 is set.
        #[deku(cond = "flags.get(18)")]
        allowed_loops: Option<u8>,
        /// Number of hops probed, included if flag 19 is set.
        #[deku(cond = "flags.get(19)")]
        hops_probed: Option<u16>,
        /// Gap limit before probing halts, included if flag 20 is set.
        #[deku(cond = "flags.get(20)")]
        gap_limit: Option<u8>,
        /// What to do when the gap limit is reached, included if flag 21 is set.
        #[deku(cond = "flags.get(21)")]
        gap_limit_action: Option<u8>,
        /// What to do when a loop is found, included if flag 22 is set.
        #[deku(cond = "flags.get(22)")]
        loop_action: Option<u8>,
        /// Number of probes sent, included if flag 23 is set.
        #[deku(cond = "flags.get(23)")]
        probes_sent: Option<u16>,
        /// Minimum time to wait between probes in centiseconds, included if flag 24 is set.
        #[deku(cond = "flags.get(24)")]
        interval_csec: Option<u8>,
        /// Confidence level to attain that all hops have replied at a given distance in the path,
        /// included if flag 25 is set.
        #[deku(cond = "flags.get(25)")]
        confidence_level: Option<u8>,
        /// Source address used in probes, included if flag 26 is set.
        #[deku(cond = "flags.get(26)")]
        src_addr: Option<Address>,
        /// Destination address used in probes, included if flag 27 is set.
        #[deku(cond = "flags.get(27)")]
        dst_addr: Option<Address>,
        /// User ID assigned to the traceroute, included if flag 28 is set.
        #[deku(cond = "flags.get(28)")]
        user_id: Option<u32>,
        /// IP offset value used in probes, included if flag 29 is set.
        #[deku(cond = "flags.get(29)")]
        ip_offset: Option<u16>,
        /// Router address used to send probes, included if flag 30 is set.
        #[deku(cond = "flags.get(30)")]
        router_addr: Option<Address>,
        /// Hop record count.
        hop_count: u16,
        /// Hop records, if hop record count > 0.
        #[deku(count = "hop_count")]
        hops: Vec<TraceProbe>,
        // TODO: Optional PMTUD, DoubleTree data.
        /// End of traceroute record; value is zero.
        #[deku(assert_eq = "0")]
        eof: u16,
    },
    /// Ping structures consist of ping parameters and responses.
    #[deku(id = "0x0007")]
    Ping {
        length: u32,
        /// Flags describing traceroute parameters and high-level outcomes.
        flags: Flags,
        /// Parameter length, included if any flags are set.
        #[deku(cond = "flags.any()")]
        param_length: Option<u16>,
        /// List ID assigned by warts, included if flag 1 is set.
        #[deku(cond = "flags.get(1)")]
        list_id: Option<u32>,
        /// Cycle ID assigned by warts, included if flag 2 is set.
        #[deku(cond = "flags.get(2)")]
        cycle_id: Option<u32>,
        /// Src IP address ID assigned by warts, included if flag 3 is set.
        #[deku(cond = "flags.get(3)")]
        src_addr_id: Option<u32>,
        /// Dst IP address ID assigned by warts, included if flag 4 is set.
        #[deku(cond = "flags.get(4)")]
        dst_addr_id: Option<u32>,
        /// Time traceroute commenced, included if flag 5 is set.
        #[deku(cond = "flags.get(5)")]
        start_time: Option<Timeval>,
        #[deku(cond = "flags.get(6)")]
        /// Stop reason, included if flag 6 is set.
        stop_reason: Option<PingStopReason>,
        /// Stop data, included if flag 7 is set.
        #[deku(cond = "flags.get(7)")]
        stop_data: Option<u8>,
        /// Data length, included if flag 8 is set.
        #[deku(cond = "flags.get(8)")]
        data_length: Option<u8>,
        /// Data bytes, included if flag 9 is set.
        #[deku(cond = "flags.get(9)", count = "data_length.unwrap()")]
        data: Vec<u8>,
        /// Probe count, included if flag 10 is set.
        #[deku(cond = "flags.get(10)")]
        probe_count: Option<u16>,
        /// Probe size, included if flag 11 is set.
        #[deku(cond = "flags.get(11)")]
        probe_size: Option<u16>,
        /// Probe wait (seconds), included if flag 12 is set.
        #[deku(cond = "flags.get(12)")]
        probe_wait: Option<u8>,
        /// Probe TTL, included if flag 13 is set.
        #[deku(cond = "flags.get(13)")]
        probe_ttl: Option<u8>,
        /// Reply count, included if flag 14 is set.
        #[deku(cond = "flags.get(14)")]
        reply_count1: Option<u16>,
        /// Pings sent, included if flag 15 is set.
        #[deku(cond = "flags.get(15)")]
        pings_sent: Option<u16>,
        /// Ping method, included if flag 16 is set.
        // TODO: Enum?
        #[deku(cond = "flags.get(16)")]
        ping_method: Option<u8>,
        /// Probe source port, included if flag 17 is set.
        #[deku(cond = "flags.get(17)")]
        src_port: Option<u16>,
        /// Probe source port, included if flag 18 is set.
        #[deku(cond = "flags.get(18)")]
        dst_port: Option<u16>,
        /// User ID, included if flag 19 is set.
        #[deku(cond = "flags.get(19)")]
        user_id: Option<u32>,
        /// Source address used, included if flag 20 is set.
        #[deku(cond = "flags.get(20)")]
        src_addr: Option<Address>,
        /// Destination address used, included if flag 21 is set.
        #[deku(cond = "flags.get(21)")]
        dst_addr: Option<Address>,
        /// Ping flags, included if flag 22 is set.
        // TODO: Enum?
        #[deku(cond = "flags.get(22)")]
        ping_flags1: Option<u8>,
        /// Probe TOS, included if flag 23 is set.
        #[deku(cond = "flags.get(23)")]
        probe_tos: Option<u8>,
        /// Probe Pre-specified timestamp option, included if flag 24 is set.
        // TODO
        #[deku(cond = "flags.get(24)", count = "0")]
        tsprespec: Vec<u8>,
        /// Probe ICMP checksum, included if flag 25 is set.
        #[deku(cond = "flags.get(25)")]
        icmp_checksum: Option<u16>,
        /// Reply psuedo Path MTU, included if flag 26 is set.
        #[deku(cond = "flags.get(26)")]
        pseudo_pmtu: Option<u16>,
        /// Probe timeout, included if flag 27 is set.
        #[deku(cond = "flags.get(27)")]
        probe_timeout: Option<u8>,
        /// Probe wait (microseconds), included if flag 28 is set.
        #[deku(cond = "flags.get(28)")]
        probe_wait_usec: Option<u32>,
        /// Probe TCP acknowledgment value, included if flag 29 is set.
        #[deku(cond = "flags.get(29)")]
        tcp_ack: Option<u32>,
        /// Ping flags, included if flag 30 is set.
        #[deku(cond = "flags.get(30)")]
        ping_flags2: Option<Address>,
        /// Probe TCP sequence number value, included if flag 31 is set.
        #[deku(cond = "flags.get(31)")]
        tcp_seq: Option<Address>,
        /// Router address used to send probes, included if flag 32 is set.
        #[deku(cond = "flags.get(32)")]
        router_addr: Option<Address>,
        /// Ping reply count.
        reply_count2: u16,
        // TODO
        #[deku(count = "reply_count2")]
        reply: Vec<PingProbe>,
    },
    /// MDA traceroute
    #[deku(id = "0x0008")]
    MultipathTraceroute {
        length: u32,
        flags: Flags,
        #[deku(cond = "flags.any()")]
        param_length: Option<u16>,
        #[deku(cond = "flags.get(1)")]
        list_id: Option<u32>,
        #[deku(cond = "flags.get(2)")]
        cycle_id: Option<u32>,
        #[deku(cond = "flags.get(3)")]
        src_addr_id: Option<u32>,
        #[deku(cond = "flags.get(4)")]
        dst_addr_id: Option<u32>,
        #[deku(cond = "flags.get(5)")]
        start_time: Option<Timeval>,
        #[deku(cond = "flags.get(6)")]
        src_port: Option<u16>,
        #[deku(cond = "flags.get(7)")]
        dst_port: Option<u16>,
        #[deku(cond = "flags.get(8)")]
        probe_size: Option<u16>,
        #[deku(cond = "flags.get(9)")]
        type_: Option<u8>,
        #[deku(cond = "flags.get(10)")]
        first_hop: Option<u8>,
        #[deku(cond = "flags.get(11)")]
        wait_timeout: Option<u8>,
        #[deku(cond = "flags.get(12)")]
        wait_probe: Option<u8>,
        #[deku(cond = "flags.get(13)")]
        attempts: Option<u8>,
        #[deku(cond = "flags.get(14)")]
        confidence: Option<u8>,
        #[deku(cond = "flags.get(15)")]
        ip_tos: Option<u8>,
        #[deku(cond = "flags.get(16)")]
        node_count: Option<u16>,
        #[deku(cond = "flags.get(17)")]
        link_count: Option<u16>,
        #[deku(cond = "flags.get(18)")]
        probe_count: Option<u32>,
        #[deku(cond = "flags.get(19)")]
        probe_count_max: Option<u32>,
        #[deku(cond = "flags.get(20)")]
        gap_limit: Option<u8>,
        #[deku(cond = "flags.get(21)")]
        src_addr: Option<Address>,
        #[deku(cond = "flags.get(22)")]
        dst_addr: Option<Address>,
        #[deku(cond = "flags.get(23)")]
        user_id: Option<u32>,
        // TODO: Enum
        #[deku(cond = "flags.get(24)")]
        flags2: Option<u8>,
        #[deku(cond = "flags.get(25)")]
        router_addr: Option<Address>,
        // TODO: unwrap_or? or use flag?
        #[deku(count = "node_count.unwrap()")]
        nodes: Vec<MultipathTraceNode>,
        #[deku(count = "link_count.unwrap()")]
        links: Vec<MultipathTraceLink>,
    },
}

impl Object {
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

    // TODO: Make this a standalone function?
    pub fn dereference(&mut self) {
        let mut table = Vec::new();
        if let Object::Traceroute {
            src_addr,
            dst_addr,
            hops,
            ..
        } = self
        {
            if let Some(addr) = src_addr {
                table.push(*addr);
            }
            if let Some(addr) = dst_addr {
                table.push(*addr);
            }
            for hop in hops {
                match &hop.addr {
                    Some(Address::Reference(id)) => {
                        hop.addr = Some(table[*id as usize]);
                    }
                    Some(address) => {
                        table.push(*address);
                    }
                    None => {}
                }
            }
        }
    }
}
