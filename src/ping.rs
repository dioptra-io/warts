use crate::{Address, Flags, Timeval};
use deku::prelude::*;

/// Reason for the termination of a ping command.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian", type = "u8")]
pub enum PingStopReason {
    /// Null reason.
    None = 0x00,
    /// Sent all probes.
    Completed = 0x01,
    /// Error occurred during ping.
    Error = 0x02,
    /// Halted.
    Halted = 0x03,
}

/// A ping.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct Ping {
    pub length: u32,
    /// Flags describing traceroute parameters and high-level outcomes.
    pub flags: Flags,
    /// Parameter length, included if any flags are set.
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    /// List ID assigned by warts, included if flag 1 is set.
    #[deku(cond = "flags.get(1)")]
    pub list_id: Option<u32>,
    /// Cycle ID assigned by warts, included if flag 2 is set.
    #[deku(cond = "flags.get(2)")]
    pub cycle_id: Option<u32>,
    /// Src IP address ID assigned by warts, included if flag 3 is set.
    #[deku(cond = "flags.get(3)")]
    pub src_addr_id: Option<u32>,
    /// Dst IP address ID assigned by warts, included if flag 4 is set.
    #[deku(cond = "flags.get(4)")]
    pub dst_addr_id: Option<u32>,
    /// Time traceroute commenced, included if flag 5 is set.
    #[deku(cond = "flags.get(5)")]
    pub start_time: Option<Timeval>,
    #[deku(cond = "flags.get(6)")]
    /// Stop reason, included if flag 6 is set.
    pub stop_reason: Option<PingStopReason>,
    /// Stop data, included if flag 7 is set.
    #[deku(cond = "flags.get(7)")]
    pub stop_data: Option<u8>,
    /// Data length, included if flag 8 is set.
    #[deku(cond = "flags.get(8)")]
    pub data_length: Option<u8>,
    /// Data bytes, included if flag 9 is set.
    #[deku(cond = "flags.get(9)", count = "data_length.unwrap()")]
    pub data: Vec<u8>,
    /// Probe count, included if flag 10 is set.
    #[deku(cond = "flags.get(10)")]
    pub probe_count: Option<u16>,
    /// Probe size, included if flag 11 is set.
    #[deku(cond = "flags.get(11)")]
    pub probe_size: Option<u16>,
    /// Probe wait (seconds), included if flag 12 is set.
    #[deku(cond = "flags.get(12)")]
    pub probe_wait: Option<u8>,
    /// Probe TTL, included if flag 13 is set.
    #[deku(cond = "flags.get(13)")]
    pub probe_ttl: Option<u8>,
    /// Reply count, included if flag 14 is set.
    #[deku(cond = "flags.get(14)")]
    pub reply_count1: Option<u16>,
    /// Pings sent, included if flag 15 is set.
    #[deku(cond = "flags.get(15)")]
    pub pings_sent: Option<u16>,
    /// Ping method, included if flag 16 is set.
    // TODO: Enum?
    #[deku(cond = "flags.get(16)")]
    pub ping_method: Option<u8>,
    /// Probe source port, included if flag 17 is set.
    #[deku(cond = "flags.get(17)")]
    pub src_port: Option<u16>,
    /// Probe source port, included if flag 18 is set.
    #[deku(cond = "flags.get(18)")]
    pub dst_port: Option<u16>,
    /// User ID, included if flag 19 is set.
    #[deku(cond = "flags.get(19)")]
    pub user_id: Option<u32>,
    /// Source address used, included if flag 20 is set.
    #[deku(cond = "flags.get(20)")]
    pub src_addr: Option<Address>,
    /// Destination address used, included if flag 21 is set.
    #[deku(cond = "flags.get(21)")]
    pub dst_addr: Option<Address>,
    /// Ping flags, included if flag 22 is set.
    // TODO: Enum?
    #[deku(cond = "flags.get(22)")]
    pub ping_flags1: Option<u8>,
    /// Probe TOS, included if flag 23 is set.
    #[deku(cond = "flags.get(23)")]
    pub probe_tos: Option<u8>,
    /// Probe Pre-specified timestamp option, included if flag 24 is set.
    // TODO
    #[deku(cond = "flags.get(24)", count = "0")]
    pub tsprespec: Vec<u8>,
    /// Probe ICMP checksum, included if flag 25 is set.
    #[deku(cond = "flags.get(25)")]
    pub icmp_checksum: Option<u16>,
    /// Reply psuedo Path MTU, included if flag 26 is set.
    #[deku(cond = "flags.get(26)")]
    pub pseudo_pmtu: Option<u16>,
    /// Probe timeout, included if flag 27 is set.
    #[deku(cond = "flags.get(27)")]
    pub probe_timeout: Option<u8>,
    /// Probe wait (microseconds), included if flag 28 is set.
    #[deku(cond = "flags.get(28)")]
    pub probe_wait_usec: Option<u32>,
    /// Probe TCP acknowledgment value, included if flag 29 is set.
    #[deku(cond = "flags.get(29)")]
    pub tcp_ack: Option<u32>,
    /// Ping flags, included if flag 30 is set.
    #[deku(cond = "flags.get(30)")]
    pub ping_flags2: Option<Address>,
    /// Probe TCP sequence number value, included if flag 31 is set.
    #[deku(cond = "flags.get(31)")]
    pub tcp_seq: Option<Address>,
    /// Router address used to send probes, included if flag 32 is set.
    #[deku(cond = "flags.get(32)")]
    pub router_addr: Option<Address>,
    /// Ping reply count.
    pub reply_count2: u16,
    // TODO
    #[deku(count = "reply_count2")]
    pub reply: Vec<PingProbe>,
}

/// A ping probe and its associated reply, if any.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct PingProbe {
    pub flags: Flags,
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    #[deku(cond = "flags.get(1)")]
    pub addr_id: Option<u32>,
    // TODO
    #[deku(cond = "flags.get(2)")]
    pub flags2: Option<u8>,
    #[deku(cond = "flags.get(3)")]
    pub reply_ttl: Option<u8>,
    #[deku(cond = "flags.get(4)")]
    pub reply_size: Option<u16>,
    #[deku(cond = "flags.get(5)")]
    pub icmp_type: Option<u8>,
    #[deku(cond = "flags.get(5)")]
    pub icmp_code: Option<u8>,
    #[deku(cond = "flags.get(6)")]
    pub rtt_usec: Option<u32>,
    #[deku(cond = "flags.get(7)")]
    pub probe_id: Option<u16>,
    #[deku(cond = "flags.get(8)")]
    pub reply_ipid: Option<u16>,
    #[deku(cond = "flags.get(9)")]
    pub probe_ipid: Option<u16>,
    // TODO: Protocol enumeration? Already existing in Rust stdlib?
    #[deku(cond = "flags.get(10)")]
    pub reply_proto: Option<u8>,
    #[deku(cond = "flags.get(11)")]
    pub tcp_flags: Option<u8>,
    #[deku(cond = "flags.get(12)")]
    pub addr: Option<Address>,
    //TODO
    #[deku(cond = "flags.get(13)")]
    pub rr: Option<u8>,
    #[deku(cond = "flags.get(14)")]
    pub ts: Option<u8>,
    #[deku(cond = "flags.get(15)")]
    pub reply_ipid32: Option<u32>,
    #[deku(cond = "flags.get(16)")]
    pub tx: Option<Timeval>,
    // TODO: tsreply
}
