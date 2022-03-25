use crate::{Address, Flags, ICMPExtension, Timeval};
use deku::prelude::*;
use std::ffi::CString;

/// An MDA traceroute.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct MultipathTraceroute {
    pub length: u32,
    pub flags: Flags,
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    #[deku(cond = "flags.get(1)")]
    pub list_id: Option<u32>,
    #[deku(cond = "flags.get(2)")]
    pub cycle_id: Option<u32>,
    #[deku(cond = "flags.get(3)")]
    pub src_addr_id: Option<u32>,
    #[deku(cond = "flags.get(4)")]
    pub dst_addr_id: Option<u32>,
    #[deku(cond = "flags.get(5)")]
    pub start_time: Option<Timeval>,
    #[deku(cond = "flags.get(6)")]
    pub src_port: Option<u16>,
    #[deku(cond = "flags.get(7)")]
    pub dst_port: Option<u16>,
    #[deku(cond = "flags.get(8)")]
    pub probe_size: Option<u16>,
    #[deku(cond = "flags.get(9)")]
    pub type_: Option<u8>,
    #[deku(cond = "flags.get(10)")]
    pub first_hop: Option<u8>,
    #[deku(cond = "flags.get(11)")]
    pub wait_timeout: Option<u8>,
    #[deku(cond = "flags.get(12)")]
    pub wait_probe: Option<u8>,
    #[deku(cond = "flags.get(13)")]
    pub attempts: Option<u8>,
    #[deku(cond = "flags.get(14)")]
    pub confidence: Option<u8>,
    #[deku(cond = "flags.get(15)")]
    pub ip_tos: Option<u8>,
    #[deku(cond = "flags.get(16)")]
    pub node_count: Option<u16>,
    #[deku(cond = "flags.get(17)")]
    pub link_count: Option<u16>,
    #[deku(cond = "flags.get(18)")]
    pub probe_count: Option<u32>,
    #[deku(cond = "flags.get(19)")]
    pub probe_count_max: Option<u32>,
    #[deku(cond = "flags.get(20)")]
    pub gap_limit: Option<u8>,
    #[deku(cond = "flags.get(21)")]
    pub src_addr: Option<Address>,
    #[deku(cond = "flags.get(22)")]
    pub dst_addr: Option<Address>,
    #[deku(cond = "flags.get(23)")]
    pub user_id: Option<u32>,
    // TODO: Enum
    #[deku(cond = "flags.get(24)")]
    pub flags2: Option<u8>,
    #[deku(cond = "flags.get(25)")]
    pub router_addr: Option<Address>,
    // TODO: unwrap_or? or use flag?
    #[deku(count = "node_count.unwrap()")]
    pub nodes: Vec<MultipathTraceNode>,
    #[deku(count = "link_count.unwrap()")]
    pub links: Vec<MultipathTraceLink>,
}

/// A node in a multipath traceroute.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct MultipathTraceNode {
    pub flags: Flags,
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    /// Node address ID, included if flag 1 is set.
    #[deku(cond = "flags.get(1)")]
    pub addr_id: Option<u32>,
    /// Node flags, included if flag 2 is set.
    #[deku(cond = "flags.get(2)")]
    pub node_flags: Option<u8>,
    /// Number of links, included if flag 3 is set.
    #[deku(cond = "flags.get(3)")]
    pub link_count: Option<u16>,
    /// Quoted TTL, included if flag 4 is set.
    #[deku(cond = "flags.get(4)")]
    pub quoted_ttl: Option<u8>,
    /// Node address, included if flag 5 is set.
    #[deku(cond = "flags.get(5)")]
    pub addr: Option<Address>,
    /// Included if flag 6 is set.
    #[deku(cond = "flags.get(6)")]
    pub name: Option<CString>,
}

/// A link in a multipath traceroute.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct MultipathTraceLink {
    pub flags: Flags,
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    /// Link from, included if flag 1 is set.
    #[deku(cond = "flags.get(1)")]
    pub from: Option<u16>,
    /// Link to, included if flag 2 is set.
    #[deku(cond = "flags.get(2)")]
    pub to: Option<u16>,
    /// Number of probe sets, included if flag 3 is set.
    #[deku(cond = "flags.get(3)")]
    pub probe_set_count: Option<u8>,
    /// Probe sets, if any.
    #[deku(count = "probe_set_count.unwrap_or(0)")]
    pub probe_sets: Vec<MultipathTraceProbeSet>,
}

/// A set of probes in a multipath traceroute.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct MultipathTraceProbeSet {
    pub flags: Flags,
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    /// Number of probes sent, included if flag 1 is set.
    #[deku(cond = "flags.get(1)")]
    pub probe_count: Option<u16>,
    /// Probes sent, if any.
    #[deku(count = "probe_count.unwrap_or(0)")]
    pub probes: Vec<MultipathTraceProbe>,
}

/// A probe in a multipath traceroute.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct MultipathTraceProbe {
    pub flags: Flags,
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    #[deku(cond = "flags.get(1)")]
    pub tx: Option<Timeval>,
    #[deku(cond = "flags.get(2)")]
    pub flow_id: Option<u16>,
    #[deku(cond = "flags.get(3)")]
    pub ttl: Option<u8>,
    #[deku(cond = "flags.get(4)")]
    pub attempts: Option<u8>,
    #[deku(cond = "flags.get(5)")]
    pub replies_count: Option<u16>,
    #[deku(count = "replies_count.unwrap_or(0)")]
    pub replies: Vec<MultipathTraceReply>,
}

/// A reply in a multipath traceroute.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct MultipathTraceReply {
    pub flags: Flags,
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    #[deku(cond = "flags.get(1)")]
    pub rx: Option<Timeval>,
    #[deku(cond = "flags.get(2)")]
    pub ip_id: Option<u16>,
    #[deku(cond = "flags.get(3)")]
    pub ttl: Option<u8>,
    #[deku(cond = "flags.get(4)")]
    pub reply_flags: Option<u8>,
    #[deku(cond = "flags.get(5)")]
    pub icmp_type: Option<u8>,
    #[deku(cond = "flags.get(5)")]
    pub icmp_code: Option<u8>,
    #[deku(cond = "flags.get(6)")]
    pub tcp_flags: Option<u8>,
    #[deku(cond = "flags.get(7)")]
    pub icmp_extensions_length: Option<u16>,
    // NOTE: We currently assume that there is at maximum one ICMP extension, and that it
    // contains an MPLS label stack.
    #[deku(
        cond = "flags.get(7)",
        count = "if icmp_extensions_length.unwrap() > 0 { 1 } else { 0 }"
    )]
    pub icmp_extensions: Vec<ICMPExtension>,
    #[deku(cond = "flags.get(8)")]
    pub quoted_ttl: Option<u8>,
    #[deku(cond = "flags.get(9)")]
    pub quoted_tos: Option<u8>,
    #[deku(cond = "flags.get(10)")]
    pub addr_id: Option<u32>,
    #[deku(cond = "flags.get(11)")]
    pub addr: Option<Address>,
}
