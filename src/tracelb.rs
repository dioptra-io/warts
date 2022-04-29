use crate::{Address, Flags, ICMPExtension, Timeval, WartsSized};
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
    #[deku(count = "node_count.unwrap_or(0)")]
    pub nodes: Vec<MultipathTraceNode>,
    #[deku(count = "link_count.unwrap_or(0)")]
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

impl MultipathTraceroute {
    pub fn fixup(&mut self) -> &mut Self {
        let mut flags = Vec::new();
        let mut param_length = 0;
        self.node_count = Some(self.nodes.len() as u16);
        self.link_count = Some(self.links.len() as u16);
        push_flag!(flags, param_length, 1, self.list_id);
        push_flag!(flags, param_length, 2, self.cycle_id);
        push_flag!(flags, param_length, 3, self.src_addr_id);
        push_flag!(flags, param_length, 4, self.dst_addr_id);
        push_flag!(flags, param_length, 5, self.start_time);
        push_flag!(flags, param_length, 6, self.src_port);
        push_flag!(flags, param_length, 7, self.dst_port);
        push_flag!(flags, param_length, 8, self.probe_size);
        push_flag!(flags, param_length, 9, self.type_);
        push_flag!(flags, param_length, 10, self.first_hop);
        push_flag!(flags, param_length, 11, self.wait_timeout);
        push_flag!(flags, param_length, 12, self.wait_probe);
        push_flag!(flags, param_length, 13, self.attempts);
        push_flag!(flags, param_length, 14, self.confidence);
        push_flag!(flags, param_length, 15, self.ip_tos);
        push_flag!(flags, param_length, 16, self.node_count);
        push_flag!(flags, param_length, 17, self.link_count);
        push_flag!(flags, param_length, 18, self.probe_count);
        push_flag!(flags, param_length, 19, self.probe_count_max);
        push_flag!(flags, param_length, 20, self.gap_limit);
        push_flag!(flags, param_length, 21, self.src_addr);
        push_flag!(flags, param_length, 22, self.dst_addr);
        push_flag!(flags, param_length, 23, self.user_id);
        push_flag!(flags, param_length, 24, self.flags2);
        push_flag!(flags, param_length, 25, self.router_addr);
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
        let nodes_size: usize = self.nodes.iter().map(|node| node.warts_size()).sum();
        let links_size: usize = self.links.iter().map(|link| link.warts_size()).sum();
        self.length = (self.flags.warts_size()
            + self.param_length.warts_size()
            + param_length
            + nodes_size
            + links_size) as u32;
        self
    }
}

impl MultipathTraceNode {
    pub fn fixup(&mut self) -> &mut Self {
        let mut flags = Vec::new();
        let mut param_length = 0;
        push_flag!(flags, param_length, 1, self.addr_id);
        push_flag!(flags, param_length, 2, self.node_flags);
        push_flag!(flags, param_length, 3, self.link_count);
        push_flag!(flags, param_length, 4, self.quoted_ttl);
        push_flag!(flags, param_length, 5, self.addr);
        push_flag!(flags, param_length, 6, self.name);
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
        self
    }
}

impl MultipathTraceLink {
    pub fn fixup(&mut self) -> &mut Self {
        let mut flags = Vec::new();
        let mut param_length = 0;
        self.probe_set_count = Some(self.probe_sets.len() as u8);
        push_flag!(flags, param_length, 1, self.from);
        push_flag!(flags, param_length, 2, self.to);
        push_flag!(flags, param_length, 3, self.probe_set_count);
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
        self
    }
}

impl MultipathTraceProbeSet {
    pub fn fixup(&mut self) -> &mut Self {
        let mut flags = Vec::new();
        let mut param_length = 0;
        push_flag!(flags, param_length, 1, self.probe_count);
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
        self
    }
}

impl MultipathTraceProbe {
    pub fn fixup(&mut self) -> &mut Self {
        let mut flags = Vec::new();
        let mut param_length = 0;
        push_flag!(flags, param_length, 1, self.tx);
        push_flag!(flags, param_length, 2, self.flow_id);
        push_flag!(flags, param_length, 3, self.ttl);
        push_flag!(flags, param_length, 4, self.attempts);
        push_flag!(flags, param_length, 5, self.replies_count);
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
        self
    }
}

impl MultipathTraceReply {
    pub fn fixup(&mut self) -> &mut Self {
        let mut flags = Vec::new();
        let mut param_length = 0;
        push_flag!(flags, param_length, 1, self.rx);
        push_flag!(flags, param_length, 2, self.ip_id);
        push_flag!(flags, param_length, 3, self.ttl);
        push_flag!(flags, param_length, 4, self.reply_flags);
        push_flag!(flags, param_length, 5, self.icmp_type);
        push_flag!(flags, param_length, 5, self.icmp_code);
        push_flag!(flags, param_length, 6, self.tcp_flags);
        push_flag!(flags, param_length, 7, self.icmp_extensions_length);
        // TODO: icmp_extensions
        push_flag!(flags, param_length, 8, self.quoted_ttl);
        push_flag!(flags, param_length, 9, self.quoted_tos);
        push_flag!(flags, param_length, 10, self.addr_id);
        push_flag!(flags, param_length, 11, self.addr);
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
        self
    }
}

impl WartsSized for MultipathTraceNode {
    fn warts_size(&self) -> usize {
        self.flags.warts_size()
            + self.param_length.warts_size()
            + self.param_length.unwrap() as usize
    }
}

impl WartsSized for MultipathTraceLink {
    fn warts_size(&self) -> usize {
        // TODO: Probe sets length? Or included in param length?
        self.flags.warts_size()
            + self.param_length.warts_size()
            + self.param_length.unwrap() as usize
    }
}
