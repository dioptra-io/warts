use crate::{Address, Flags, ICMPExtension, Timeval, WartsSized};
use deku::prelude::*;

/// Traceroute type.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian", type = "u8")]
pub enum TraceType {
    /// ICMP echo requests.
    ICMPEcho = 0x01,
    /// UDP to unused ports.
    UDP = 0x02,
    /// TCP SYN packets.
    TCP = 0x03,
    /// Paris traceroute.
    ICMPEchoParis = 0x04,
    /// Paris traceroute.
    UDPParis = 0x05,
    /// TCP ACK packets.
    TCPAck = 0x06,
}

/// Reason for the termination of a trace command.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian", type = "u8")]
pub enum TraceStopReason {
    /// Null reason.
    None = 0x00,
    /// Got an ICMP port unreach.
    Completed = 0x01,
    /// Got an other ICMP unreach code.
    Unreach = 0x02,
    /// Got an ICMP msg, not unreach.
    ICMP = 0x03,
    /// Loop detected.
    Loop = 0x04,
    /// Gaplimit reached.
    GapLimit = 0x05,
    /// Sendto error.
    Error = 0x06,
    /// Hoplimit reached.
    HopLimit = 0x07,
    /// Found hop in global stop set.
    GSS = 0x08,
    /// Halted.
    Halted = 0x09,
}

/// A traceroute.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct Traceroute {
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
    pub stop_reason: Option<TraceStopReason>,
    /// Stop data, included if flag 7 is set.
    #[deku(cond = "flags.get(7)")]
    pub stop_data: Option<u8>,
    /// Trace flags, included if flag 8 is set.
    #[deku(cond = "flags.get(8)")]
    pub trace_flags: Option<Flags>,
    /// Attempts, included if flag 9 is set.
    #[deku(cond = "flags.get(9)")]
    pub attempts: Option<u8>,
    /// Hoplimit, included if flag 10 is set.
    #[deku(cond = "flags.get(10)")]
    pub hop_limit: Option<u8>,
    /// Trace type, included if flag 11 is set.
    #[deku(cond = "flags.get(11)")]
    pub trace_type: Option<TraceType>,
    /// Probe size, included if flag 12 is set.
    #[deku(cond = "flags.get(12)")]
    pub probe_size: Option<u16>,
    /// Source port, included if flag 13 is set.
    #[deku(cond = "flags.get(13)")]
    pub src_port: Option<u16>,
    /// Destination port, included if flag 14 is set.
    #[deku(cond = "flags.get(14)")]
    pub dst_port: Option<u16>,
    /// TTL of first probe, included if flag 15 is set.
    #[deku(cond = "flags.get(15)")]
    pub first_ttl: Option<u8>,
    /// IP ToS set in probe packets, included if flag 16 is set.
    #[deku(cond = "flags.get(16)")]
    pub ip_tos: Option<u8>,
    /// Timeout length for each probe in seconds, included if flag 17 is set.
    #[deku(cond = "flags.get(17)")]
    pub timeout_sec: Option<u8>,
    /// How many loops are allowed before probing halts, included if flag 18 is set.
    #[deku(cond = "flags.get(18)")]
    pub allowed_loops: Option<u8>,
    /// Number of hops probed, included if flag 19 is set.
    #[deku(cond = "flags.get(19)")]
    pub hops_probed: Option<u16>,
    /// Gap limit before probing halts, included if flag 20 is set.
    #[deku(cond = "flags.get(20)")]
    pub gap_limit: Option<u8>,
    /// What to do when the gap limit is reached, included if flag 21 is set.
    #[deku(cond = "flags.get(21)")]
    pub gap_limit_action: Option<u8>,
    /// What to do when a loop is found, included if flag 22 is set.
    #[deku(cond = "flags.get(22)")]
    pub loop_action: Option<u8>,
    /// Number of probes sent, included if flag 23 is set.
    #[deku(cond = "flags.get(23)")]
    pub probes_sent: Option<u16>,
    /// Minimum time to wait between probes in centiseconds, included if flag 24 is set.
    #[deku(cond = "flags.get(24)")]
    pub interval_csec: Option<u8>,
    /// Confidence level to attain that all hops have replied at a given distance in the path,
    /// included if flag 25 is set.
    #[deku(cond = "flags.get(25)")]
    pub confidence_level: Option<u8>,
    /// Source address used in probes, included if flag 26 is set.
    #[deku(cond = "flags.get(26)")]
    pub src_addr: Option<Address>,
    /// Destination address used in probes, included if flag 27 is set.
    #[deku(cond = "flags.get(27)")]
    pub dst_addr: Option<Address>,
    /// User ID assigned to the traceroute, included if flag 28 is set.
    #[deku(cond = "flags.get(28)")]
    pub user_id: Option<u32>,
    /// IP offset value used in probes, included if flag 29 is set.
    #[deku(cond = "flags.get(29)")]
    pub ip_offset: Option<u16>,
    /// Router address used to send probes, included if flag 30 is set.
    #[deku(cond = "flags.get(30)")]
    pub router_addr: Option<Address>,
    /// Hop record count.
    pub hop_count: u16,
    /// Hop records, if hop record count > 0.
    #[deku(count = "hop_count")]
    pub hops: Vec<TraceProbe>,
    // TODO: Optional PMTUD, DoubleTree data.
    /// End of traceroute record; value is zero.
    #[deku(assert_eq = "0")]
    pub eof: u16,
}

/// A traceroute probe and its associated reply, if any.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct TraceProbe {
    pub flags: Flags,
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    /// Hop address, ID corresponding to global warts address; included if flag 1 is set.
    #[deku(cond = "flags.get(1)")]
    pub addr_id: Option<u32>,
    /// IP TTL of probe packet, included if flag 2 is set.
    #[deku(cond = "flags.get(2)")]
    pub probe_ttl: Option<u8>,
    /// IP TTL of reply packet, included if flag 3 is set.
    #[deku(cond = "flags.get(3)")]
    pub reply_ttl: Option<u8>,
    /// Hop flags, included if flag 4 is set
    #[deku(cond = "flags.get(4)")]
    pub hop_flags: Option<u8>,
    /// Hop probe ID - how many probes have been sent for the given TTL. Included if flag 5 is set.
    #[deku(cond = "flags.get(5)")]
    pub probe_id: Option<u8>,
    /// Round trip time - the length of time in microseconds it took this reply
    /// to arrive after the probe was transmitted. Included if flag 6 is set.
    #[deku(cond = "flags.get(6)")]
    pub rtt_usec: Option<u32>,
    /// ICMP type of the response. Included if flag 7 is set.
    #[deku(cond = "flags.get(7)")]
    pub icmp_type: Option<u8>,
    /// ICMP code of the response. Included if flag 7 is set.
    #[deku(cond = "flags.get(7)")]
    pub icmp_code: Option<u8>,
    /// Probe size - the size of the probe sent.  Included if flag 8 is set.
    #[deku(cond = "flags.get(8)")]
    pub probe_size: Option<u16>,
    /// Reply size - the size of the response received.  Included if flag 9 is set.
    #[deku(cond = "flags.get(9)")]
    pub reply_size: Option<u16>,
    /// IPID - the IP identifier value set in the response packet.
    /// Included if flag 10 is set, else it is zero.
    #[deku(cond = "flags.get(10)")]
    pub reply_ip_id: Option<u16>,
    /// Type of Service - the value of the ToS byte in the IP header, including ECN bits.
    /// Included if flag 11 is set.
    #[deku(cond = "flags.get(11)")]
    pub reply_ip_tos: Option<u8>,
    /// Next-hop MTU - the value of the next-hop MTU field if the response
    /// is an ICMP packet too big message. Included if flag 12 is set.
    #[deku(cond = "flags.get(12)")]
    pub next_hop_mtu: Option<u16>,
    /// Quoted IP length - the value of the IP length field found in the ICMP quotation.
    /// Included if flag 13 is set, else it is the same as the probe size.
    #[deku(cond = "flags.get(13)")]
    pub quoted_length: Option<u16>,
    /// Quoted TTL - the value of the IP TTL field found in the ICMP quotation.
    /// Included if flag 14 is set, else it is one.
    #[deku(cond = "flags.get(14)")]
    pub quoted_ttl: Option<u8>,
    /// TCP flags - the value of the TCP flags received in response to TCP probes.
    /// Included if flag 15 is set.
    #[deku(cond = "flags.get(15)")]
    pub reply_tcp_flags: Option<u8>,
    /// Quoted TOS - the value of the IP ToS byte found in the ICMP quotation.
    /// Included if flag 16 is set.
    #[deku(cond = "flags.get(16)")]
    pub quoted_tos: Option<u8>,
    /// ICMP extension total length, included if flag 17 is set.
    #[deku(cond = "flags.get(17)")]
    pub icmp_extensions_length: Option<u16>,
    // NOTE: We currently assume that there is at maximum one ICMP extension, and that it
    // contains an MPLS label stack.
    #[deku(
        cond = "flags.get(17)",
        count = "if icmp_extensions_length.unwrap() > 0 { 1 } else { 0 }"
    )]
    pub icmp_extensions: Vec<ICMPExtension>,
    /// Hop address, included if flag 18 is set.
    #[deku(cond = "flags.get(18)")]
    pub addr: Option<Address>,
    /// Hop tx, included if flag 19 is set.
    #[deku(cond = "flags.get(19)")]
    pub tx: Option<Timeval>,
}

impl Traceroute {
    pub fn fixup(&mut self) {
        let mut flags = Vec::new();
        let mut param_length = 0;
        push_flag!(flags, param_length, 1, self.list_id);
        push_flag!(flags, param_length, 2, self.cycle_id);
        push_flag!(flags, param_length, 3, self.src_addr_id);
        push_flag!(flags, param_length, 4, self.dst_addr_id);
        push_flag!(flags, param_length, 5, self.start_time);
        push_flag!(flags, param_length, 6, self.stop_reason);
        push_flag!(flags, param_length, 7, self.stop_data);
        push_flag!(flags, param_length, 8, self.trace_flags);
        push_flag!(flags, param_length, 9, self.attempts);
        push_flag!(flags, param_length, 10, self.hop_limit);
        push_flag!(flags, param_length, 11, self.trace_type);
        push_flag!(flags, param_length, 12, self.probe_size);
        push_flag!(flags, param_length, 13, self.src_port);
        push_flag!(flags, param_length, 14, self.dst_port);
        push_flag!(flags, param_length, 15, self.first_ttl);
        push_flag!(flags, param_length, 16, self.ip_tos);
        push_flag!(flags, param_length, 17, self.timeout_sec);
        push_flag!(flags, param_length, 18, self.allowed_loops);
        push_flag!(flags, param_length, 19, self.hops_probed);
        push_flag!(flags, param_length, 20, self.gap_limit);
        push_flag!(flags, param_length, 21, self.gap_limit_action);
        push_flag!(flags, param_length, 22, self.loop_action);
        push_flag!(flags, param_length, 23, self.probes_sent);
        push_flag!(flags, param_length, 24, self.interval_csec);
        push_flag!(flags, param_length, 25, self.confidence_level);
        push_flag!(flags, param_length, 26, self.src_addr);
        push_flag!(flags, param_length, 27, self.dst_addr);
        push_flag!(flags, param_length, 28, self.user_id);
        push_flag!(flags, param_length, 29, self.ip_offset);
        push_flag!(flags, param_length, 30, self.router_addr);
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
        self.hop_count = self.hops.len() as u16;
        let hops_size: usize = self.hops.iter().map(|hop| hop.warts_size()).sum();
        self.length = (self.flags.warts_size()
            + self.param_length.warts_size()
            + param_length
            + self.hop_count.warts_size()
            + hops_size
            + self.eof.warts_size()) as u32
    }
}

impl TraceProbe {
    pub fn fixup(&mut self) {
        let mut flags = Vec::new();
        let mut param_length = 0;
        push_flag!(flags, param_length, 1, self.addr_id);
        push_flag!(flags, param_length, 2, self.probe_ttl);
        push_flag!(flags, param_length, 3, self.reply_ttl);
        push_flag!(flags, param_length, 4, self.hop_flags);
        push_flag!(flags, param_length, 5, self.probe_id);
        push_flag!(flags, param_length, 6, self.rtt_usec);
        push_flag!(flags, param_length, 7, self.icmp_type);
        push_flag!(flags, param_length, 7, self.icmp_code);
        push_flag!(flags, param_length, 8, self.probe_size);
        push_flag!(flags, param_length, 9, self.reply_size);
        push_flag!(flags, param_length, 10, self.reply_ip_id);
        push_flag!(flags, param_length, 11, self.reply_ip_tos);
        push_flag!(flags, param_length, 12, self.next_hop_mtu);
        push_flag!(flags, param_length, 13, self.quoted_length);
        push_flag!(flags, param_length, 14, self.quoted_ttl);
        push_flag!(flags, param_length, 15, self.reply_tcp_flags);
        push_flag!(flags, param_length, 16, self.quoted_tos);
        push_flag!(flags, param_length, 17, self.icmp_extensions_length);
        // TODO: push_flag!(flags, length, 17, self.icmp_extensions);
        push_flag!(flags, param_length, 18, self.addr);
        push_flag!(flags, param_length, 19, self.tx.as_ref());
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
    }
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_usec.map(|x| x as f64 / 1000.0)
    }
}

impl WartsSized for TraceType {
    fn warts_size(&self) -> usize {
        1
    }
}

impl WartsSized for TraceStopReason {
    fn warts_size(&self) -> usize {
        1
    }
}

impl WartsSized for TraceProbe {
    fn warts_size(&self) -> usize {
        self.flags.warts_size()
            + self.param_length.warts_size()
            + self.param_length.unwrap() as usize
    }
}
