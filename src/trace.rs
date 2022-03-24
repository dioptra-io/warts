use crate::{Address, Flags, ICMPExtension, Timeval};
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

impl TraceProbe {
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_usec.map(|x| x as f64 / 1000.0)
    }
}
