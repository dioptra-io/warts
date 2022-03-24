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
