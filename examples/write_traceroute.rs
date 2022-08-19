use chrono::Utc;
use deku::DekuContainerWrite;
use std::ffi::CString;
use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use warts::{
    Address, CycleStart, CycleStop, Flags, List, Object, Timeval, TraceGapAction, TraceProbe,
    TraceStopReason, TraceType, Traceroute,
};

fn main() -> io::Result<()> {
    let list_name = CString::new("default").unwrap();
    let hostname = CString::new("ubuntu-linux-20-04-desktop").unwrap();

    let mut list = List {
        length: 0,
        list_id: 1,
        list_id_human: 0,
        name: list_name.clone(),
        flags: Default::default(),
        param_length: None,
        description: Some(list_name.clone()),
        monitor_name: None,
    };
    // The `fixup()` method computes and set the flags and length fields.
    list.fixup();
    io::stdout().write_all(&Object::List(list).to_bytes().unwrap())?;

    let mut cycle_start = CycleStart {
        length: 0,
        cycle_id: 1,
        list_id: 1,
        cycle_id_human: 0,
        start_time: Utc::now().timestamp() as u32,
        flags: Default::default(),
        param_length: None,
        stop_time: None,
        hostname: Some(hostname),
    };
    cycle_start.fixup();
    io::stdout().write_all(&Object::CycleStart(cycle_start).to_bytes().unwrap())?;

    let mut tp = TraceProbe {
        flags: Default::default(),
        param_length: None,
        addr_id: None,
        probe_ttl: Some(1),
        reply_ttl: Some(254),
        hop_flags: Some(17),
        probe_id: Some(0),
        rtt_usec: Some(1057),
        icmp_type: Some(11),
        icmp_code: Some(0),
        probe_size: Some(44),
        reply_size: Some(56),
        reply_ip_id: Some(387),
        reply_ip_tos: Some(0),
        next_hop_mtu: None,
        quoted_length: None,
        quoted_ttl: None,
        reply_tcp_flags: None,
        quoted_tos: Some(0),
        icmp_extensions_length: None,
        icmp_extensions: vec![],
        addr: Some(Address::from(Ipv4Addr::new(137, 194, 164, 254))),
        tx: Some(Timeval::from(Utc::now().naive_utc())),
    };
    tp.fixup();

    let mut traceroute = Traceroute {
        length: 0,
        flags: Flags::default(),
        param_length: None,
        list_id: Some(1),
        cycle_id: Some(1),
        src_addr_id: None,
        dst_addr_id: None,
        start_time: Some(Timeval::from(Utc::now().naive_utc())),
        stop_reason: Some(TraceStopReason::Completed),
        stop_data: Some(0),
        trace_flags: None,
        attempts: Some(2),
        hop_limit: Some(0),
        trace_type: Some(TraceType::UDPParis),
        probe_size: Some(44),
        src_port: Some(57352),
        dst_port: Some(33435),
        first_ttl: Some(1),
        ip_tos: Some(0),
        timeout_sec: Some(5),
        allowed_loops: Some(1),
        hops_probed: Some(7),
        gap_limit: Some(5),
        gap_limit_action: Some(TraceGapAction::LastDitch),
        loop_action: Some(0),
        probes_sent: Some(8),
        interval_csec: Some(0),
        confidence_level: Some(0),
        src_addr: Some(Address::from(Ipv4Addr::new(137, 194, 165, 109))),
        dst_addr: Some(Address::from(Ipv4Addr::new(8, 8, 8, 8))),
        user_id: None,
        ip_offset: None,
        router_addr: None,
        hop_count: 1,
        hops: vec![tp],
        eof: 0,
    };
    traceroute.fixup();
    io::stdout().write_all(
        Object::Traceroute(traceroute)
            .to_bytes()
            .unwrap()
            .as_slice(),
    )?;

    let mut cycle_stop = CycleStop {
        length: 0,
        cycle_id: 1,
        stop_time: Utc::now().timestamp() as u32,
        flags: Default::default(),
    };
    cycle_stop.fixup();
    io::stdout().write_all(&Object::CycleStop(cycle_stop).to_bytes().unwrap())?;

    Ok(())
}
