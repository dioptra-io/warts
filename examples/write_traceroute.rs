use chrono::Utc;
use deku::DekuContainerWrite;
use std::ffi::CString;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::{fs, io};
use warts::Address::IPv4;
use warts::Object::{CycleStart, CycleStop, List, Traceroute};
use warts::{Address, Flags, Timeval, TraceProbe, TraceStopReason, TraceType};

fn warts_string_len_u16(s: &CString) -> u16 {
    return s.to_bytes_with_nul().len() as u16;
}

fn warts_string_len_u32(s: &CString) -> u32 {
    return s.to_bytes_with_nul().len() as u32;
}

fn main() {
    // NOTE: Currently flags and length fields must be computed manually.
    let list_name = CString::new("default").unwrap();
    let hostname = CString::new("ubuntu-linux-20-04-desktop").unwrap();
    let list = List {
        length: 2 * 4 + 1 + 2 + 2 * warts_string_len_u32(&list_name),
        list_id: 1,
        list_id_human: 0,
        name: list_name.clone(),
        flags: Flags::from(Vec::from([1])),
        param_length: Some(warts_string_len_u16(&list_name)),
        description: Some(list_name.clone()),
        monitor_name: None,
    };
    let cycle_start = CycleStart {
        length: 4 * 4 + 1 + 2 + warts_string_len_u32(&hostname),
        cycle_id: 1,
        list_id: 1,
        cycle_id_human: 0,
        start_time: Utc::now().timestamp() as u32,
        flags: Flags::from(Vec::from([2])),
        param_length: Some(warts_string_len_u16(&hostname)),
        stop_time: None,
        hostname: Some(hostname),
    };
    let cycle_stop = CycleStop {
        length: 2 * 4 + 1,
        cycle_id: 1,
        stop_time: Utc::now().timestamp() as u32,
        flags: Flags::from(Vec::from([])),
    };
    let traceroute = Traceroute {
        length: 99,
        flags: Flags::from(Vec::from([
            1, 2, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
            27,
        ])),
        param_length: Some(52),
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
        gap_limit_action: Some(1),
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
        hops: vec![TraceProbe {
            flags: Flags::from(Vec::from([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 18, 19])),
            param_length: Some(32),
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
        }],
        eof: 0,
    };
    io::stdout().write_all(list.to_bytes().unwrap().as_slice());
    io::stdout().write_all(cycle_start.to_bytes().unwrap().as_slice());
    io::stdout().write_all(traceroute.to_bytes().unwrap().as_slice());
    io::stdout().write_all(cycle_stop.to_bytes().unwrap().as_slice());
}
