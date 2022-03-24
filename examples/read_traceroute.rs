use std::net::IpAddr;
use std::{env, fs};
use warts::Object;

fn main() {
    let args: Vec<String> = env::args().collect();
    for path in &args[1..] {
        let data = fs::read(path).unwrap();
        let objects = Object::all_from_bytes(&data);
        for mut object in objects {
            // Resolve IP addresses references.
            object.dereference();
            print(object);
        }
    }
}

fn print(object: Object) {
    match object {
        Object::Traceroute {
            src_addr,
            dst_addr,
            hops,
            ..
        } => {
            // NOTE: In practice, you may want to handle the case where the fields
            // behind flags are not present.
            let src_addr = IpAddr::from(src_addr.unwrap());
            let dst_addr = IpAddr::from(dst_addr.unwrap());
            println!("Traceroute from {} to {}", src_addr, dst_addr);
            for hop in hops {
                let addr = IpAddr::from(hop.addr.unwrap());
                println!("{} {}", hop.probe_ttl.unwrap(), addr);
            }
        }
        _ => {}
    }
}
