use std::{env, fs};
use warts::Object;

fn main() {
    let args: Vec<String> = env::args().collect();
    for path in &args[1..] {
        let data = fs::read(path).unwrap();
        let objects = Object::all_from_bytes(&data);
        for object in objects {
            println!("{:?}", object);
        }
    }
}
