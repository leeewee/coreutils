#![no_main]
use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;
use uufuzz::generate_and_run_uumain;
fn fake_uumain(_a: std::vec::IntoIter<OsString>) -> i32 {
    match std::env::var("PROBE").as_deref() {
        Ok("panic") => panic!("probe explicit panic"),
        Ok("cap") => { let v: Vec<u8> = Vec::with_capacity(usize::MAX); v.len() as i32 }
        Ok("oom") => { let v = vec![1u8; 1usize << 40]; v.len() as i32 }
        Ok("alloc") => { let v: Vec<u8> = std::hint::black_box(Vec::with_capacity(1usize << 42)); std::hint::black_box(&v); v.capacity() as i32 }
        _ => 0,
    }
}
fuzz_target!(|_d: &[u8]| { let r = generate_and_run_uumain(&[OsString::from("probe")], fake_uumain, None); println!("{r:?}"); });
