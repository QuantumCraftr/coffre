#![no_main]

use coffre_core::format::decode_payload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_payload(data);
});
