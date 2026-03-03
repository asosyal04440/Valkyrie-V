#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = core::str::from_utf8(data);
    let mut checksum = 0u8;
    for byte in data {
        checksum ^= *byte;
    }
    let _ = checksum;
});
