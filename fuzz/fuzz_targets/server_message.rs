//! Цель cargo-fuzz `server_message`: тело и инварианты — в `certscan_fuzz::server_message`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    certscan_fuzz::server_message(data);
});
