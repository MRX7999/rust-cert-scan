//! Цель cargo-fuzz `client_hello`: тело и инварианты — в `certscan_fuzz::client_hello`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    certscan_fuzz::client_hello(data);
});
