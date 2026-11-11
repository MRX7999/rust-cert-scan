//! Цель cargo-fuzz `certificate`: тело и инварианты — в `certscan_fuzz::certificate`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    certscan_fuzz::certificate(data);
});
