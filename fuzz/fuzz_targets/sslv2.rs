//! Цель cargo-fuzz `sslv2`: тело и инварианты — в `certscan_fuzz::sslv2`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    certscan_fuzz::sslv2(data);
});
