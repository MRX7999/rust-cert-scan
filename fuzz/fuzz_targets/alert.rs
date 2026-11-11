//! Цель cargo-fuzz `alert`: тело и инварианты — в `certscan_fuzz::alert`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    certscan_fuzz::alert(data);
});
