//! Цель cargo-fuzz `record_layer`: тело и инварианты — в `certscan_fuzz::record_layer`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    certscan_fuzz::record_layer(data);
});
