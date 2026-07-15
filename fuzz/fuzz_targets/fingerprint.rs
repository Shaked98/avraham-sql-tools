//! Arbitrary SQL-ish strings through the fingerprint normalizer. Must never
//! panic, must emit valid UTF-8 (guaranteed by the String type but the
//! internal byte-level collapses could corrupt it — the expect() inside
//! would abort), and must be idempotent: fingerprinting a fingerprint must
//! be a fixed point, otherwise the same query class could intern under two
//! different ids depending on which spelling arrived first.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sql_replay::fingerprint::fingerprint;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let fp = fingerprint(&s);
    let fp2 = fingerprint(&fp);
    assert_eq!(fp, fp2, "fingerprint not idempotent for input {s:?}");
});
