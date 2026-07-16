//! Arbitrary SQL-ish strings through the fingerprint normalizer. Must
//! never panic (the byte-level IN/VALUES collapses carry internal
//! expect()s that UTF-8 corruption would abort), and two metamorphic
//! properties the grouping depends on are asserted:
//!
//! - ASCII case invariance: the same query differing only in letter case
//!   must land in the same class.
//! - Leading/trailing whitespace invariance: padding must not change the
//!   class.
//!
//! Full idempotence (fingerprint(fingerprint(x)) == fingerprint(x)) does
//! NOT hold — output can end in `--`, which re-reads as a comment — and is
//! deliberately not asserted: the pipeline fingerprints raw query text
//! exactly once and never re-fingerprints normalized text.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sql_replay::fingerprint::fingerprint;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let fp = fingerprint(&s);

    let upper = fingerprint(&s.to_ascii_uppercase());
    assert_eq!(fp, upper, "fingerprint is ASCII-case sensitive for {s:?}");

    let padded = fingerprint(&format!(" \t\n{s} \t\n"));
    assert_eq!(fp, padded, "fingerprint changed by padding for {s:?}");
});
