//! Arbitrary bytes through the slow-log parser, fed exactly the way
//! `capture::run_capture` feeds it (read_until(b'\n'), lossy UTF-8, strip
//! trailing \n/\r). The parser must never panic, whatever the input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sql_replay::slowlog::SlowLogParser;

fuzz_target!(|data: &[u8]| {
    let mut parser = SlowLogParser::new();
    let mut events = 0u64;
    for raw in data.split_inclusive(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(raw);
        let line = line.trim_end_matches(['\n', '\r']);
        if let Some(q) = parser.push_line(line) {
            // take_query never emits an empty statement.
            assert!(!q.query.is_empty());
            events += 1;
        }
    }
    if let Some(q) = parser.finish() {
        assert!(!q.query.is_empty());
        events += 1;
    }
    // finish() must be idempotent: a second call cannot yield another event.
    assert!(parser.finish().is_none(), "finish() emitted twice");
    let _ = events;
});
