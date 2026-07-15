//! Corrupted capture files through `format::stream_capture`. Every failure
//! must surface as an Err, never a panic. Two modes, chosen by the first
//! byte: the remaining bytes are fed either raw (fuzzes the zstd framing)
//! or wrapped in a valid zstd frame (fuzzes the JSONL record layer, which
//! raw mode almost never reaches past the magic-number check).

#![no_main]

use std::io::Write;
use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use sql_replay::format::stream_capture;

fn scratch_path() -> PathBuf {
    std::env::temp_dir().join(format!("sql-replay-fuzz-capture-{}", std::process::id()))
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, payload)) = data.split_first() else {
        return;
    };
    let bytes = if mode & 1 == 0 {
        payload.to_vec()
    } else {
        zstd::encode_all(payload, 1).expect("in-memory zstd encode")
    };
    let path = scratch_path();
    {
        let mut f = std::fs::File::create(&path).expect("create scratch file");
        f.write_all(&bytes).expect("write scratch file");
    }
    // Err is the expected outcome for almost every input; only panics or
    // hangs are findings. On Ok, the events closure has run to completion.
    let _ = stream_capture(&path, |_event| Ok(()));
});
