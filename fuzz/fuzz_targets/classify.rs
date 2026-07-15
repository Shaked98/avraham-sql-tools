//! Arbitrary statements through the replay write gate. classify() must
//! never panic, and two gate invariants are asserted:
//!
//! 1. Multi-statement smuggling: for any input that ends outside strings
//!    and block comments (per an independently written scanner), appending
//!    "\n;DROP TABLE fuzz_guard" MUST classify as Write — a top-level `;`
//!    followed by content is never provably read-only.
//! 2. Comment/whitespace prefix invariance: prepending a complete comment
//!    or whitespace never changes the classification, so an attacker can't
//!    flip the gate with padding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sql_replay::classify::{classify, QueryClass};

#[derive(PartialEq)]
enum EndState {
    Normal,
    InString,
    InBlockComment,
}

/// Independent (deliberately re-written) scan of MySQL lexical state at
/// end-of-input: backslash escapes in '\'' and '"' but not '`', doubled
/// quotes, non-nesting /* */ comments, `-- ` and `#` line comments ended
/// by '\n'.
fn end_state(s: &str) -> EndState {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        match b[i] {
            q @ (b'\'' | b'"' | b'`') => {
                i += 1;
                loop {
                    if i >= n {
                        return EndState::InString;
                    }
                    if b[i] == b'\\' && q != b'`' {
                        i += 2;
                    } else if b[i] == q {
                        if i + 1 < n && b[i + 1] == q {
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'/' if i + 1 < n && b[i + 1] == b'*' => {
                i += 2;
                loop {
                    if i + 1 >= n {
                        return EndState::InBlockComment;
                    }
                    if b[i] == b'*' && b[i + 1] == b'/' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            b'#' => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'-' if i + 1 < n
                && b[i + 1] == b'-'
                && (i + 2 >= n || b[i + 2].is_ascii_whitespace()) =>
            {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    EndState::Normal
}

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let class = classify(&s);

    // Invariant 1: appended top-level statement always makes it a write.
    // The leading '\n' terminates any open line comment; strings and block
    // comments have no closer we could safely synthesize, so skip those.
    if end_state(&s) == EndState::Normal {
        let smuggled = format!("{s}\n;DROP TABLE fuzz_guard");
        assert_eq!(
            classify(&smuggled),
            QueryClass::Write,
            "write gate missed a trailing statement after {s:?}"
        );
    }

    // Invariant 2: complete comment / whitespace prefixes are neutral.
    for prefix in ["/*x*/ ", "  \t\n", "-- c\n", "# c\n"] {
        let padded = format!("{prefix}{s}");
        assert_eq!(
            classify(&padded),
            class,
            "classification flipped by prefix {prefix:?} on {s:?}"
        );
    }
});
