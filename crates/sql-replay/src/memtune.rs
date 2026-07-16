//! Process-wide memory tuning for blob-heavy workloads.
//!
//! Replay peak memory is O(active connections x largest result row) by
//! design: each in-flight statement briefly holds its current row twice
//! (the wire packet buffer plus the decoded row — mysql_async's public
//! API has no decode-free drain), and `--pool N` bounds active
//! connections when a capture has more sessions than memory allows. On
//! top of that floor, two *retention* mechanisms used to keep multi-MB
//! buffers alive long after the rows were dropped, growing peak RSS to
//! ~50 MB per session against 15 MB rows (measured: 85 MB at 1 session
//! -> 725 MB at 12; see the README's "Memory model" section). This
//! module removes both:
//!
//! - mysql_async reads every packet into a buffer from a global pool of
//!   up to 128, and a buffer returned to the pool only shrinks to
//!   `MYSQL_ASYNC_BUFFER_SIZE_CAP` (driver default 4 MiB) — up to
//!   512 MiB retained after a blob-heavy replay. We default the cap to
//!   128 KiB instead: buffers at or under it are still pooled and
//!   reused (small-row workloads see no change), larger ones are freed
//!   on return.
//!
//! - glibc's malloc dynamically raises its mmap threshold (up to
//!   32 MiB) the first time it frees an mmap'd chunk, so freed multi-MB
//!   packet/row buffers soon come from sbrk arenas and are retained by
//!   the allocator instead of returned to the OS. Pinning the threshold
//!   keeps multi-MB buffers mmap'd, so freeing them immediately returns
//!   the memory. musl (the RHEL 8 static binary) already unmaps large
//!   frees; this knob is glibc-only.
//!
//! Both knobs respect an explicit environment override
//! (`MYSQL_ASYNC_BUFFER_SIZE_CAP`, `MALLOC_MMAP_THRESHOLD_`), and both
//! are applied by the binary's `main` — library embedders keep their
//! process untouched.

/// Retention cap in bytes: pooled packet buffers above this are freed
/// instead of kept, and (on glibc) allocations at or above it are
/// mmap'd so freeing returns them to the OS. 128 KiB comfortably holds
/// ordinary statement/row packets, so non-blob workloads keep full
/// buffer reuse.
pub const RETAINED_BUFFER_CAP_BYTES: usize = 128 * 1024;

/// Apply the tuning. Call once at process start, before any other
/// thread exists (it mutates the environment) and before the first
/// MySQL connection (mysql_async initializes its buffer pool lazily,
/// once, from the environment).
pub fn tune_process_memory() {
    if std::env::var_os("MYSQL_ASYNC_BUFFER_SIZE_CAP").is_none() {
        std::env::set_var(
            "MYSQL_ASYNC_BUFFER_SIZE_CAP",
            RETAINED_BUFFER_CAP_BYTES.to_string(),
        );
    }

    // glibc reads MALLOC_MMAP_THRESHOLD_ at startup; when the user set
    // it, the dynamic threshold is already disabled and we must not
    // override their choice. mallopt returns 1 on success — nothing
    // actionable on failure, so the result is ignored.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    if std::env::var_os("MALLOC_MMAP_THRESHOLD_").is_none() {
        // SAFETY: FFI call with no pointer arguments, made while the
        // process is still single-threaded.
        unsafe {
            libc::mallopt(
                libc::M_MMAP_THRESHOLD,
                RETAINED_BUFFER_CAP_BYTES as libc::c_int,
            );
        }
    }
}
