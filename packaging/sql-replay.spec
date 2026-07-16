# RPM spec for sql-replay on RHEL 8 (and compatible: Rocky/Alma/Oracle 8+).
#
# The packaged binary is the static musl build (x86_64-unknown-linux-musl):
# no glibc/OpenSSL runtime dependencies, so one RPM serves every EL8 host.
# Build from the release tarball produced by .github/workflows/release.yml:
#
#   rpmbuild -bb packaging/sql-replay.spec \
#     --define "_sourcedir $PWD/dist" \
#     --define "version 0.4.0"
#
# where dist/ holds sql-replay-<version>-x86_64-unknown-linux-musl.tar.gz.

%{!?version: %global version 0.4.0}

# The binary is prebuilt and static: no debuginfo to extract, no build-id
# links, and no automatic library dependencies to scan for.
%global debug_package %{nil}
%global _build_id_links none
%global __brp_strip_static_archive %{nil}

Name:           sql-replay
Version:        %{version}
Release:        1%{?dist}
Summary:        MySQL slow-log capture and replay benchmarking tool
License:        MIT OR Apache-2.0
URL:            https://github.com/Shaked98/avraham-sql-tools
Source0:        sql-replay-%{version}-x86_64-unknown-linux-musl.tar.gz
ExclusiveArch:  x86_64
AutoReqProv:    no

%description
sql-replay captures MySQL slow query logs (long_query_time=0) into a
compressed replay file, replays them against a target server at the
original concurrency — optionally honoring the capture's original timing —
and compares two run reports to gate 5.7 -> 8.0 migrations on per-query
latency regressions. When the source server cannot be replayed against
because it is live production, the baseline report can instead be built
from the capture's recorded slow-log latencies (sql-replay baseline).

The binary is statically linked (musl); it has no runtime dependencies.

%prep
%setup -q -n sql-replay-%{version}-x86_64-unknown-linux-musl

%install
install -Dm755 sql-replay %{buildroot}%{_bindir}/sql-replay
install -Dm644 README.md %{buildroot}%{_docdir}/sql-replay/README.md

%check
%{buildroot}%{_bindir}/sql-replay --version

%files
%{_bindir}/sql-replay
%doc %{_docdir}/sql-replay/README.md
%license LICENSE-MIT LICENSE-APACHE

%changelog
* Wed Jul 15 2026 avraham-sql-tools contributors - 0.4.0-1
- pcap capture source: `capture --input traffic.pcap` decodes MySQL wire
  traffic recorded with tcpdump (prepared statements expanded, true wire
  timestamps, request->response latencies recorded for `baseline`).
- Result-correctness diffing: `replay --checksum` records order-
  insensitive result-set checksums; `compare` gains a correctness section
  and exits 2 on deterministic result mismatches.

* Wed Jul 15 2026 avraham-sql-tools contributors - 0.2.0-1
- `baseline` subcommand: build a compare-ready baseline report from a
  capture's recorded production slow-log latencies (no replay target
  needed); `compare` warns when a recorded side meets a replayed one.

* Tue Jul 14 2026 avraham-sql-tools contributors - 0.1.0-1
- Initial RPM packaging (M3): static musl binary, no runtime dependencies.
