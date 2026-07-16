//! Self-contained HTML rendering for [`crate::compare::CompareReport`]:
//! inline CSS and a tiny inline sort script only — no CDN, fonts, images,
//! or network requests of any kind, so the report renders offline.

use std::fmt::Write as _;

use crate::compare::{BucketDelta, ChecksumDelta, CompareReport, FpDelta, OnlyIn, RunMeta};
use crate::report::fmt_bytes;

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn fmt_ms(us: f64) -> String {
    format!("{:.3}", us / 1000.0)
}

fn pct_cell(p: Option<f64>) -> String {
    match p {
        Some(p) => {
            let class = if p >= 0.5 {
                "worse"
            } else if p <= -0.5 {
                "better"
            } else {
                ""
            };
            format!(r#"<td class="num {class}" data-v="{p:.4}">{p:+.1}%</td>"#)
        }
        None => r#"<td class="num" data-v="0">n/a</td>"#.to_string(),
    }
}

fn fp_rows(out: &mut String, rows: &[FpDelta], class: &str) {
    for d in rows {
        let mismatch = if d.count_mismatch {
            r#" <span class="badge">count mismatch</span>"#
        } else {
            ""
        };
        let (bbytes_v, bbytes, cbytes_v, cbytes, bytespct) = match &d.result_bytes {
            Some(b) => (
                b.baseline_mean,
                fmt_bytes(b.baseline_mean),
                b.candidate_mean,
                fmt_bytes(b.candidate_mean),
                pct_cell(b.mean_delta_pct),
            ),
            None => (
                0.0,
                "n/a".to_string(),
                0.0,
                "n/a".to_string(),
                r#"<td class="num" data-v="0">n/a</td>"#.to_string(),
            ),
        };
        let _ = write!(
            out,
            r#"<tr><td>{class}</td><td class="fp">{fp}{mismatch}</td>
<td class="num" data-v="{bc}">{bc}</td><td class="num" data-v="{cc}">{cc}</td>
<td class="num" data-v="{bp95}">{bp95_ms}</td><td class="num" data-v="{cp95}">{cp95_ms}</td>{p95pct}
<td class="num" data-v="{bp50}">{bp50_ms}</td><td class="num" data-v="{cp50}">{cp50_ms}</td>{p50pct}
<td class="num" data-v="{bp99}">{bp99_ms}</td><td class="num" data-v="{cp99}">{cp99_ms}</td>{p99pct}
<td class="num" data-v="{bmean}">{bmean_ms}</td><td class="num" data-v="{cmean}">{cmean_ms}</td>{meanpct}
<td class="num" data-v="{bbytes_v}">{bbytes}</td><td class="num" data-v="{cbytes_v}">{cbytes}</td>{bytespct}
<td class="num" data-v="{be}">{be}</td><td class="num" data-v="{ce}">{ce}</td></tr>
"#,
            fp = esc(&d.fingerprint),
            bc = d.baseline_count,
            cc = d.candidate_count,
            bp95 = d.p95.baseline_us,
            bp95_ms = fmt_ms(d.p95.baseline_us),
            cp95 = d.p95.candidate_us,
            cp95_ms = fmt_ms(d.p95.candidate_us),
            p95pct = pct_cell(d.p95.delta_pct),
            bp50 = d.p50.baseline_us,
            bp50_ms = fmt_ms(d.p50.baseline_us),
            cp50 = d.p50.candidate_us,
            cp50_ms = fmt_ms(d.p50.candidate_us),
            p50pct = pct_cell(d.p50.delta_pct),
            bp99 = d.p99.baseline_us,
            bp99_ms = fmt_ms(d.p99.baseline_us),
            cp99 = d.p99.candidate_us,
            cp99_ms = fmt_ms(d.p99.candidate_us),
            p99pct = pct_cell(d.p99.delta_pct),
            bmean = d.mean.baseline_us,
            bmean_ms = fmt_ms(d.mean.baseline_us),
            cmean = d.mean.candidate_us,
            cmean_ms = fmt_ms(d.mean.candidate_us),
            meanpct = pct_cell(d.mean.delta_pct),
            be = d.baseline_errors,
            ce = d.candidate_errors,
        );
    }
}

fn only_in_table(out: &mut String, title: &str, list: &[OnlyIn]) {
    if list.is_empty() {
        return;
    }
    let _ = write!(
        out,
        "<h2>{title} ({n})</h2>\n<table><thead><tr><th>executed</th><th>errors</th><th>fingerprint</th></tr></thead><tbody>\n",
        n = list.len()
    );
    for o in list {
        let _ = write!(
            out,
            r#"<tr><td class="num">{}</td><td class="num">{}</td><td class="fp">{}</td></tr>"#,
            o.count,
            o.errors,
            esc(&o.fingerprint)
        );
        out.push('\n');
    }
    out.push_str("</tbody></table>\n");
}

fn checksum_table(out: &mut String, title: &str, list: &[ChecksumDelta], failures: bool) {
    if list.is_empty() {
        return;
    }
    let _ = write!(
        out,
        "<h3>{title} ({n})</h3>\n<table><thead><tr><th>fingerprint</th>\
<th>digest b</th><th>digest c</th><th>rows b</th><th>rows c</th>\
<th>events b</th><th>events c</th><th>flags</th></tr></thead><tbody>\n",
        title = esc(title),
        n = list.len()
    );
    for d in list {
        let mut badges = String::new();
        if d.columns_differ {
            badges.push_str(r#" <span class="badge">columns differ</span>"#);
        }
        if d.events_differ {
            badges.push_str(r#" <span class="badge">event counts differ</span>"#);
        }
        if d.nondeterministic {
            badges.push_str(r#" <span class="badge">nondeterministic</span>"#);
        }
        let cls = if failures { " class=\"differs\"" } else { "" };
        let _ = writeln!(
            out,
            r#"<tr{cls}><td class="fp">{fp}</td><td class="num">{bd}</td><td class="num">{cd}</td>
<td class="num">{br}</td><td class="num">{cr}</td><td class="num">{be}</td><td class="num">{ce}</td><td>{badges}</td></tr>"#,
            fp = esc(&d.fingerprint),
            bd = esc(&d.baseline_digest),
            cd = esc(&d.candidate_digest),
            br = d.baseline_rows,
            cr = d.candidate_rows,
            be = d.baseline_events,
            ce = d.candidate_events,
        );
    }
    out.push_str("</tbody></table>\n");
}

fn size_bucket_rows(out: &mut String, rows: &[BucketDelta]) {
    if rows.is_empty() {
        return;
    }
    out.push_str(
        "<table><thead><tr><th>decade</th><th>fingerprint</th><th>count b</th><th>count c</th>\
<th>p95 b (ms)</th><th>p95 c (ms)</th><th>Δp95</th>\
<th>p50 b (ms)</th><th>p50 c (ms)</th><th>Δp50</th>\
<th>mean b (ms)</th><th>mean c (ms)</th><th>Δmean</th>\
<th>bytes b</th><th>bytes c</th></tr></thead><tbody>\n",
    );
    for d in rows {
        let mismatch = if d.count_mismatch {
            r#" <span class="badge">count mismatch</span>"#
        } else {
            ""
        };
        let _ = write!(
            out,
            r#"<tr class="differs"><td>{bucket}</td><td class="fp">{fp}{mismatch}</td>
<td class="num">{bc}</td><td class="num">{cc}</td>
<td class="num">{bp95}</td><td class="num">{cp95}</td>{p95pct}
<td class="num">{bp50}</td><td class="num">{cp50}</td>{p50pct}
<td class="num">{bmean}</td><td class="num">{cmean}</td>{meanpct}
<td class="num">{bb}</td><td class="num">{cb}</td></tr>
"#,
            bucket = esc(&d.bucket),
            fp = esc(&d.fingerprint),
            bc = d.baseline_count,
            cc = d.candidate_count,
            bp95 = fmt_ms(d.p95.baseline_us),
            cp95 = fmt_ms(d.p95.candidate_us),
            p95pct = pct_cell(d.p95.delta_pct),
            bp50 = fmt_ms(d.p50.baseline_us),
            cp50 = fmt_ms(d.p50.candidate_us),
            p50pct = pct_cell(d.p50.delta_pct),
            bmean = fmt_ms(d.mean.baseline_us),
            cmean = fmt_ms(d.mean.candidate_us),
            meanpct = pct_cell(d.mean.delta_pct),
            bb = fmt_bytes(d.baseline_bytes_total as f64),
            cb = fmt_bytes(d.candidate_bytes_total as f64),
        );
    }
    out.push_str("</tbody></table>\n");
}

fn meta_rows(out: &mut String, b: &RunMeta, c: &RunMeta) {
    let flags = |m: &RunMeta| {
        format!(
            "max-connections={} allow-writes={} db-override={} speed={}",
            m.flags.max_connections,
            m.flags.allow_writes,
            m.flags.db_override.as_deref().unwrap_or("<none>"),
            m.flags.speed,
        )
    };
    let pacing = |m: &RunMeta| match &m.pacing {
        Some(p) => format!(
            "speed {}x, max lag {} ms, mean lag {:.1} ms",
            p.speed,
            p.max_lag_us / 1000,
            p.mean_lag_us / 1000.0
        ),
        None => "—".to_string(),
    };
    let url = |m: &RunMeta| {
        if m.target_url.is_empty() {
            "— (no target)".to_string()
        } else {
            m.target_url.clone()
        }
    };
    let rows: [(&str, String, String); 11] = [
        ("run file", b.file.clone(), c.file.clone()),
        (
            "latency source",
            b.latency_source.clone(),
            c.latency_source.clone(),
        ),
        (
            "target server version",
            b.display_server_version(),
            c.display_server_version(),
        ),
        ("target url", url(b), url(c)),
        (
            "capture file",
            b.capture_file.clone(),
            c.capture_file.clone(),
        ),
        (
            "capture dialect",
            b.capture_dialect.clone(),
            c.capture_dialect.clone(),
        ),
        ("started at", b.started_at.clone(), c.started_at.clone()),
        (
            "wall clock",
            format!("{:.2}s", b.wall_secs),
            format!("{:.2}s", c.wall_secs),
        ),
        (
            "executed / errors",
            format!("{} / {}", b.totals.executed, b.totals.errors),
            format!("{} / {}", c.totals.executed, c.totals.errors),
        ),
        ("flags", flags(b), flags(c)),
        ("pacing", pacing(b), pacing(c)),
    ];
    for (name, bv, cv) in rows {
        let differs =
            if bv != cv && name != "run file" && name != "started at" && name != "target url" {
                " class=\"differs\""
            } else {
                ""
            };
        let _ = writeln!(
            out,
            "<tr{differs}><th>{}</th><td>{}</td><td>{}</td></tr>",
            esc(name),
            esc(&bv),
            esc(&cv)
        );
    }
}

pub fn render_html(r: &CompareReport) -> String {
    let mut out = String::with_capacity(64 * 1024);
    let title = format!(
        "sql-replay compare: {} vs {}",
        r.baseline.display_server_version(),
        r.candidate.display_server_version()
    );
    let _ = write!(
        out,
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font: 14px/1.45 system-ui, sans-serif; margin: 1.5rem auto; max-width: 90rem; padding: 0 1rem; }}
h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.1rem; margin-top: 1.6rem; }}
table {{ border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }}
th, td {{ border: 1px solid color-mix(in srgb, currentColor 25%, transparent); padding: .25rem .5rem; text-align: left; vertical-align: top; }}
thead th {{ position: sticky; top: 0; background: Canvas; }}
td.num {{ text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }}
td.fp {{ font-family: ui-monospace, monospace; font-size: .85rem; word-break: break-word; max-width: 36rem; }}
.worse {{ color: light-dark(#b00020, #ff8a80); font-weight: 600; }}
.better {{ color: light-dark(#00695c, #80cbc4); font-weight: 600; }}
.warnbox {{ border: 2px solid light-dark(#b00020, #ff8a80); background: light-dark(#fff3f3, #3a1416); padding: .75rem 1rem; border-radius: .4rem; margin: 1rem 0; }}
.warnbox h2 {{ margin: 0 0 .4rem; color: light-dark(#b00020, #ff8a80); }}
.badge {{ background: light-dark(#fde293, #6d5300); border-radius: .5rem; padding: 0 .4rem; font-size: .75rem; white-space: nowrap; }}
tr.differs td {{ background: light-dark(#fff8e1, #4a3d10); }}
table.sortable th {{ cursor: pointer; user-select: none; }}
table.sortable th[data-dir="asc"]::after {{ content: " ▲"; }}
table.sortable th[data-dir="desc"]::after {{ content: " ▼"; }}
.muted {{ opacity: .7; }}
.versions {{ font-size: 1.05rem; }}
.versions b {{ font-size: 1.2rem; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="versions">baseline <b>{bver}</b> ({bfile}) → candidate <b>{cver}</b> ({cfile})<br>
<span class="muted">generated by sql-replay {ver} — threshold ±{thr}%, min count {minc}</span></p>
"#,
        title = esc(&title),
        bver = esc(&r.baseline.display_server_version()),
        bfile = esc(&r.baseline.file),
        cver = esc(&r.candidate.display_server_version()),
        cfile = esc(&r.candidate.file),
        ver = esc(&r.tool_version),
        thr = r.threshold_pct,
        minc = r.min_count,
    );

    if !r.comparability_warnings.is_empty() {
        out.push_str(
            "<div class=\"warnbox\"><h2>⚠ Comparability warnings — the runs may not be directly comparable</h2><ul>\n",
        );
        for w in &r.comparability_warnings {
            let _ = writeln!(out, "<li>{}</li>", esc(w));
        }
        out.push_str("</ul></div>\n");
    }

    if r.correctness_failed {
        let n = r
            .correctness
            .as_ref()
            .map(|c| c.mismatches.len())
            .unwrap_or(0);
        let _ = writeln!(
            out,
            r#"<p><b class="worse">{n} fingerprint(s) returned different data (result checksum mismatch)</b> (exit code 2).</p>"#,
        );
    }
    if r.size_regressed {
        let _ = writeln!(
            out,
            r#"<p><b class="worse">{} result-size decade(s) regressed ≥ {}% on p95 inside otherwise-stable fingerprints</b> (exit code 2).</p>"#,
            r.size_regressions.len(),
            r.threshold_pct
        );
    }
    let verdict = if r.regressed {
        format!(
            r#"<p><b class="worse">{} fingerprint(s) regressed ≥ {}% on p95</b> (exit code 2).</p>"#,
            r.regressions.len(),
            r.threshold_pct
        )
    } else if !r.size_regressed && !r.correctness_failed {
        format!(
            r#"<p><b class="better">No regressions at/beyond the {}% threshold</b> (exit code 0).</p>"#,
            r.threshold_pct
        )
    } else {
        String::new()
    };
    out.push_str(&verdict);

    let t = &r.totals;
    let fmt_opt_pct = |p: Option<f64>| {
        p.map(|p| format!("{p:+.1}%"))
            .unwrap_or_else(|| "n/a".into())
    };
    let _ = write!(
        out,
        "<h2>Totals</h2>\n<table><tbody>\
<tr><th>QPS</th><td class=\"num\">{:.1}</td><td class=\"num\">{:.1}</td><td class=\"num\">{}</td></tr>\
<tr><th>wall clock</th><td class=\"num\">{:.2}s</td><td class=\"num\">{:.2}s</td><td class=\"num\">{}</td></tr>\
<tr><th>executed</th><td class=\"num\">{}</td><td class=\"num\">{}</td><td></td></tr>\
<tr><th>errors</th><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{:+}</td></tr>\
</tbody></table>\n",
        t.baseline_qps,
        t.candidate_qps,
        fmt_opt_pct(t.qps_delta_pct),
        t.baseline_wall_secs,
        t.candidate_wall_secs,
        fmt_opt_pct(t.wall_delta_pct),
        t.baseline_executed,
        t.candidate_executed,
        t.baseline_errors,
        t.candidate_errors,
        t.error_delta,
    );

    out.push_str("<h2>Run metadata</h2>\n<table><thead><tr><th></th><th>baseline</th><th>candidate</th></tr></thead><tbody>\n");
    meta_rows(&mut out, &r.baseline, &r.candidate);
    out.push_str("</tbody></table>\n");

    if let Some(note) = &r.settings_note {
        let _ = writeln!(
            out,
            "<h2>Target settings diff</h2>\n<p class=\"muted\">{}</p>",
            esc(note)
        );
    } else if !r.settings_diff.is_empty() {
        out.push_str("<h2>Target settings diff</h2>\n<table><thead><tr><th>variable</th><th>baseline</th><th>candidate</th></tr></thead><tbody>\n");
        for d in &r.settings_diff {
            let show = |v: &Option<String>| {
                v.as_deref()
                    .map(esc)
                    .unwrap_or_else(|| "<i>absent</i>".to_string())
            };
            let _ = writeln!(
                out,
                "<tr class=\"differs\"><th>{}</th><td>{}</td><td>{}</td></tr>",
                esc(&d.name),
                show(&d.baseline),
                show(&d.candidate)
            );
        }
        out.push_str("</tbody></table>\n");
    }

    if let Some(corr) = &r.correctness {
        let _ = write!(
            out,
            "<h2>Result correctness (--checksum): {} checked, {} matched, {} mismatched, {} advisory</h2>\n<p class=\"muted\">{}</p>\n",
            corr.checked,
            corr.matched,
            corr.mismatches.len(),
            corr.advisory.len(),
            esc(&corr.note),
        );
        checksum_table(
            &mut out,
            "Mismatches (deterministic — wrong answers)",
            &corr.mismatches,
            true,
        );
        checksum_table(
            &mut out,
            "Advisory (nondeterministic or unequal event populations)",
            &corr.advisory,
            false,
        );
    }

    if let Some(note) = &r.size_note {
        let _ = writeln!(
            out,
            "<h2>Result-size decades</h2>\n<p class=\"muted\">{}</p>",
            esc(note)
        );
    } else {
        let _ = write!(
            out,
            "<h2>Result-size decade regressions ({n}; {checked} decade pair(s) checked)</h2>\n\
<p class=\"muted\">Per-decade p95 regressions inside fingerprints the fingerprint-level \
verdict did not flag — regressions that only affect one result-size class and would \
otherwise be averaged away by the mixed-size percentiles.</p>\n",
            n = r.size_regressions.len(),
            checked = r.size_buckets_checked,
        );
        size_bucket_rows(&mut out, &r.size_regressions);
    }

    let matched = r.regressions.len() + r.improvements.len() + r.stable.len() + r.low_sample.len();
    let _ = write!(
        out,
        "<h2>Matched fingerprints ({matched}: {} regressed, {} improved, {} within threshold, {} low-sample)</h2>\n\
<p class=\"muted\">Sorted by worst p95 regression; click a column header to re-sort. Low-sample rows (count &lt; {} in either run) are excluded from the regression verdict.</p>\n",
        r.regressions.len(),
        r.improvements.len(),
        r.stable.len(),
        r.low_sample.len(),
        r.min_count,
    );
    out.push_str(
        "<table class=\"sortable\"><thead><tr>\
<th>class</th><th>fingerprint</th><th>count b</th><th>count c</th>\
<th>p95 b (ms)</th><th>p95 c (ms)</th><th>Δp95</th>\
<th>p50 b (ms)</th><th>p50 c (ms)</th><th>Δp50</th>\
<th>p99 b (ms)</th><th>p99 c (ms)</th><th>Δp99</th>\
<th>mean b (ms)</th><th>mean c (ms)</th><th>Δmean</th>\
<th>res/q b</th><th>res/q c</th><th>Δres</th>\
<th>errs b</th><th>errs c</th></tr></thead><tbody>\n",
    );
    fp_rows(&mut out, &r.regressions, "regressed");
    fp_rows(&mut out, &r.improvements, "improved");
    fp_rows(&mut out, &r.stable, "stable");
    fp_rows(&mut out, &r.low_sample, "low-sample");
    out.push_str("</tbody></table>\n");

    only_in_table(&mut out, "Only in baseline", &r.only_in_baseline);
    only_in_table(&mut out, "Only in candidate", &r.only_in_candidate);

    out.push_str(
        r#"<script>
document.querySelectorAll("table.sortable").forEach(function (t) {
  var ths = t.querySelectorAll("th");
  ths.forEach(function (th, i) {
    th.addEventListener("click", function () {
      var dir = th.dataset.dir === "desc" ? "asc" : "desc";
      ths.forEach(function (h) { delete h.dataset.dir; });
      th.dataset.dir = dir;
      var tb = t.tBodies[0];
      var rows = Array.prototype.slice.call(tb.rows);
      rows.sort(function (a, b) {
        var av = a.cells[i].dataset.v !== undefined ? a.cells[i].dataset.v : a.cells[i].textContent;
        var bv = b.cells[i].dataset.v !== undefined ? b.cells[i].dataset.v : b.cells[i].textContent;
        var an = parseFloat(av), bn = parseFloat(bv);
        var c = (isNaN(an) || isNaN(bn)) ? String(av).localeCompare(String(bv)) : an - bn;
        return dir === "asc" ? c : -c;
      });
      rows.forEach(function (rw) { tb.appendChild(rw); });
    });
  });
});
</script>
</body>
</html>
"#,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(
            esc(r#"SELECT * FROM t WHERE a < ? AND b > "x" & c = '<script>'"#),
            "SELECT * FROM t WHERE a &lt; ? AND b &gt; &quot;x&quot; &amp; c = &#39;&lt;script&gt;&#39;"
        );
    }
}
