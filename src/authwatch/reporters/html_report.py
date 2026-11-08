"""Self-contained HTML report: summary, attack timeline and alert table.

No JavaScript and no external assets: the file opens offline (SOC networks are often
air-gapped) and can be attached to a ticket as-is. Every value that comes from the
logs is HTML-escaped - user names and host names in logs can be attacker-controlled,
and a report that renders them raw would itself be an XSS vector.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from html import escape
from pathlib import Path
from typing import TYPE_CHECKING

from authwatch import __version__
from authwatch.detectors._common import format_duration
from authwatch.models import Alert, AuthEvent, Severity

if TYPE_CHECKING:
    from authwatch.scan import ScanSummary

# Candidate bar widths for the timeline, in seconds.
BUCKET_SIZES = (1, 5, 10, 30, 60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600,
                86400, 7 * 86400)
MAX_BARS = 120
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _fmt_span(first: datetime, last: datetime) -> str:
    if first.date() == last.date():
        return f"{_fmt(first)} → {last:%H:%M:%S}"
    return f"{_fmt(first)} → {_fmt(last)}"


def _mitre_url(technique: str) -> str:
    main, _, sub = technique.partition(".")
    return f"https://attack.mitre.org/techniques/{main}/" + (f"{sub}/" if sub else "")


def choose_bucket(span: timedelta) -> int:
    """Smallest bar width (seconds) that keeps the timeline under MAX_BARS bars."""
    seconds = max(span.total_seconds(), 0.0)
    for size in BUCKET_SIZES:
        if seconds / size < MAX_BARS:
            return size
    return math.ceil(seconds / MAX_BARS)


def timeline_svg(events: Sequence[AuthEvent], alerts: Sequence[Alert]) -> str:
    """Stacked bars of failed/successful logons over time, alert windows shaded behind."""
    if not events:
        return '<p class="empty">No logon events to plot.</p>'

    start = min(e.timestamp for e in events)
    end = max(e.timestamp for e in events)
    bucket = choose_bucket(end - start)
    origin = _EPOCH + timedelta(
        seconds=math.floor((start - _EPOCH).total_seconds() / bucket) * bucket
    )

    def index(ts: datetime) -> int:
        return int((ts - origin).total_seconds() // bucket)

    n = index(end) + 1
    failed, succeeded = [0] * n, [0] * n
    for event in events:
        (succeeded if event.success else failed)[index(event.timestamp)] += 1
    peak = max(f + s for f, s in zip(failed, succeeded, strict=True)) or 1

    width, height = 1000, 260
    left, right, top, bottom = 44, 12, 14, 40
    plot_w, plot_h = width - left - right, height - top - bottom
    bar_w = plot_w / n
    base = top + plot_h

    def bar_h(value: int) -> float:
        return value / peak * plot_h

    out = [f'<svg class="timeline" viewBox="0 0 {width} {height}" role="img" '
           'aria-label="Failed and successful logons over time">']

    for alert in alerts:
        i1 = min(max(index(alert.first_seen), 0), n - 1)
        i2 = min(max(index(alert.last_seen), i1), n - 1)
        out.append(
            f'<rect class="band band-{alert.severity.label}" x="{left + i1 * bar_w:.1f}" '
            f'y="{top}" width="{(i2 - i1 + 1) * bar_w:.1f}" height="{plot_h}">'
            f"<title>{_e(alert.rule)} · {_e(alert.source)} · "
            f"{_e(_fmt_span(alert.first_seen, alert.last_seen))}</title></rect>"
        )

    gap = bar_w * 0.15 if bar_w > 4 else 0.0
    for i, (f, s) in enumerate(zip(failed, succeeded, strict=True)):
        if not f and not s:
            continue
        x, w = left + i * bar_w + gap / 2, max(bar_w - gap, 1.0)
        label = f"{_fmt(origin + timedelta(seconds=i * bucket))} UTC: {f} failed, {s} successful"
        out.append(f"<g><title>{_e(label)}</title>")
        if f:
            out.append(f'<rect class="bar-fail" x="{x:.1f}" y="{base - bar_h(f):.1f}" '
                       f'width="{w:.1f}" height="{bar_h(f):.1f}"/>')
        if s:
            out.append(f'<rect class="bar-ok" x="{x:.1f}" y="{base - bar_h(f) - bar_h(s):.1f}" '
                       f'width="{w:.1f}" height="{bar_h(s):.1f}"/>')
        out.append("</g>")

    out.append(f'<line class="axis" x1="{left}" y1="{base}" x2="{width - right}" y2="{base}"/>')
    out.append(f'<text class="tick" x="{left - 8}" y="{top + 10}" text-anchor="end">{peak}</text>')
    out.append(f'<text class="tick" x="{left - 8}" y="{base}" text-anchor="end">0</text>')

    multi_day = (end - start) >= timedelta(days=1)
    if bucket >= 86400:
        tick_fmt = "%Y-%m-%d"
    else:
        tick_fmt = ("%m-%d " if multi_day else "") + ("%H:%M:%S" if bucket < 60 else "%H:%M")
    ticks = min(6, n)
    for k in range(ticks):
        i = round(k * (n - 1) / (ticks - 1)) if ticks > 1 else 0
        anchor = "start" if k == 0 else ("end" if k == ticks - 1 else "middle")
        x = left + (i * bar_w if anchor == "start" else (i + 1) * bar_w if anchor == "end"
                    else (i + 0.5) * bar_w)
        tick = (origin + timedelta(seconds=i * bucket)).strftime(tick_fmt)
        out.append(f'<text class="tick" x="{x:.1f}" y="{base + 20}" '
                   f'text-anchor="{anchor}">{_e(tick)}</text>')
    out.append("</svg>")
    out.append(f'<p class="caption">Each bar = {_e(format_duration(timedelta(seconds=bucket)))}'
               " (UTC). Hover a bar or a shaded alert window for details.</p>")
    return "".join(out)


def _alert_rows(alerts: Sequence[Alert]) -> str:
    if not alerts:
        return '<p class="ok">No alerts.</p>'
    rows = []
    for alert in alerts:
        mitre = ", ".join(
            f'<a href="{_e(_mitre_url(t))}">{_e(t)}</a>' for t in alert.mitre
        )
        rows.append(
            f'<tr><td><span class="badge sev-{alert.severity.label}">'
            f"{_e(alert.severity.label.upper())}</span></td>"
            f"<td>{_e(alert.rule)}</td>"
            f'<td class="mono">{_e(alert.source)}</td>'
            f"<td>{_e(', '.join(alert.usernames))}</td>"
            f'<td class="num">{alert.count}</td>'
            f'<td class="mono">{_e(_fmt_span(alert.first_seen, alert.last_seen))}</td>'
            f"<td>{mitre}</td></tr>"
            f'<tr class="detail"><td></td><td colspan="6">{_e(alert.description)}</td></tr>'
        )
    return (
        '<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Rule</th>'
        "<th>Source</th><th>Account(s)</th><th class=\"num\">Attempts</th>"
        "<th>Time (UTC)</th><th>MITRE ATT&amp;CK</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def build_html(
    alerts: Sequence[Alert],
    summary: ScanSummary,
    events: Sequence[AuthEvent],
    generated_at: datetime | None = None,
) -> str:
    generated_at = generated_at or datetime.now(UTC)
    failed = sum(1 for e in events if not e.success)
    counts = Counter(a.severity for a in alerts)
    by_severity = " · ".join(
        f"{counts[s]} {s.label}" for s in sorted(Severity, reverse=True) if counts[s]
    ) or "none"

    warnings = []
    if summary.skipped_records or summary.skipped_chunks:
        warnings.append(f"Skipped {summary.skipped_records} corrupted record(s) and "
                        f"{summary.skipped_chunks} corrupted chunk(s).")
    if summary.auth_events == 0:
        warnings.append("No logon events found. Expected a Windows Security log or a "
                        "Linux SSH log (auth.log / secure).")
    warning_html = "".join(f'<p class="warning">{_e(w)}</p>' for w in warnings)

    time_range = (
        f"{_fmt(summary.first_event)} → {_fmt(summary.last_event)} UTC"
        if summary.first_event and summary.last_event else "–"
    )
    files = "".join(f"<li>{_e(f)}</li>" for f in summary.files)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>authwatch report</title>
<style>
:root {{
  --bg: #f6f8fa; --panel: #ffffff; --text: #1f2328; --muted: #59636e; --border: #d1d9e0;
  --fail: #cf222e; --ok: #1a7f37; --critical: #cf222e; --high: #bc4c00; --medium: #9a6700;
  --low: #0969da; --link: #0969da;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0d1117; --panel: #161b22; --text: #e6edf3; --muted: #8d96a0; --border: #30363d;
    --fail: #f85149; --ok: #3fb950; --critical: #f85149; --high: #db6d28; --medium: #d29922;
    --low: #58a6ff; --link: #58a6ff;
  }}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }}
main {{ max-width: 1100px; margin: 0 auto; padding: 32px 16px 48px; }}
h1 {{ margin: 0; font-size: 28px; }}
h2 {{ font-size: 18px; margin: 32px 0 12px; }}
.meta, .caption, footer {{ color: var(--muted); font-size: 13px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px; margin-top: 20px; }}
.card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px 14px; }}
.card .value {{ font-size: 22px; font-weight: 600; font-variant-numeric: tabular-nums; }}
.card .label {{ color: var(--muted); font-size: 13px; }}
.panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px; }}
.timeline {{ width: 100%; height: auto; display: block; }}
.bar-fail {{ fill: var(--fail); }} .bar-ok {{ fill: var(--ok); }}
.axis {{ stroke: var(--border); stroke-width: 1; }}
.tick {{ fill: var(--muted); font-size: 12px; font-family: ui-monospace, Consolas, monospace; }}
.band {{ opacity: 0.14; }}
.band-critical {{ fill: var(--critical); }} .band-high {{ fill: var(--high); }}
.band-medium {{ fill: var(--medium); }} .band-low {{ fill: var(--low); }}
.legend {{ display: flex; gap: 16px; flex-wrap: wrap; font-size: 13px; color: var(--muted);
  margin-top: 8px; }}
.legend span::before {{ content: ""; display: inline-block; width: 10px; height: 10px;
  border-radius: 2px; margin-right: 6px; vertical-align: -1px; }}
.legend .l-fail::before {{ background: var(--fail); }}
.legend .l-ok::before {{ background: var(--ok); }}
.legend .l-band::before {{ background: var(--critical); opacity: 0.25; }}
.table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
th, td {{ text-align: left; padding: 8px 10px; vertical-align: top; }}
th {{ font-size: 13px; color: var(--muted); border-bottom: 1px solid var(--border); }}
tr.detail td {{ color: var(--muted); font-size: 13px; padding-top: 0;
  border-bottom: 1px solid var(--border); }}
.mono {{ font-family: ui-monospace, Consolas, monospace; font-size: 13px; white-space: nowrap; }}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.badge {{ display: inline-block; padding: 1px 8px; border-radius: 999px; color: #fff;
  font-size: 12px; font-weight: 600; letter-spacing: .03em; }}
.sev-critical {{ background: var(--critical); }} .sev-high {{ background: var(--high); }}
.sev-medium {{ background: var(--medium); }} .sev-low {{ background: var(--low); }}
a {{ color: var(--link); }}
.warning {{ border-left: 3px solid var(--medium); padding: 6px 10px; background: var(--panel); }}
.ok {{ color: var(--ok); font-weight: 600; }}
.empty {{ color: var(--muted); }}
ul.files {{ margin: 4px 0 0; padding-left: 18px; }}
</style>
</head>
<body>
<main>
<header>
<h1>authwatch report</h1>
<p class="meta">{_e(time_range)}</p>
</header>
{warning_html}
<section class="cards">
<div class="card"><div class="value">{len(alerts)}</div><div class="label">alerts
 ({_e(by_severity)})</div></div>
<div class="card"><div class="value">{len(events)}</div><div class="label">logon events
 analysed</div></div>
<div class="card"><div class="value">{failed}</div><div class="label">failed</div></div>
<div class="card"><div class="value">{len(events) - failed}</div><div class="label">successful
</div></div>
<div class="card"><div class="value">{len(summary.files)}</div><div class="label">file(s)
 scanned</div></div>
</section>

<h2>Timeline</h2>
<div class="panel">
{timeline_svg(events, alerts)}
<div class="legend"><span class="l-fail">failed logons</span><span class="l-ok">successful
 logons</span><span class="l-band">alert window</span></div>
</div>

<h2>Alerts</h2>
{_alert_rows(alerts)}

<h2>Scanned files</h2>
<ul class="files">{files}</ul>

<footer>
<p>Generated by authwatch {_e(__version__)} on {_e(_fmt(generated_at))} UTC.
Noise (local, loopback and machine-account logons) is filtered out before analysis.</p>
</footer>
</main>
</body>
</html>
"""


def write_html(
    alerts: Sequence[Alert], summary: ScanSummary, events: Sequence[AuthEvent], path: Path
) -> None:
    Path(path).write_text(build_html(alerts, summary, events), encoding="utf-8")
