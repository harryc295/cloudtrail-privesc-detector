"""Renders findings to a static HTML timeline. Same no-framework approach as
iam-privesc-mapper: string.Template (stdlib) only, no server, no database.
"""
import os
from datetime import datetime, timezone
from html import escape
from string import Template

from .runbook_map import runbook_for

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {
    "Critical": "#b91c1c", "High": "#c2410c", "Medium": "#a16207", "Low": "#15803d", "Info": "#1d4ed8",
}

REPORT_TEMPLATE = Template("""<!doctype html>
<html><head><meta charset="utf-8"><title>CloudTrail Privesc Detector Report</title>
<style>
body { font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background:#0b1220; color:#e2e8f0; }
h1 { font-size: 1.4rem; }
.summary { display:flex; gap:1rem; margin: 1rem 0 2rem; }
.card { background:#111827; border-radius:8px; padding:1rem 1.5rem; border:1px solid #1f2937; min-width:6rem; }
.card .n { font-size:1.8rem; font-weight:700; }
table { width:100%; border-collapse: collapse; margin-top:1rem; }
th, td { text-align:left; padding:.5rem .75rem; border-bottom:1px solid #1f2937; font-size:.9rem; vertical-align:top; }
th { color:#94a3b8; text-transform:uppercase; font-size:.75rem; }
.sev { display:inline-block; padding:.15rem .6rem; border-radius:999px; font-size:.75rem; font-weight:600; color:#fff; white-space:nowrap; }
.evidence { color:#94a3b8; }
.time { color:#60a5fa; font-size:.8rem; white-space:nowrap; }
a { color:#60a5fa; text-decoration:none; }
</style></head>
<body>
<h1>CloudTrail Privilege-Escalation Detector — Report</h1>
<p>Window analysed: $window_note &mdash; generated $generated_at</p>
<div class="summary">$summary_cards</div>
<h2>Findings, oldest first ($finding_count)</h2>
<table>
<tr><th>Time</th><th>Severity</th><th>Event</th><th>Principal</th><th>Target</th><th>Evidence</th><th>Runbook</th></tr>
$rows
</table>
</body></html>""")

ROW_TEMPLATE = Template("""<tr>
<td class="time">$event_time</td>
<td><span class="sev" style="background:$color">$severity</span></td>
<td>$title</td>
<td>$principal</td>
<td>$target</td>
<td class="evidence">$evidence</td>
<td><a href="../$runbook">runbook</a></td>
</tr>""")


def generate_report(findings, window_note, out_dir="output") -> str:
    os.makedirs(out_dir, exist_ok=True)
    findings_sorted = sorted(findings, key=lambda f: (f["event_time"], SEVERITY_ORDER.get(f["severity"], 9)))

    counts: dict = {}
    for f in findings_sorted:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary_cards = "".join(
        f'<div class="card"><div class="n">{counts.get(sev, 0)}</div><div>{sev}</div></div>'
        for sev in ["Critical", "High", "Medium", "Low", "Info"] if counts.get(sev)
    )

    rows = []
    for f in findings_sorted:
        rows.append(ROW_TEMPLATE.substitute(
            event_time=escape(f["event_time"]),
            color=SEVERITY_COLOR.get(f["severity"], "#475569"),
            severity=escape(f["severity"]),
            title=escape(f["title"]),
            principal=escape(f["principal"]),
            target=escape(f["target"]),
            evidence=escape(f["evidence"]),
            runbook=escape(runbook_for(f["rule_id"])),
        ))

    html_out = REPORT_TEMPLATE.substitute(
        window_note=escape(window_note),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        summary_cards=summary_cards or '<div class="card"><div class="n">0</div><div>No findings</div></div>',
        finding_count=len(findings_sorted),
        rows="\n".join(rows) if rows else '<tr><td colspan="7">No findings.</td></tr>',
    )
    report_path = os.path.join(out_dir, "report.html")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    return report_path
