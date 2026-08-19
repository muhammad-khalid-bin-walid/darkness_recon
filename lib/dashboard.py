from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path


def generate_dashboard(
    target: str, output_dir: str, findings: list[dict]
) -> str:
    """Generate a self-contained HTML dashboard and return its file path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    severity_counts: Counter[str] = Counter(f.get("severity", "info") for f in findings)
    phase_counts: Counter[str] = Counter(f.get("phase", "unknown") for f in findings)
    metrics = {
        "total": len(findings),
        "severity": dict(severity_counts),
        "phases": dict(phase_counts),
    }
    html_content = _generate_html(findings, metrics)
    dest = out / "dashboard.html"
    dest.write_text(html_content, encoding="utf-8")
    return str(dest)


def _generate_html(findings: list[dict], metrics: dict) -> str:
    chart_svg = _severity_chart_svg(findings)
    phase_html = _phase_table(findings)
    severity_rows = ""
    for sev, count in sorted(metrics["severity"].items()):
        severity_rows += f"<tr><td>{html.escape(sev)}</td><td>{count}</td></tr>\n"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="60">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DarkRecon Dashboard – {html.escape(metrics.get('target', ''))}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
h1{{color:#58a6ff;margin-bottom:1rem}}
h2{{color:#8b949e;margin:1.5rem 0 .75rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin-bottom:1rem}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:.5rem .75rem;border-bottom:1px solid #21262d;text-align:left}}
th{{color:#58a6ff;cursor:pointer}}
th:hover{{color:#79c0ff}}
.sev-critical{{color:#f85149}}.sev-high{{color:#d29922}}.sev-medium{{color:#58a6ff}}.sev-low{{color:#8b949e}}.sev-info{{color:#3fb950}}
</style>
</head>
<body>
<h1>DarkRecon Scan Dashboard</h1>
<p>Total findings: <strong>{metrics['total']}</strong></p>
<div class="card">
<h2>Severity Distribution</h2>
{chart_svg}
<table><tr><th>Severity</th><th>Count</th></tr>
{severity_rows}</table>
</div>
<div class="card">
<h2>Findings</h2>
{phase_html}
</div>
<script>
document.querySelectorAll('th[data-col]').forEach(th=>{{
  th.addEventListener('click',()=>{{
    const col=th.dataset.col,tbl=th.closest('table'),rows=[...tbl.querySelectorAll('tr:not(:first-child)')];
    const idx=[...th.parentNode.children].indexOf(th);
    rows.sort((a,b)=>a.children[idx].textContent.localeCompare(b.children[idx].textContent));
    rows.forEach(r=>tbl.appendChild(r));
  }});
}});
</script>
</body>
</html>"""


def _severity_chart_svg(findings: list[dict]) -> str:
    counts: Counter[str] = Counter(f.get("severity", "info") for f in findings)
    colors = {
        "critical": "#f85149",
        "high": "#d29922",
        "medium": "#58a6ff",
        "low": "#8b949e",
        "info": "#3fb950",
    }
    total = sum(counts.values()) or 1
    cx, cy, r = 80, 80, 70
    svg_parts = [
        f'<svg width="160" height="160" viewBox="0 0 160 160" xmlns="http://www.w3.org/2000/svg">'
    ]
    angle = 0.0
    for sev in ("critical", "high", "medium", "low", "info"):
        c = counts.get(sev, 0)
        if c == 0:
            continue
        sweep = 360 * c / total
        start_rad = angle
        end_rad = angle + sweep
        x1 = cx + r * __import__("math").cos(__import__("math").radians(start_rad - 90))
        y1 = cy + r * __import__("math").sin(__import__("math").radians(start_rad - 90))
        x2 = cx + r * __import__("math").cos(__import__("math").radians(end_rad - 90))
        y2 = cy + r * __import__("math").sin(__import__("math").radians(end_rad - 90))
        large = 1 if sweep > 180 else 0
        svg_parts.append(
            f'<path d="M{cx},{cy} L{x1:.2f},{y1:.2f} A{r},{r} 0 {large},1 {x2:.2f},{y2:.2f} Z" '
            f'fill="{colors.get(sev, "#8b949e")}" stroke="#0d1117" stroke-width="1"/>'
        )
        angle += sweep
    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


def _phase_table(findings: list[dict]) -> str:
    rows = ""
    for f in findings:
        sev = f.get("severity", "info")
        esc = html.escape
        rows += (
            f'<tr><td class="sev-{esc(sev)}">{esc(sev)}</td>'
            f"<td>{esc(f.get('phase', ''))}</td>"
            f"<td>{esc(f.get('title', ''))}</td>"
            f"<td>{esc(f.get('target', ''))}</td></tr>\n"
        )
    return (
        "<table>"
        '<tr><th data-col="0">Severity</th><th data-col="1">Phase</th>'
        '<th data-col="2">Title</th><th data-col="3">Target</th></tr>'
        f"{rows}</table>"
    )
