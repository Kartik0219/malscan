"""Render scan results as a standalone, shareable HTML report.

The output is a single self-contained .html file (inline CSS, no JS, no local
assets) so it can be emailed or opened anywhere. All user-controlled strings —
file paths, finding messages — are HTML-escaped: a hostile filename like
``<script>...`` must never become live markup in the report.
"""

from __future__ import annotations

import html
import time

from . import attack

# Worst-first ordering so the most important rows sit at the top.
_SEV_ORDER = ["malicious", "suspicious", "info", "clean"]
_SEV_COLORS = {
    "clean": "#4caf72",
    "info": "#4aa3c7",
    "suspicious": "#e0a528",
    "malicious": "#e0483f",
}


def _sev_rank(verdict: str) -> int:
    return _SEV_ORDER.index(verdict) if verdict in _SEV_ORDER else len(_SEV_ORDER)


def _badge(sev: str) -> str:
    color = _SEV_COLORS.get(sev, "#8a8a8a")
    return f'<span class="badge" style="background:{color}22;color:{color}">{html.escape(sev)}</span>'


def _row(result: dict) -> str:
    verdict = result.get("verdict", "clean")
    parts: list[str] = []
    if result.get("error"):
        parts.append(f'<div class="err">error: {html.escape(str(result["error"]))}</div>')
    findings = result.get("findings") or []
    if findings:
        items = "".join(
            f'<li class="f-{html.escape(str(f.get("severity", "info")))}">'
            f'<span class="eng">{html.escape(str(f.get("engine", "")))}</span>'
            f'{html.escape(str(f.get("message", "")))}</li>'
            for f in findings
        )
        parts.append(f'<ul class="findings">{items}</ul>')
    techs = result.get("techniques") or []
    if techs:
        badges = "".join(
            f'<a class="attck" href="{html.escape(attack.url(t))}" '
            f'target="_blank" rel="noopener">{html.escape(attack.label(t))}</a>'
            for t in techs
        )
        parts.append(f'<div class="attcks">{badges}</div>')
    detail = "".join(parts)
    sha = result.get("sha256") or ""
    sha_disp = f"{html.escape(sha[:16])}…" if sha else "—"
    return (
        "<tr>"
        f"<td>{_badge(verdict)}</td>"
        f'<td><div class="path">{html.escape(str(result.get("path", "")))}</div>{detail}</td>'
        f'<td class="num">{int(result.get("size", 0)):,}</td>'
        f'<td class="hash">{sha_disp}</td>'
        "</tr>"
    )


def render_html(report: dict) -> str:
    results = sorted(
        report.get("results", []),
        key=lambda r: _sev_rank(r.get("verdict", "clean")),
    )
    summary = report.get("summary", {})
    summary_html = "".join(
        f'<span class="stat" style="color:{_SEV_COLORS[s]}">{s}: {summary.get(s, 0)}</span>'
        for s in _SEV_ORDER
        if summary.get(s)
    ) or '<span class="stat">no files scanned</span>'
    engines_html = "".join(
        f'<span class="chip">{html.escape(str(k))} <b>{html.escape(str(v))}</b></span>'
        for k, v in report.get("engine_status", {}).items()
    )
    rows_html = "".join(_row(r) for r in results) or (
        '<tr><td colspan="4" class="empty">No files scanned.</td></tr>'
    )
    generated = html.escape(str(report.get("generated_at") or time.strftime("%Y-%m-%d %H:%M:%S")))
    target = html.escape(str(report.get("target", "")))
    version = html.escape(str(report.get("version", "")))
    elapsed = report.get("elapsed_seconds", 0)
    count = len(results)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>malscan report — {target}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg:#2b2b2b; --surface:#323232; --card:#383838; --border:rgba(255,255,255,.08);
    --text:#f2f2f2; --muted:#8a8a8a; --orange:#ff6b35; --orange-lt:#ff8656; --radius:10px;
  }}
  body {{ font-family:'Inter',-apple-system,"Helvetica Neue",Arial,sans-serif; background:var(--bg);
    color:var(--text); -webkit-font-smoothing:antialiased; padding:2.5rem 1.5rem 4rem; max-width:1000px; margin:0 auto; line-height:1.5; }}
  h1 {{ font-size:1.7rem; font-weight:800; letter-spacing:-.02em; }}
  h1 span {{ color:var(--orange); }}
  .meta {{ color:var(--muted); font-size:.82rem; margin-top:.4rem; }}
  .meta code {{ font-family:ui-monospace,"Cascadia Code",monospace; color:var(--orange-lt); }}
  .engines {{ display:flex; gap:.5rem; flex-wrap:wrap; margin:.9rem 0 1.6rem; }}
  .chip {{ font-size:.72rem; font-weight:600; padding:.2rem .7rem; border-radius:999px; background:var(--card);
    border:1px solid var(--border); color:var(--muted); }}
  .chip b {{ color:var(--orange-lt); font-weight:700; }}
  .summary {{ display:flex; gap:.6rem; flex-wrap:wrap; margin-bottom:1.4rem; }}
  .stat {{ padding:.4rem .9rem; border-radius:8px; font-size:.84rem; font-weight:700; background:var(--card);
    border:1px solid var(--border); }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; background:var(--card);
    border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; }}
  th, td {{ text-align:left; padding:.6rem .8rem; border-bottom:1px solid var(--border); vertical-align:top; }}
  th {{ color:var(--muted); font-size:.72rem; text-transform:uppercase; letter-spacing:.05em; }}
  tr:last-child td {{ border-bottom:none; }}
  .num {{ text-align:right; font-variant-numeric:tabular-nums; color:var(--muted); white-space:nowrap; }}
  .hash {{ font-family:ui-monospace,monospace; font-size:.78rem; color:var(--muted); white-space:nowrap; }}
  .badge {{ display:inline-block; padding:.15rem .7rem; border-radius:999px; font-size:.74rem; font-weight:800;
    text-transform:uppercase; letter-spacing:.03em; }}
  .path {{ font-family:ui-monospace,monospace; font-size:.82rem; word-break:break-all; }}
  .findings {{ list-style:none; margin-top:.5rem; display:flex; flex-direction:column; gap:.35rem; }}
  .findings li {{ background:var(--surface); border-left:3px solid var(--border); padding:.4rem .7rem;
    border-radius:0 6px 6px 0; font-size:.8rem; color:var(--muted); }}
  .findings li.f-malicious {{ border-left-color:#e0483f; }}
  .findings li.f-suspicious {{ border-left-color:#e0a528; }}
  .findings li.f-info {{ border-left-color:#4aa3c7; }}
  .eng {{ color:var(--orange-lt); font-weight:700; font-size:.68rem; text-transform:uppercase;
    letter-spacing:.04em; margin-right:.5rem; }}
  .err {{ color:#ff8a82; font-size:.8rem; margin-top:.3rem; }}
  .attcks {{ margin-top:.5rem; display:flex; gap:.35rem; flex-wrap:wrap; }}
  .attck {{ font-size:.68rem; font-weight:700; text-decoration:none; padding:.12rem .5rem; border-radius:5px;
    background:rgba(255,107,53,.12); color:var(--orange-lt); border:1px solid rgba(255,107,53,.25); }}
  .attck:hover {{ border-color:var(--orange); }}
  .empty {{ color:var(--muted); text-align:center; padding:1.2rem; }}
  footer {{ color:#555; font-size:.74rem; margin-top:2rem; }}
</style>
</head>
<body>
  <h1>mal<span>scan</span> report</h1>
  <p class="meta">Target: <code>{target}</code> · {count} file(s) · {elapsed}s · generated {generated} · malscan v{version}</p>
  <div class="engines">{engines_html}</div>
  <div class="summary">{summary_html}</div>
  <table>
    <thead><tr><th>Verdict</th><th>File</th><th>Size</th><th>SHA-256</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
  <footer>Generated by malscan — an educational on-demand scanner. Verdicts are illustrative and may miss real-world threats.</footer>
</body>
</html>
"""
