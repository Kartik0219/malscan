"""Claude-powered triage of scan findings.

Turns malscan's structured findings into an analyst-grade, plain-English
explanation with recommended next steps. **Privacy by design:** only scan
*metadata* is sent to Claude — verdicts, engine findings, rule names, entropy
scores, hashes, and the file's basename. The file's *contents* are never sent.

Uses the official Anthropic SDK with adaptive thinking and streaming. The
`anthropic` package is an optional dependency; importing it is deferred so the
core scanner runs without it.
"""

from __future__ import annotations

import os
from typing import Any

# Defaults follow the Claude API skill guidance: latest Opus + adaptive thinking.
DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_MAX_TOKENS = 4000

SYSTEM_PROMPT = (
    "You are a senior malware analyst helping triage results from 'malscan', a "
    "local on-demand scanner. You are given ONLY scan metadata — verdicts, engine "
    "findings, YARA rule names, entropy scores, hashes, and filenames — never the "
    "file contents themselves. For each flagged file, explain in plain English what "
    "the detection most likely indicates, how much confidence is warranted, and the "
    "recommended next steps for an analyst. Explicitly flag likely false positives "
    "(e.g. EICAR is a harmless industry test file; high entropy alone is not proof "
    "of malware; a single low-reputation hit may be noise). Be concise and practical, "
    "and never claim capabilities you cannot infer from the provided metadata."
)


def _basename(path: str) -> str:
    """Last path component only — avoids leaking full filesystem paths to the API.

    Works for archive-member names too: ``os.path.basename`` splits on the OS
    separator, leaving composed ``archive.zip!member`` labels intact.
    """
    return os.path.basename(path) or path


def build_prompt(results: list[dict[str, Any]]) -> str:
    """Render a metadata-only prompt from FileResult dicts (clean files omitted).

    Returns an empty string if nothing is worth triaging.
    """
    flagged = [r for r in results if r.get("verdict") not in (None, "clean")]
    if not flagged:
        return ""

    lines = [
        "Triage the following malscan findings. These are scanner metadata only — "
        "no file contents are included.\n",
    ]
    for r in flagged:
        lines.append(f"File: {_basename(str(r.get('path', '')))}")
        lines.append(f"  Verdict: {r.get('verdict', 'unknown')}")
        if r.get("sha256"):
            lines.append(f"  SHA-256: {r['sha256']}")
        if r.get("size") is not None:
            lines.append(f"  Size: {r['size']} bytes")
        findings = r.get("findings") or []
        if findings:
            lines.append("  Findings:")
            for f in findings:
                lines.append(f"    - [{f.get('engine', '?')}] {f.get('message', '')}")
        if r.get("error"):
            lines.append(f"  Scan error: {r['error']}")
        lines.append("")

    lines.append(
        "For each file, give: (1) what the detection most likely means, "
        "(2) confidence and false-positive risk, (3) concrete next steps."
    )
    return "\n".join(lines)


def make_client():
    """Construct an Anthropic client, deferring the optional import.

    Reads ANTHROPIC_API_KEY from the environment (the SDK's default). Raises a
    clear RuntimeError if the package isn't installed.
    """
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise RuntimeError(
            "the 'anthropic' package is required for triage: pip install anthropic"
        ) from exc
    return anthropic.Anthropic()


def has_api_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def triage_results(
    results: list[dict[str, Any]],
    *,
    client,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    echo=None,
) -> str:
    """Stream a triage explanation from Claude. Returns the full text.

    `client` is injected (an `anthropic.Anthropic`) so this stays unit-testable
    without network access. `echo` is an optional callable for live output
    (e.g. ``lambda s: print(s, end="", flush=True)``).
    """
    prompt = build_prompt(results)
    if not prompt:
        return ""

    parts: list[str] = []
    with client.messages.stream(
        model=model,
        max_tokens=max_tokens,
        thinking={"type": "adaptive"},
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        for text in stream.text_stream:
            if echo is not None:
                echo(text)
            parts.append(text)
    return "".join(parts)
