"""Command-line interface for malscan."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .models import Severity
from .quarantine import Quarantine
from .scanner import Scanner

# ANSI colors keyed by severity (disabled when output isn't a TTY).
_COLORS = {
    Severity.CLEAN: "\033[32m",       # green
    Severity.INFO: "\033[36m",        # cyan
    Severity.SUSPICIOUS: "\033[33m",  # yellow
    Severity.MALICIOUS: "\033[31m",   # red
}
_RESET = "\033[0m"


def _color(text: str, severity: Severity, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLORS[severity]}{text}{_RESET}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="malscan",
        description="Local on-demand malware scanner (hash + heuristics + YARA).",
    )
    p.add_argument("--version", action="version", version=f"malscan {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("target", help="file or directory to scan")
    scan.add_argument("--no-recursive", action="store_true", help="don't descend into subdirectories")
    scan.add_argument("--json", dest="json_out", metavar="FILE", help="write full JSON report to FILE")
    scan.add_argument("--html", dest="html_out", metavar="FILE", help="write a standalone HTML report to FILE")
    scan.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default="info",
        help="only print files at or above this severity (default: info)",
    )
    scan.add_argument(
        "--quarantine",
        action="store_true",
        help="move files with a 'malicious' verdict into the quarantine vault",
    )
    scan.add_argument(
        "--virustotal",
        action="store_true",
        help="look up each file's hash on VirusTotal (needs VT_API_KEY env var; "
             "sends only the hash, not the file; free tier is 4 lookups/min)",
    )
    scan.add_argument(
        "--no-archives",
        action="store_true",
        help="don't scan inside zip/tar/gzip archives (archive members are "
             "otherwise walked in memory under strict budgets)",
    )

    tri = sub.add_parser(
        "triage",
        help="scan a path, then have Claude explain the findings (needs ANTHROPIC_API_KEY)",
    )
    tri.add_argument("target", help="file or directory to scan and triage")
    tri.add_argument("--no-recursive", action="store_true", help="don't descend into subdirectories")
    tri.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default="suspicious",
        help="triage files at or above this severity (default: suspicious)",
    )
    tri.add_argument("--model", default="claude-opus-4-8", help="Claude model ID (default: claude-opus-4-8)")

    q = sub.add_parser("quarantine", help="manage the quarantine vault")
    qsub = q.add_subparsers(dest="qcommand", required=True)
    qsub.add_parser("list", help="list quarantined files")
    qr = qsub.add_parser("restore", help="restore a quarantined file")
    qr.add_argument("id", help="quarantine entry id")
    qr.add_argument("--to", dest="dest", help="restore to this path instead of the original")
    qd = qsub.add_parser("delete", help="permanently delete a quarantined file")
    qd.add_argument("id", help="quarantine entry id")
    return p


def _cmd_scan(args) -> int:
    use_color = sys.stdout.isatty()
    min_rank = Severity(args.min_severity).rank

    vt_key = None
    if args.virustotal:
        vt_key = os.environ.get("VT_API_KEY") or os.environ.get("MALSCAN_VT_API_KEY")
        if not vt_key:
            print("error: --virustotal requires the VT_API_KEY environment variable", file=sys.stderr)
            return 2

    scanner = Scanner(vt_api_key=vt_key, scan_archives=not args.no_archives)
    status = scanner.engine_status
    print(f"malscan {__version__} | engines: "
          + ", ".join(f"{k}={v}" for k, v in status.items()))
    print(f"scanning: {args.target}\n")

    quarantine = Quarantine() if args.quarantine else None
    start = time.time()
    results = []
    counts = {s: 0 for s in Severity}
    quarantined = 0

    for result in scanner.scan_path(args.target, recursive=not args.no_recursive):
        results.append(result)
        verdict = result.verdict
        counts[verdict] += 1

        if result.error:
            print(f"  [error] {result.path}: {result.error}")
            continue
        if verdict.rank >= min_rank:
            label = _color(verdict.value.upper(), verdict, use_color)
            print(f"  [{label}] {result.path}")
            for f in result.findings:
                print(f"           - ({f.engine}) {f.message}")

        if quarantine and verdict == Severity.MALICIOUS:
            # Archive members (composed "archive!member" names) aren't real
            # files on disk, so they can't be quarantined individually.
            if not Path(result.path).is_file():
                print("           -> inside archive; quarantine the container instead")
            else:
                try:
                    entry = quarantine.quarantine_file(
                        result.path,
                        verdict=verdict.value,
                        reasons=[f.message for f in result.findings],
                    )
                    quarantined += 1
                    print(f"           -> quarantined as {entry.id}")
                except OSError as exc:
                    print(f"           -> quarantine failed: {exc}")

    elapsed = time.time() - start
    print(f"\nscanned {len(results)} file(s) in {elapsed:.2f}s")
    summary = " | ".join(f"{s.value}: {counts[s]}" for s in Severity if counts[s])
    print("  " + (summary or "no findings"))
    if quarantined:
        print(f"  quarantined: {quarantined}")

    if args.json_out or args.html_out:
        report = {
            "tool": "malscan",
            "version": __version__,
            "target": args.target,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": round(elapsed, 3),
            "engine_status": status,
            "summary": {s.value: counts[s] for s in Severity},
            "results": [r.to_dict() for r in results],
        }
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"\nJSON report written to {args.json_out}")
        if args.html_out:
            from .report import render_html
            Path(args.html_out).write_text(render_html(report), encoding="utf-8")
            print(f"HTML report written to {args.html_out}")

    return 1 if counts[Severity.MALICIOUS] else 0


def _cmd_quarantine(args) -> int:
    q = Quarantine()
    if args.qcommand == "list":
        entries = q.list_entries()
        if not entries:
            print("quarantine vault is empty")
            return 0
        for e in entries:
            print(f"  {e.id}  [{e.verdict}]  {e.original_path}")
            print(f"           quarantined {e.quarantined_at}, sha256 {e.sha256[:16]}...")
        return 0
    if args.qcommand == "restore":
        try:
            dest = q.restore(args.id, args.dest)
        except KeyError as exc:
            print(f"error: {exc}")
            return 1
        print(f"restored to {dest}")
        return 0
    if args.qcommand == "delete":
        ok = q.delete(args.id)
        print("deleted" if ok else f"no such entry: {args.id}")
        return 0 if ok else 1
    return 1


def _cmd_triage(args) -> int:
    from .ai import triage as triage_mod

    min_rank = Severity(args.min_severity).rank
    scanner = Scanner()
    print(f"malscan {__version__} | scanning {args.target} for triage…\n")

    results = [
        r.to_dict()
        for r in scanner.scan_path(args.target, recursive=not args.no_recursive)
        if not r.error and r.verdict.rank >= min_rank
    ]
    if not results:
        print(f"Nothing at or above '{args.min_severity}' to triage.")
        return 0

    if not triage_mod.has_api_key():
        print("error: triage requires the ANTHROPIC_API_KEY environment variable", file=sys.stderr)
        return 2

    print(f"Triaging {len(results)} flagged file(s) with {args.model}…\n")
    try:
        client = triage_mod.make_client()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    triage_mod.triage_results(
        results, client=client, model=args.model,
        echo=lambda s: print(s, end="", flush=True),
    )
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "quarantine":
        return _cmd_quarantine(args)
    if args.command == "triage":
        return _cmd_triage(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
