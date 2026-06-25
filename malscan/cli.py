"""Command-line interface for malscan."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__, attack
from .models import Severity
from .quarantine import Quarantine
from .scanner import DEFAULT_MAX_SIZE, Scanner
from ._paths import resource_root, user_data_root

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
    scan.add_argument("--sarif", dest="sarif_out", metavar="FILE",
                      help="write a SARIF 2.1.0 report (for GitHub code scanning) to FILE")
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
    scan.add_argument(
        "--ml",
        action="store_true",
        help="enable the ML classifier using the default model "
             "(signatures/ml_model.json); train one with `malscan ml-train`",
    )
    scan.add_argument(
        "--ml-model", dest="ml_model", metavar="FILE",
        help="enable the ML classifier using a specific model JSON file",
    )
    scan.add_argument(
        "--reputation", action="store_true",
        help="record file prevalence locally and flag never-before-seen executables",
    )
    scan.add_argument(
        "--reputation-db", dest="reputation_db", metavar="FILE",
        help="path to the reputation database (implies --reputation)",
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

    mon = sub.add_parser(
        "monitor",
        help="watch folder(s) and scan files in real time as they appear or change",
    )
    mon.add_argument("paths", nargs="+", help="folder(s) or file(s) to watch")
    mon.add_argument("--interval", type=float, default=1.0, help="seconds between polls (default: 1.0)")
    mon.add_argument("--no-recursive", action="store_true", help="don't watch subdirectories")
    mon.add_argument("--quarantine", action="store_true",
                     help="auto-isolate files with a 'malicious' verdict")
    mon.add_argument("--min-severity", choices=[s.value for s in Severity], default="suspicious",
                     help="only report files at or above this severity (default: suspicious)")
    mon.add_argument("--ml-model", dest="ml_model", metavar="FILE",
                     help="also score watched files with this ML model")
    mon.add_argument("--reputation", action="store_true",
                     help="record prevalence and flag never-before-seen executables")
    mon.add_argument("--scan-existing", action="store_true",
                     help="scan files already present at startup, not just new/changed ones")
    mon.add_argument("--backend", choices=["poll", "fanotify"], default="poll",
                     help="'poll' (default, cross-platform, react-after) or 'fanotify' "
                          "(Linux+root, real intercept-and-block before open)")
    mon.add_argument("--block-suspicious", action="store_true",
                     help="fanotify backend: also deny 'suspicious' verdicts, not just 'malicious'")

    mlt = sub.add_parser(
        "ml-train",
        help="train the ML classifier from labelled benign/ and malicious/ folders",
    )
    mlt.add_argument("--benign", required=True, metavar="DIR", help="folder of known-good files")
    mlt.add_argument("--malicious", required=True, metavar="DIR", help="folder of known-bad files")
    mlt.add_argument("-o", "--out", default="ml_model.json", metavar="FILE", help="output model path")
    mlt.add_argument("--epochs", type=int, default=400, help="training iterations (default: 400)")
    mlt.add_argument("--lr", type=float, default=0.1, help="learning rate (default: 0.1)")
    mlt.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE,
                     help="skip training files larger than this many bytes")

    rep = sub.add_parser("reputation", help="show local file-reputation cache statistics")
    rep.add_argument("--db", dest="reputation_db", metavar="FILE",
                     help="reputation database path (default: under the user data dir)")

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

    ml_model_path = None
    if args.ml_model or args.ml:
        ml_model_path = Path(args.ml_model) if args.ml_model else resource_root() / "signatures" / "ml_model.json"
        if not ml_model_path.is_file():
            print(f"error: ML model not found at {ml_model_path}\n"
                  "       train one with: malscan ml-train --benign <dir> --malicious <dir> -o "
                  f"{ml_model_path}", file=sys.stderr)
            return 2

    reputation_db = None
    if args.reputation_db or args.reputation:
        reputation_db = Path(args.reputation_db) if args.reputation_db else user_data_root() / "reputation.db"

    try:
        scanner = Scanner(
            vt_api_key=vt_key, scan_archives=not args.no_archives,
            ml_model_path=ml_model_path, reputation_db=reputation_db,
        )
    except (ValueError, OSError) as exc:
        print(f"error: could not load ML model: {exc}", file=sys.stderr)
        return 2
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
            if result.techniques:
                print("           ATT&CK: "
                      + ", ".join(attack.label(t) for t in result.techniques))

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

    if args.json_out or args.html_out or args.sarif_out:
        report = {
            "tool": "malscan",
            "version": __version__,
            "target": args.target,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": round(elapsed, 3),
            "engine_status": status,
            "summary": {s.value: counts[s] for s in Severity},
            "attack_techniques": attack.enrich(
                sorted({t for r in results for t in r.techniques})
            ),
            "results": [r.to_dict() for r in results],
        }
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"\nJSON report written to {args.json_out}")
        if args.html_out:
            from .report import render_html
            Path(args.html_out).write_text(render_html(report), encoding="utf-8")
            print(f"HTML report written to {args.html_out}")
        if args.sarif_out:
            from .sarif import render_sarif
            Path(args.sarif_out).write_text(render_sarif(report), encoding="utf-8")
            print(f"SARIF report written to {args.sarif_out}")

    return 1 if counts[Severity.MALICIOUS] else 0


def _run_fanotify(args, scanner, use_color) -> int:
    """Linux on-access backend: block malicious opens before they complete."""
    from .fanotify import FanotifyMonitor, FanotifyError, is_supported

    if not is_supported():
        print("error: the fanotify backend requires Linux with libc (and root to run).\n"
              "       use the default --backend poll on this platform.", file=sys.stderr)
        return 2

    monitor = FanotifyMonitor(scanner, block_suspicious=args.block_suspicious)
    print(f"malscan {__version__} | fanotify on-access (intercept-and-block)")
    print(f"watching mounts for: {', '.join(args.paths)}")
    print("blocking: malicious" + (" + suspicious" if args.block_suspicious else "")
          + " - press Ctrl-C to stop\n")

    def on_decision(path, allow):
        verb = "ALLOW" if allow else _color("DENY", Severity.MALICIOUS, use_color)
        if not allow:
            print(f"  [{verb}] {path}")

    try:
        monitor.run(args.paths, on_decision=on_decision)
    except FanotifyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _cmd_monitor(args) -> int:
    from .monitor import Monitor

    use_color = sys.stdout.isatty()
    min_rank = Severity(args.min_severity).rank

    ml_model_path = Path(args.ml_model) if args.ml_model else None
    if ml_model_path and not ml_model_path.is_file():
        print(f"error: ML model not found at {ml_model_path}", file=sys.stderr)
        return 2
    reputation_db = (user_data_root() / "reputation.db") if args.reputation else None
    try:
        scanner = Scanner(ml_model_path=ml_model_path, reputation_db=reputation_db)
    except (ValueError, OSError) as exc:
        print(f"error: could not load ML model: {exc}", file=sys.stderr)
        return 2

    if args.backend == "fanotify":
        return _run_fanotify(args, scanner, use_color)

    for p in args.paths:
        if not Path(p).exists():
            print(f"warning: path does not exist: {p}", file=sys.stderr)

    quarantine = Quarantine() if args.quarantine else None
    monitor = Monitor(
        scanner, args.paths,
        recursive=not args.no_recursive, quarantine=quarantine,
    )

    status = scanner.engine_status
    print(f"malscan {__version__} | engines: " + ", ".join(f"{k}={v}" for k, v in status.items()))
    print(f"monitoring (real-time): {', '.join(args.paths)}")
    print(f"poll interval: {args.interval}s | reporting: {args.min_severity}+"
          + (" | auto-quarantine: on" if quarantine else ""))

    counts = {"events": 0, "quarantined": 0}

    def report(event) -> None:
        result = event.result
        if result.error:
            return
        verdict = result.verdict
        if verdict.rank < min_rank:
            return
        counts["events"] += 1
        label = _color(verdict.value.upper(), verdict, use_color)
        print(f"  [{label}] {event.path}")
        for f in result.findings:
            print(f"           - ({f.engine}) {f.message}")
        if result.techniques:
            print("           ATT&CK: " + ", ".join(attack.label(t) for t in result.techniques))
        if event.quarantined:
            counts["quarantined"] += 1
            print(f"           -> quarantined as {event.quarantined}")

    if args.scan_existing:
        for p in args.paths:
            for result in scanner.scan_path(p, recursive=not args.no_recursive):
                from .monitor import MonitorEvent
                report(MonitorEvent(path=result.path, result=result))

    print("watching for changes - press Ctrl-C to stop\n")
    monitor.run(interval=args.interval, on_event=report)
    print(f"\nstopped. {counts['events']} flagged event(s)"
          + (f", {counts['quarantined']} quarantined" if counts["quarantined"] else ""))
    return 0


def _cmd_mltrain(args) -> int:
    from . import features, ml

    def _load_dir(folder: str, label: int) -> tuple[list, list]:
        root = Path(folder)
        if not root.is_dir():
            raise NotADirectoryError(folder)
        X, y = [], []
        for child in root.rglob("*"):
            if not child.is_file():
                continue
            try:
                data = child.read_bytes()
            except OSError:
                continue
            if len(data) > args.max_size:
                continue
            X.append(features.extract(data))
            y.append(label)
        return X, y

    try:
        bx, by = _load_dir(args.benign, 0)
        mx, my = _load_dir(args.malicious, 1)
    except NotADirectoryError as exc:
        print(f"error: not a directory: {exc}", file=sys.stderr)
        return 2

    X, y = bx + mx, by + my
    if not bx or not mx:
        print("error: need at least one file in each of --benign and --malicious",
              file=sys.stderr)
        return 2

    print(f"malscan {__version__} | training on {len(bx)} benign + {len(mx)} malicious sample(s)...")
    model = ml.fit(X, y, epochs=args.epochs, lr=args.lr, malscan_version=__version__)

    # Report training accuracy as a sanity check (not a generalisation estimate).
    correct = sum(1 for vec, label in zip(X, y) if model.predict(vec) == bool(label))
    model.save(args.out)
    print(f"training accuracy: {correct}/{len(X)} ({100 * correct / len(X):.1f}%)")
    print(f"model written to {args.out}")
    print("scan with it via:  malscan scan <target> --ml-model " + args.out)
    return 0


def _cmd_reputation(args) -> int:
    from .reputation import ReputationStore

    db_path = Path(args.reputation_db) if args.reputation_db else user_data_root() / "reputation.db"
    if not db_path.exists():
        print(f"no reputation cache yet at {db_path}\n"
              "build one by scanning with --reputation, e.g. "
              "malscan scan <target> --reputation")
        return 0
    store = ReputationStore(db_path)
    try:
        stats = store.stats()
    finally:
        store.close()
    print(f"reputation cache: {db_path}")
    print(f"  unique files:  {stats['total']}")
    print(f"  executables:   {stats['executables']}")
    if stats["most_seen"]:
        print("  most-seen hashes:")
        for row in stats["most_seen"]:
            print(f"    {row['sha256'][:16]}...  x{row['times_seen']}")
    return 0


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
    if args.command == "monitor":
        return _cmd_monitor(args)
    if args.command == "ml-train":
        return _cmd_mltrain(args)
    if args.command == "reputation":
        return _cmd_reputation(args)
    if args.command == "quarantine":
        return _cmd_quarantine(args)
    if args.command == "triage":
        return _cmd_triage(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
