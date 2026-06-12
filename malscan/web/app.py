"""Flask dashboard: scan a path, view verdicts, manage the quarantine vault."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for

from .. import __version__
from ..models import Severity
from ..quarantine import Quarantine
from ..scanner import Scanner


def create_app(vault_dir: Path | None = None) -> Flask:
    app = Flask(__name__)
    app.secret_key = "malscan-local-dashboard"  # local-only UI; not security-sensitive
    scanner = Scanner()
    quarantine = Quarantine(vault_dir)

    @app.route("/")
    def index():
        return render_template(
            "index.html",
            version=__version__,
            engine_status=scanner.engine_status,
            results=None,
            summary=None,
            target="",
            entries=quarantine.list_entries(),
        )

    @app.route("/scan", methods=["POST"])
    def scan():
        target = (request.form.get("target") or "").strip()
        do_quarantine = bool(request.form.get("quarantine"))
        if not target:
            flash("Please enter a path to scan.", "error")
            return redirect(url_for("index"))
        if not Path(target).exists():
            flash(f"Path not found: {target}", "error")
            return redirect(url_for("index"))

        results = list(scanner.scan_path(target))
        summary = {s.value: 0 for s in Severity}
        for r in results:
            summary[r.verdict.value] += 1
            if do_quarantine and r.verdict == Severity.MALICIOUS and not r.error:
                try:
                    quarantine.quarantine_file(
                        r.path, verdict=r.verdict.value,
                        reasons=[f.message for f in r.findings],
                    )
                except OSError as exc:
                    flash(f"Quarantine failed for {r.path}: {exc}", "error")

        return render_template(
            "index.html",
            version=__version__,
            engine_status=scanner.engine_status,
            results=[r.to_dict() for r in results],
            summary=summary,
            target=target,
            entries=quarantine.list_entries(),
        )

    @app.route("/quarantine/restore/<entry_id>", methods=["POST"])
    def restore(entry_id: str):
        try:
            dest = quarantine.restore(entry_id)
            flash(f"Restored to {dest}", "ok")
        except KeyError:
            flash(f"No quarantine entry {entry_id}", "error")
        return redirect(url_for("index"))

    @app.route("/quarantine/delete/<entry_id>", methods=["POST"])
    def delete(entry_id: str):
        if quarantine.delete(entry_id):
            flash("Entry permanently deleted.", "ok")
        else:
            flash(f"No quarantine entry {entry_id}", "error")
        return redirect(url_for("index"))

    @app.route("/health")
    def health():
        return {"status": "ok", "version": __version__}, 200

    return app


if __name__ == "__main__":
    create_app().run(debug=True, port=5060)
