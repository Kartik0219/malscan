"""Flask dashboard: scan a path, view verdicts, manage the quarantine vault."""

from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for

from .. import __version__, attack
from .._paths import resource_root
from ..models import Severity
from ..quarantine import Quarantine
from ..scanner import Scanner

# Cap in-memory uploads (the drag & drop / browse scan) so a huge file can't
# exhaust memory. The path/folder scan below is unaffected by this limit.
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_UPLOAD_MB = MAX_UPLOAD_BYTES // (1024 * 1024)


def create_app(vault_dir: Path | None = None) -> Flask:
    template_folder = "templates"  # Flask's default, relative to this module
    if getattr(sys, "frozen", False):
        # In a PyInstaller bundle, templates are unpacked under sys._MEIPASS.
        template_folder = str(resource_root() / "malscan" / "web" / "templates")
    app = Flask(__name__, template_folder=template_folder)
    app.secret_key = "malscan-local-dashboard"  # local-only UI; not security-sensitive
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.jinja_env.globals["attack_label"] = attack.label
    app.jinja_env.globals["attack_url"] = attack.url
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
            max_mb=MAX_UPLOAD_MB,
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
            max_mb=MAX_UPLOAD_MB,
            entries=quarantine.list_entries(),
        )

    @app.route("/scan-file", methods=["POST"])
    def scan_file():
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            flash("Please choose a file to scan.", "error")
            return redirect(url_for("index"))
        # Scan the uploaded bytes in memory (also walks into archives). Nothing is
        # written to disk, so the quarantine option doesn't apply to this mode.
        data = uploaded.read()
        results = list(scanner.iter_results(uploaded.filename, data))
        summary = {s.value: 0 for s in Severity}
        for r in results:
            summary[r.verdict.value] += 1
        return render_template(
            "index.html",
            version=__version__,
            engine_status=scanner.engine_status,
            results=[r.to_dict() for r in results],
            summary=summary,
            target=uploaded.filename,
            max_mb=MAX_UPLOAD_MB,
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

    @app.errorhandler(413)
    def too_large(_err):
        flash(
            f"That file is too large to scan in memory (limit {MAX_UPLOAD_MB} MB). "
            "For bigger files or whole folders, use the path scan above.",
            "error",
        )
        return (
            render_template(
                "index.html",
                version=__version__,
                engine_status=scanner.engine_status,
                results=None,
                summary=None,
                target="",
                max_mb=MAX_UPLOAD_MB,
                entries=quarantine.list_entries(),
            ),
            413,
        )

    return app


if __name__ == "__main__":
    create_app().run(debug=True, port=8080)
