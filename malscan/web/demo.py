"""Public, deploy-safe demo of malscan.

Unlike the full local dashboard (``web/app.py``), this variant is designed to be
exposed to the public internet:

- It NEVER accepts a filesystem path. Visitors upload a file; the bytes are
  scanned in memory and immediately discarded.
- It has NO quarantine, NO restore, NO delete - nothing reads from or writes to
  the server's filesystem.
- Upload size is capped to bound memory use.

This mirrors the ``create_demo_app()`` pattern already used by phishing-sim:
the real tool stays local, a neutered illustrative variant goes public.
"""

from __future__ import annotations

from flask import Flask, render_template, request

from .. import __version__
from ..scanner import Scanner

# Cap request bodies so a hostile upload can't exhaust container memory.
MAX_UPLOAD_BYTES = 8 * 1024 * 1024  # 8 MB


def create_demo_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    scanner = Scanner()

    def _render(results=None, error=None, status=200):
        return (
            render_template(
                "demo.html",
                version=__version__,
                engine_status=scanner.engine_status,
                max_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
                results=results,
                error=error,
            ),
            status,
        )

    @app.route("/")
    def index():
        return _render()

    @app.route("/scan", methods=["POST"])
    def scan():
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return _render(error="Please choose a file to scan.")
        # Read the upload fully into memory (bounded by MAX_CONTENT_LENGTH),
        # scan the bytes, and let them fall out of scope. Nothing hits disk.
        # iter_results also walks inside archives (zip/tar/gzip) in memory.
        data = uploaded.read()
        results = [r.to_dict() for r in scanner.iter_results(uploaded.filename, data)]
        return _render(results=results)

    @app.errorhandler(413)
    def too_large(_err):
        return _render(
            error=f"File too large. The demo accepts up to {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
            status=413,
        )

    @app.route("/health")
    def health():
        return {"status": "ok", "version": __version__}, 200

    return app


if __name__ == "__main__":
    create_demo_app().run(debug=True, port=5061)
