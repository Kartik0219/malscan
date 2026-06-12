"""WSGI entrypoint for production deployment (Railway/gunicorn).

Serves the PUBLIC, deploy-safe demo app (upload-based, no filesystem access,
no quarantine) - never the full local dashboard.
"""

from malscan.web.demo import create_demo_app

app = create_demo_app()
