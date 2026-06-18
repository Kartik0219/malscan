"""Desktop entrypoint for the packaged malscan binary ("both in one").

- No arguments (e.g. a double-click) -> start the local web dashboard and open
  it in the default browser.
- Any arguments -> behave exactly like the ``malscan`` command-line interface
  (``malscan scan ...``, ``malscan quarantine ...``, etc.).

The explicit subcommands ``dashboard``/``gui``/``ui`` also force the dashboard.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
import webbrowser

# Avoid browser-blocked "unsafe" ports (5060 = SIP -> ERR_UNSAFE_PORT in
# Chrome/Edge/Firefox). 8080 is a safe, conventional local web port.
_DEFAULT_PORT = 8080


def _pick_port(preferred: int = _DEFAULT_PORT) -> int:
    """Return ``preferred`` if free, otherwise an OS-assigned free port."""
    for candidate in (preferred, 0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", candidate))
            return sock.getsockname()[1]
        except OSError:
            continue
        finally:
            sock.close()
    return preferred


def run_dashboard() -> int:
    from .web.app import create_app

    app = create_app()
    port = _pick_port()
    url = f"http://127.0.0.1:{port}"

    # Open the browser a moment after the server starts accepting connections
    # (set MALSCAN_NO_BROWSER=1 to run headless, e.g. as a plain local server).
    if not os.environ.get("MALSCAN_NO_BROWSER"):
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    print(f"\n  malscan dashboard running at  {url}")
    print("  Leave this window open while you use it; close it to quit.\n")

    try:
        from waitress import serve

        logging.getLogger("waitress").setLevel(logging.ERROR)
        serve(app, host="127.0.0.1", port=port, threads=4)
    except ImportError:
        # waitress isn't bundled -> fall back to Flask's built-in server.
        app.run(host="127.0.0.1", port=port)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"dashboard", "gui", "ui"}:
        return run_dashboard()
    from .cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
