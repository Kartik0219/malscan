"""PyInstaller entry script for the packaged, "both in one" malscan binary.

Double-click (no args) launches the dashboard; passing args runs the CLI.
See ``malscan/desktop.py`` for the dispatch logic.
"""

import sys

from malscan.desktop import main

if __name__ == "__main__":
    sys.exit(main())
