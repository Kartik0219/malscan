"""malscan - a local, on-demand malware scanner.

Combines hash blocklists, Shannon-entropy heuristics, PE structure analysis,
file-type masquerading detection, and YARA rule matching into a single verdict
per file. Detection logic is entirely local: no external API calls, no cloud
dependencies.
"""

__version__ = "0.6.0"
