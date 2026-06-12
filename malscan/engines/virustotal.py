"""VirusTotal hash-lookup engine (opt-in, makes a network request).

Privacy by design: this sends only the file's SHA-256 **hash** to VirusTotal,
never the file's contents. If VT has analysed that hash before, it returns the
aggregated antivirus verdicts; if it hasn't, nothing about the file is disclosed.

Requires a free API key, read from the ``VT_API_KEY`` environment variable.
Disabled by default, and deliberately never enabled in the public web demo
(which would leak the key and burn the rate limit on strangers' uploads).

Uses only the standard library (urllib) so it adds no hard dependency.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request

from ..models import Finding, Severity

_API = "https://www.virustotal.com/api/v3/files/{}"

# VT free tier: 4 lookups/min, 500/day. Treat malicious consensus as high signal,
# but require a few engines before calling something outright malicious (a single
# no-name engine flagging a file is frequently a false positive).
_MALICIOUS_THRESHOLD = 3


class VirusTotalEngine:
    name = "virustotal"

    def __init__(self, api_key: str, timeout: float = 15.0):
        self._key = api_key
        self._timeout = timeout

    def scan(self, name: str, data: bytes) -> list[Finding]:
        sha256 = hashlib.sha256(data).hexdigest()
        req = urllib.request.Request(_API.format(sha256), headers={"x-apikey": self._key})

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "ignore"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return []  # VT has never seen this file — reveals nothing
            if exc.code == 401:
                return [Finding(self.name, Severity.INFO, "VirusTotal auth failed (check VT_API_KEY)")]
            if exc.code == 429:
                return [Finding(self.name, Severity.INFO, "VirusTotal rate limit reached (free tier: 4/min)")]
            return [Finding(self.name, Severity.INFO, f"VirusTotal HTTP {exc.code}")]
        except (urllib.error.URLError, TimeoutError) as exc:
            return [Finding(self.name, Severity.INFO, f"VirusTotal unreachable: {exc}")]
        except ValueError:
            return [Finding(self.name, Severity.INFO, "VirusTotal: could not parse response")]

        stats = (
            payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        )
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) if stats else 0
        detail = {"malicious": malicious, "suspicious": suspicious, "total": total}

        if malicious >= _MALICIOUS_THRESHOLD:
            severity = Severity.MALICIOUS
        elif malicious >= 1 or suspicious >= 1:
            severity = Severity.SUSPICIOUS
        else:
            return [
                Finding(
                    self.name, Severity.INFO,
                    f"VirusTotal: known file, 0/{total} engines flagged it", detail,
                )
            ]

        return [
            Finding(
                self.name, severity,
                f"VirusTotal: {malicious} malicious / {suspicious} suspicious of {total} engines",
                detail,
            )
        ]
