# malscan

A local, on-demand malware scanner. Combines four detection techniques into a
single verdict per file — entirely offline, no cloud APIs, no telemetry.

> **Scope note:** malscan is an *on-demand* scanner (you point it at files), not
> a real-time antivirus with kernel hooks. It's a focused, ClamAV-style tool —
> built to be genuinely useful and to demonstrate how detection engines work,
> not to replace Microsoft Defender.

## Detection engines

| Engine | Technique | Verdict it can raise |
|--------|-----------|----------------------|
| **hash** | SHA-256 / MD5 match against a blocklist | `malicious` |
| **heuristic** | Shannon entropy (packing/encryption detection) | `suspicious` |
| **heuristic** | PE header + suspicious-import analysis (`pefile`) | `suspicious` |
| **yara** | YARA rule matching (`yara-python`) | per-rule (`suspicious`/`malicious`) |

The hash and entropy engines are pure stdlib. `pefile` and `yara-python` are
optional — if they're not installed, those checks degrade gracefully and the
rest of the scan still runs.

## Install

```bash
pip install -r requirements.txt   # optional extras: pefile, yara-python
```

The core scanner runs with zero dependencies; the extras unlock PE and YARA.

## Usage

```bash
# Scan a single file
python -m malscan scan suspicious.exe

# Scan a directory (recursive by default), write JSON + HTML reports
python -m malscan scan ./downloads --json report.json --html report.html

# Only show suspicious-or-worse, non-recursive
python -m malscan scan ./downloads --no-recursive --min-severity suspicious
```

The HTML report is a single self-contained file (no external assets) you can
open in any browser or share — handy for attaching scan results to a ticket.

Exit code is `1` if anything `malicious` is found, else `0` — convenient for
CI pipelines and pre-commit hooks.

## Verdicts

Each file gets one verdict — the highest severity across all engine findings:

`clean` < `info` < `suspicious` < `malicious`

## How detection works

- **Hashes** catch *known* bad files instantly. The bundled blocklist seeds the
  SHA-256 of the [EICAR test file](https://www.eicar.org/) (a harmless industry
  test string, not real malware) so you can verify the scanner works.
- **Entropy** flags files whose byte distribution approaches randomness
  (≥ 7.2 bits/byte), a hallmark of packing or encryption. This is *signal, not
  proof* — legitimate installers are packed too, so it never condemns alone.
- **PE analysis** parses Windows executables for imports commonly abused for
  process injection and anti-debugging (`WriteProcessMemory`,
  `CreateRemoteThread`, `IsDebuggerPresent`, …).
- **YARA** runs pattern rules from `signatures/yara/`. Drop in curated rule
  feeds (e.g. [signature-base](https://github.com/Neo23x0/signature-base)) to
  expand coverage.

## Extending it

- **More hashes:** append `<sha256>  <label>` lines to
  `signatures/hash_blocklist.txt`.
- **More rules:** drop `.yar` files into `signatures/yara/`. Rule `meta` may set
  `severity = "suspicious"` to downgrade from the default `malicious`.

## Testing

```bash
python -m pytest
```

Tests use the EICAR string in-memory for hash detection. The on-disk scanner
tests deliberately use a synthetic blocklisted payload rather than writing real
EICAR to disk — on Windows the host antivirus quarantines EICAR before the test
can read it back.

## Quarantine

Isolate flagged files into a local vault. Stored blobs are XOR-obfuscated so
they can't execute and won't re-trip on-access AV; restore is byte-for-byte
lossless. Every entry keeps a JSON sidecar (original path, hash, verdict, time).

```bash
# Scan and auto-isolate anything malicious
python -m malscan scan ./downloads --quarantine

# Manage the vault
python -m malscan quarantine list
python -m malscan quarantine restore <id> [--to <path>]
python -m malscan quarantine delete <id>
```

## Web dashboard

A themed Flask UI to scan paths, view verdicts, and manage quarantine.

```bash
pip install flask
python serve.py        # http://127.0.0.1:5060
```

## VirusTotal lookup (optional)

Cross-reference each file against [VirusTotal's](https://www.virustotal.com)
aggregated antivirus verdicts. It's **opt-in** and **privacy-preserving**: only
the file's SHA-256 **hash** is sent, never its contents. If VT has never seen the
hash, nothing about your file is disclosed.

```bash
# Get a free API key at virustotal.com, then:
export VT_API_KEY=your_key_here          # PowerShell: $env:VT_API_KEY="your_key_here"
python -m malscan scan ./downloads --virustotal
```

Verdicts map from VT's engine consensus: ≥3 engines malicious → `malicious`,
1–2 → `suspicious`, known-but-clean → `info`, unknown → no finding. The free
tier allows 4 lookups/min, so this is best for scanning a handful of files.

> The VirusTotal engine is **never** enabled in the public web demo — it would
> leak the API key and exhaust the rate limit on visitors' uploads. It's
> CLI-only and off unless you pass `--virustotal` with a key present.

## Roadmap

- [x] Quarantine vault (isolate + restore flagged files)
- [x] Flask web dashboard (themed, Railway-deployable)
- [x] Optional VirusTotal hash lookups
- [x] HTML report output

## License

MIT
