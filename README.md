# malscan

A local, on-demand malware scanner. Combines five detection techniques into a
single verdict per file — entirely offline, no cloud APIs, no telemetry.

**Live demo:** <https://malscan.onrender.com> — a safe, upload-only public build (the full local dashboard is CLI-only).

> **Scope note:** malscan is an *on-demand* scanner (you point it at files), not
> a real-time antivirus with kernel hooks. It's a focused, ClamAV-style tool —
> built to be genuinely useful and to demonstrate how detection engines work,
> not to replace Microsoft Defender.

## Quick start — download & run (step by step)

Two ways to get going. **Option A** is the fastest (no Python); **Option B** runs
from source with zero OS warnings.

### Option A — Download the app (no Python needed)

1. Open the [**Releases page**](https://github.com/Kartik0219/malscan/releases/latest).
2. Under **Assets**, download the file for your system:
   - **Windows:** `malscan-windows-x64.exe`
   - **macOS (Apple Silicon):** `malscan-macos-arm64`
3. Run it:
   - **Windows:** double-click the `.exe`. The first time, Windows SmartScreen may
     say *"Windows protected your PC"* → click **More info → Run anyway** (it's
     unsigned, not infected — see [the note below](#running-it-safely-no-smartscreen--gatekeeper-warnings)).
   - **macOS:** open Terminal in your Downloads folder and run
     `chmod +x malscan-macos-arm64 && ./malscan-macos-arm64`. If Gatekeeper blocks
     it, **right-click the file → Open** once to allow it.
4. A scan dashboard opens in your browser at **<http://127.0.0.1:8080>**. Or use it
   from a terminal as a command-line tool:
   ```bash
   # Windows
   malscan-windows-x64.exe scan "C:\Users\you\Downloads"
   # macOS
   ./malscan-macos-arm64 scan ~/Downloads
   ```

### Option B — Run from source (no warnings; needs Python 3)

1. Install **[Python 3](https://www.python.org/downloads/)** (tick *"Add Python to
   PATH"* on Windows).
2. Get the code — either with git, or as a ZIP:
   ```bash
   git clone https://github.com/Kartik0219/malscan.git
   cd malscan
   ```
   *(No git? On the repo page click **Code → Download ZIP**, then unzip it.)*
3. Start it:
   - **Windows:** double-click **`run_malscan.bat`** (it installs what it needs and
     opens the dashboard).
   - **macOS / Linux:**
     ```bash
     chmod +x run_malscan.sh
     ./run_malscan.sh
     ```
4. Open **<http://127.0.0.1:8080>** in your browser.

### Your first scan (command line)

```bash
# Scan a single file
python -m malscan scan suspicious.exe

# Scan your whole Downloads folder, show only suspicious-or-worse
python -m malscan scan ~/Downloads --min-severity suspicious
```

It prints a verdict per file (`clean` / `info` / `suspicious` / `malicious`) and
exits with code `1` if anything malicious is found. That's it — see the rest of
this README for reports, quarantine, real-time monitoring, and the other engines.

## Running it safely (no SmartScreen / Gatekeeper warnings)

malscan is pure Python, so the safest and warning-free way to run it is **from
source** — no unsigned `.exe`/binary for the OS to flag.

**Windows** — double-click **`run_malscan.bat`** (or run it in a terminal). It
installs dependencies and opens the dashboard at <http://127.0.0.1:8080>.

**macOS / Linux**:

```bash
chmod +x run_malscan.sh
./run_malscan.sh        # http://127.0.0.1:8080
```

Or manually on any platform:

```bash
pip install -r requirements.txt flask waitress
python serve.py         # http://127.0.0.1:8080
```

> **Why port 8080?** Earlier builds used port 5060, which browsers block as
> "unsafe" (it's the SIP/VoIP port) — you'd see `ERR_UNSAFE_PORT`. The dashboard
> now defaults to **8080**.

> **About the prebuilt binaries:** the `.exe`/app bundles in the Releases are
> *unsigned*, so Windows SmartScreen ("Windows protected your PC") and macOS
> Gatekeeper ("unidentified developer") will warn before they run. That's
> expected for any unsigned app — not a sign of infection. To clear it: on
> Windows click **More info → Run anyway**; on macOS **right-click → Open** (or
> `xattr -d com.apple.quarantine <app>`). Removing the warning entirely requires
> a paid code-signing certificate (Windows) and Apple notarization (macOS).
> Running from source as above avoids the warning completely.

## Detection engines

| Engine | Technique | Verdict it can raise |
|--------|-----------|----------------------|
| **hash** | SHA-256 / MD5 match against a blocklist | `malicious` |
| **heuristic** | Weighted static traits: whole-file & PE-section entropy + risky imports | `suspicious` |
| **filetype** | Magic-bytes vs. claimed extension mismatch + double-extension trick | `suspicious` |
| **logical** | Multi-condition signatures (ClamAV-`.ldb`-style boolean rules) | per-rule |
| **yara** | YARA rule matching (`yara-python`) | per-rule (`suspicious`/`malicious`) |
| **ml** *(opt-in)* | Trained logistic-regression model over byte/PE features | `suspicious` |
| **reputation** *(opt-in)* | Local prevalence cache — flags never-before-seen executables | `info` |
| **virustotal** | Opt-in hash lookup against VirusTotal's AV consensus | per-consensus |

The hash and heuristic engines are pure stdlib. `pefile` and `yara-python` are
optional — if they're not installed, those checks degrade gracefully and the
rest of the scan still runs. Files are also walked **inside archives** (see below).

### Heuristic scoring

The heuristic engine sums *weighted traits* into a risk score in `[0, 1]` and
only flags `suspicious` once the score crosses a threshold — a single risky
import won't condemn a file, but several together (or a packed PE section) will.
Compressed and media formats (zip, gzip, png, jpeg, …) are **exempt** from the
whole-file entropy check, since they're high-entropy by design; their contents
are inspected by the archive walker instead.

## Archive scanning

Files inside `.zip`, `.tar` (incl. `.tar.gz`/`.tar.xz`), and bare `.gz` streams
are scanned too — walked **in memory**, never extracted to disk. This means the
zip-slip class of bugs can't occur (a member named `../../etc/passwd` is just an
inert label), and decompression bombs are bounded by explicit budgets (per
member, total bytes, member count, and nesting depth). Member paths compose with
`!`, e.g. `bundle.zip!evil.exe`. Disable with `--no-archives`.

## Download (Windows & macOS)

Prebuilt binaries are on the [**Releases**](https://github.com/Kartik0219/malscan/releases) page — no Python required:

| Platform | File |
|----------|------|
| Windows 10/11 (x64) | `malscan-windows-x64.exe` |
| macOS (Apple Silicon) | `malscan-macos-arm64` |
| macOS (Intel) | `malscan-macos-x64` |

- **Double-click** to open the dashboard in your browser, **or** run it from a terminal as the CLI: `malscan-windows-x64.exe scan <file>`.
- The binaries are **unsigned**, so the OS shows a one-time warning:
  - **Windows:** SmartScreen → *More info* → *Run anyway*.
  - **macOS:** right-click → *Open* (or `xattr -d com.apple.quarantine ./malscan-macos-arm64 && chmod +x ./malscan-macos-arm64`).
- Some antivirus engines may flag a PyInstaller binary (ironic for a scanner) — it's a false positive; install from source below to avoid it.

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

### SARIF output (GitHub code scanning)

Write a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report so findings
surface as alerts in a repository's **Security** tab, alongside CodeQL:

```bash
python -m malscan scan ./artifacts --sarif malscan.sarif
```

Each finding becomes a SARIF `result` (severity maps to `error`/`warning`/`note`
with a GitHub `security-severity` band); MITRE ATT&CK IDs ride along in result
properties. Upload it from a workflow:

```yaml
- run: python -m malscan scan ./artifacts --sarif malscan.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: malscan.sarif
```

## Verdicts

Each file gets one verdict — the highest severity across all engine findings:

`clean` < `info` < `suspicious` < `malicious`

## How detection works

- **Hashes** catch *known* bad files instantly. The bundled blocklist seeds the
  SHA-256 of the [EICAR test file](https://www.eicar.org/) (a harmless industry
  test string, not real malware) so you can verify the scanner works.
- **Entropy** flags files whose byte distribution approaches randomness
  (≥ 7.5 bits/byte), a hallmark of packing or encryption. This is *signal, not
  proof* — legitimate installers are packed too, so it only contributes weight,
  never condemns alone, and compressed/media formats are exempt.
- **PE analysis** parses Windows executables for high-entropy (packed) sections
  and imports commonly abused for process injection and anti-debugging
  (`WriteProcessMemory`, `CreateRemoteThread`, `IsDebuggerPresent`, …).
- **File-type masquerading** compares a file's real magic bytes against the type
  its name claims — a `.pdf` or `.jpg` that is actually a PE/ELF/Mach-O
  executable, or a double extension like `invoice.pdf.exe`. Maps to MITRE
  `T1036.008` / `T1036.007`. Pure stdlib; near-zero false positives by design.
- **YARA** runs pattern rules from `signatures/yara/`. Drop in curated rule
  feeds (e.g. [signature-base](https://github.com/Neo23x0/signature-base)) to
  expand coverage.

## Extending it

- **More hashes:** append `<sha256>  <label>` lines to
  `signatures/hash_blocklist.txt`.
- **More rules:** drop `.yar` files into `signatures/yara/`. Rule `meta` may set
  `severity = "suspicious"` to downgrade from the default `malicious`.
- **Logical signatures:** add `.msig` rules under `signatures/logical/` (below).

### Logical signatures

A hash or single string is blunt; real engines combine several sub-patterns with
boolean logic. The `logical` engine brings ClamAV-`.ldb`-style multi-condition
rules to malscan. Each line of a `signatures/logical/*.msig` file is:

```
name ; severity ; techniques ; expression ; sub0 ; sub1 ; ...
```

`expression` is boolean over sub-signature indices (`&`, `|`, parentheses); each
`subN` is `str:LITERAL` or a hex pattern (`4d5a`, `??` = any byte, `*` = gap). For
example, a precise process-injection rule — any one import is benign, all three
together is not:

```
PE_Injection_Trio ; suspicious ; T1055 ; 0 & 1 & 2 & 3 ; 4d5a ; str:VirtualAllocEx ; str:WriteProcessMemory ; str:CreateRemoteThread
```

The boolean expression is parsed by a small recursive-descent evaluator (never
`eval`), so a malformed or hostile rule file is skipped, not executed.

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

## Real-time monitoring

Watch one or more folders and scan files **as they are created or modified** —
the on-access counterpart to the one-shot `scan` command, handy for a Downloads
folder or an upload directory:

```bash
# Watch a folder; report suspicious-or-worse, auto-isolate anything malicious
python -m malscan monitor ~/Downloads --quarantine

# Watch several paths, also scoring with an ML model, polling twice a second
python -m malscan monitor ./incoming ./uploads --ml-model ml_model.json --interval 0.5
```

A changed file is only scanned once it has **settled** (size and mtime stable
across two polls), so half-written downloads aren't scanned mid-flight. The
monitor reuses whatever engines you configure, and skips its own quarantine vault.

> **Scope, stated plainly:** this is *user-space monitor-and-react*, not
> *kernel-level intercept-and-block*. A production AV scans a file **before** the
> OS opens it and can deny the open — via Linux `fanotify` (`FAN_OPEN_PERM`), a
> Windows minifilter driver, or the macOS Endpoint Security framework. That is
> native kernel code and out of scope for a pure-Python tool; malscan reacts as
> soon as a file lands, which is the right model for a watched drop-folder.

## Web dashboard

A themed Flask UI to scan paths, view verdicts, and manage quarantine.

```bash
pip install flask
python serve.py        # http://127.0.0.1:8080
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

## Machine-learning classifier (optional)

Where the heuristic engine encodes an analyst's hand-written rules, the ML engine
*learns* the weights from a labelled corpus — the approach modern AV uses to catch
novel samples it has no signature for. It extracts a compact feature vector from
each file (whole-file entropy, byte-distribution stats, plus PE section/import
structure) and scores it with a logistic-regression model.

It is **opt-in and model-gated**, just like the VirusTotal engine: no model is
bundled, and a scan never loads one implicitly. You train it on your own labelled
data. **Inference is pure stdlib** (the model is a small JSON of weights), so a
trained model scores files even in the dependency-free frozen binary.

```bash
# 1. Train on two folders of known-good and known-bad files.
#    For a real model, point --malicious at a malware corpus such as a subset of
#    the EMBER dataset (https://github.com/elastic/ember); keep samples in a VM.
python -m malscan ml-train --benign ./clean --malicious ./malware -o ml_model.json

# 2. Scan with it.
python -m malscan scan ./downloads --ml-model ml_model.json
# or place it at signatures/ml_model.json and just pass --ml
```

Being inference rather than a signature, the ML engine raises at most `suspicious`
and reports the model's probability, so a human can weigh it. The bundled trainer
is a readable baseline (logistic regression via gradient descent); the feature
extractor and scoring interface are the same shape a production gradient-boosting
pipeline would use, so it's a faithful, retrainable starting point — not a
pretrained, production-grade detector.

## Local reputation cache (optional)

Commercial AV treats a file the world has never seen differently from one running
on millions of machines — rarity is signal ("block at first sight"). You can't
replicate a global telemetry network solo, but you *can* keep a **local**
prevalence record. With `--reputation`, malscan logs every scanned hash to a small
SQLite cache and raises an `info` finding the first time it sees an **executable**
on this host:

```bash
python -m malscan scan ./downloads --reputation     # record + flag unknowns
python -m malscan reputation                         # show cache statistics
```

It is **opt-in** and only writes when enabled, so the core and the public web demo
stay stateless. This is the honest, single-host slice of cloud reputation — the
*mechanism* (prevalence-based suspicion), scoped to what one machine can know.

## AI triage (optional)

Have Claude turn malscan's findings into a plain-English analyst writeup —
what each detection likely means, how much to trust it, and what to do next.

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...        # PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-..."
python -m malscan triage ./downloads       # triages suspicious-or-worse files
```

**Privacy by design** (same discipline as the VirusTotal engine): triage sends
only scan *metadata* — verdicts, engine findings, rule names, entropy scores,
hashes, and the file's basename. **The file's contents are never sent**, and
full filesystem paths are stripped to basenames before leaving your machine.
Uses the Anthropic SDK with `claude-opus-4-8` and adaptive thinking, streamed
to your terminal. Opt-in and CLI-only — never wired into the public web demo.

## Roadmap

- [x] Quarantine vault (isolate + restore flagged files)
- [x] Flask web dashboard (themed, Render-deployable)
- [x] Optional VirusTotal hash lookups
- [x] HTML report output
- [x] AI triage of findings (Claude)
- [x] MITRE ATT&CK technique tagging on findings (CLI, reports, dashboard)
- [x] File-type masquerading detection (magic-bytes vs. extension)
- [x] SARIF output for GitHub code scanning
- [x] ML classifier (trainable logistic-regression engine, stdlib inference)
- [x] Real-time folder monitoring (user-space on-access scanning)
- [x] Logical multi-condition signatures (ClamAV-`.ldb`-style boolean rules)
- [x] Local file-reputation cache (first-seen / prevalence flagging)

## License

MIT
