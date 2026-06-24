# Building malscan: what I learned writing a malware scanner from scratch

I set out to answer a question that sounds simple and isn't: *how does antivirus
actually work?* The fastest way I know to understand something is to build it, so
I built **[malscan](https://github.com/Kartik0219/malscan)** — a local, on-demand
malware scanner in Python. It started as a hash-matcher and grew into an
eight-engine detection stack with static analysis, machine learning, real-time
monitoring, and dynamic sandboxing.

This is a writeup of the decisions I'm proud of — and, just as importantly, the
ones where the honest answer was "you can't really do this as one person, and
here's why."

## The core idea: layered detection, one verdict

No single technique catches everything. Hashes catch *known* malware instantly but
miss anything new. Entropy catches packing but also flags legitimate installers.
YARA is powerful but only as good as its rules. So malscan runs several engines
over each file and takes the **highest severity** any of them reports as the
verdict:

```
clean < info < suspicious < malicious
```

Each engine is a small class with one method — `scan(path, data) -> [Finding]` —
registered in a list. Adding a new detection technique means writing one class.
That structure is the reason the project could grow from one engine to eight
without turning into spaghetti.

## The decision I think about most: inference should never condemn

Here's the rule that shaped everything: **only signatures raise `malicious`;
everything that *infers* maxes out at `suspicious`.**

A hash match or a YARA hit is evidence — this file *is* a known-bad thing. But
entropy, a suspicious import, an ML score, a file-type mismatch? Those are
*inferences*. They're often right, but a packed installer is high-entropy too. If
I let inference condemn files, malscan would quarantine legitimate software, and
the first time it deleted someone's real file, they'd uninstall it forever.

This isn't hypothetical. The 2024 CrowdStrike incident — a bad update that bricked
8.5 million Windows machines — is the industry's reminder that in security
software, **a false positive can be far more expensive than a false negative.**
Trust is the actual product. So malscan's heuristic, ML, and file-type engines
contribute *weight and context*, never a death sentence.

## Catching the tricks: file-type masquerading

One of my favorite engines is also one of the simplest. A classic delivery trick
is dressing an executable as something harmless — `invoice.pdf` that's really a
Windows `.exe`, or `photo.jpg.scr` relying on the OS hiding the final extension.

The bytes give it away: a real PDF starts with `%PDF`, a PE with `MZ`. So the
engine compares the *claimed* type (from the filename) against the *actual* type
(from the magic bytes) and flags the mismatch — mapping cleanly to MITRE ATT&CK
`T1036.008` (Masquerade File Type). It's maybe 80 lines, has near-zero false
positives, and catches a real, common technique. Good detection isn't always
complicated.

## Doing archives without getting owned

Malware loves to hide inside zips. But *extracting* untrusted archives to disk
invites two classic bugs: **zip-slip** (a member named `../../etc/passwd` escaping
the extraction dir) and **zip bombs** (a few KB that decompress to gigabytes).

malscan walks archives **entirely in memory** and never writes members to disk. A
member named `../../etc/passwd` becomes an inert *label* like
`bundle.zip!../../etc/passwd` — it can't traverse anything because nothing is ever
written. Decompression is bounded by explicit budgets: per-member size, total
bytes, member count, and nesting depth. Security tools are a juicy target; a
scanner that can be exploited by the thing it's scanning is worse than useless.

## Machine learning — done honestly

I added an ML engine because learned detection is how modern AV catches novel
samples. But I made a deliberate choice: **malscan ships the engine and the
training pipeline, not a pretrained "production" model.**

Why? Because I don't have the labeled corpus to train a model that actually
generalizes to real-world malware, and shipping a toy model dressed up as a real
detector would be dishonest. So the ML engine is opt-in and model-gated — exactly
like the VirusTotal integration needs your own API key. You train it on a real
dataset (like EMBER); the feature extractor and scoring interface are the same
shape a production gradient-boosting pipeline uses. It's a faithful, retrainable
foundation, and I say so plainly in the docs.

That honesty principle runs through the whole project. The local reputation cache
is labeled "one host, not a global telemetry network." The Linux on-access and
dynamic-sandbox features — which I couldn't fully test without a Linux/Docker box
— live on branches marked *experimental/unverified*, with the testable logic unit-
tested and the kernel paths clearly flagged. I'd rather ship something honest than
overclaim.

## Where the wall is (and why that's fine)

Building this taught me exactly where a solo project hits its ceiling — and it's
**not** the detection code. It's everything around it:

- **Telemetry.** Microsoft Defender treats a file seen once globally as suspicious
  because it has signals from a billion machines. You can't bootstrap a network
  effect. (malscan's reputation cache demonstrates the *mechanism* on one host —
  honestly scoped.)
- **Real-time blocking.** True on-access interception needs a kernel driver — a
  Linux fanotify responder, a Windows minifilter, the macOS Endpoint Security
  framework. I built the Linux fanotify path; a signed Windows minifilter is out
  of reach solo.
- **False-positive blast radius.** Pushing detection to millions of machines
  safely is a staged-rollout and QA discipline, not a feature.

"Best antivirus in the world" as a monolithic product is a data-and-trust game won
by trillion-dollar platforms. "Best in the world at *one focused thing*" is wide
open — and it's how every recent security company actually started.

## What I'd tell someone starting their own

- **Build the thing to understand the thing.** I learned more about AV in a few
  weeks of building than I had from any amount of reading.
- **Model your false positives as the expensive failure**, because in security
  they are.
- **Be honest about scope in the code and the README.** "This is a demonstration
  of the concept, not a global intelligence network" is a *stronger* signal than
  pretending otherwise — it shows you understand the real boundaries.

malscan is open source (and has 130+ tests, downloadable builds, and a live demo):
**<https://github.com/Kartik0219/malscan>**. If you're into detection engineering,
I'd love feedback.
