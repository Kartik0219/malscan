"""Logical (multi-condition) signatures — a small ClamAV-``.ldb``-style engine.

A plain hash or single string is a blunt instrument. Real engines combine
*several* sub-patterns with boolean logic: "this is a PE **and** it imports
``VirtualAllocEx`` **and** ``WriteProcessMemory``" is far more precise than any
one of those alone. This engine brings that idea to malscan.

Rule format (one rule per line in ``signatures/logical/*.msig``)::

    name ; severity ; techniques ; expression ; sub0 ; sub1 ; ...

* ``severity``   — clean|info|suspicious|malicious (default: malicious)
* ``techniques`` — comma-separated ATT&CK IDs (may be empty)
* ``expression`` — boolean over sub-signature indices, e.g. ``0 & 1``,
  ``(0 | 1) & 2``. Operators: ``&`` (and), ``|`` (or), parentheses.
* ``subN``       — either ``str:LITERAL`` (matched as raw bytes) or a hex
  pattern (``4d5a``) where ``??`` is any single byte and ``*`` is a gap.

Lines starting with ``#`` are comments. The boolean expression is parsed by a
tiny recursive-descent evaluator (never ``eval``), so a malformed or hostile rule
file can't execute code — a bad rule is skipped, not run.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?")


# ── Sub-signature compilation ──

def compile_pattern(text: str) -> re.Pattern[bytes]:
    """Compile one sub-signature (``str:...`` or hex) into a bytes regex.

    Hex supports ``??`` (any single byte) and ``*`` (variable-length gap).
    Raises ``ValueError`` on malformed input.
    """
    text = text.strip()
    if text.startswith("str:"):
        return re.compile(re.escape(text[4:].encode("utf-8", "surrogateescape")), re.DOTALL)

    hexes = text.replace(" ", "")
    if not hexes:
        raise ValueError("empty sub-signature")
    parts: list[bytes] = []
    i = 0
    while i < len(hexes):
        ch = hexes[i]
        if ch == "*":
            parts.append(b".*?")
            i += 1
            continue
        pair = hexes[i:i + 2]
        if len(pair) < 2:
            raise ValueError(f"dangling hex nibble in {text!r}")
        if pair == "??":
            parts.append(b".")
        else:
            try:
                parts.append(re.escape(bytes([int(pair, 16)])))
            except ValueError as exc:
                raise ValueError(f"bad hex {pair!r} in {text!r}") from exc
        i += 2
    return re.compile(b"".join(parts), re.DOTALL)


# ── Boolean expression: tokenise -> AST -> evaluate (no eval) ──

def parse_expression(expr: str, n_subsigs: int):
    """Parse a boolean expression over subsig indices into an AST tuple.

    Grammar: expr := term ('|' term)* ; term := factor ('&' factor)* ;
    factor := INT | '(' expr ')'. Raises ``ValueError`` on bad syntax or an
    index outside ``range(n_subsigs)``.
    """
    tokens = re.findall(r"\d+|[&|()]", expr)
    if not tokens:
        raise ValueError(f"empty expression: {expr!r}")
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def advance():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or():
        node = parse_and()
        while peek() == "|":
            advance()
            node = ("or", node, parse_and())
        return node

    def parse_and():
        node = parse_factor()
        while peek() == "&":
            advance()
            node = ("and", node, parse_factor())
        return node

    def parse_factor():
        tok = peek()
        if tok == "(":
            advance()
            node = parse_or()
            if peek() != ")":
                raise ValueError(f"unbalanced parentheses in {expr!r}")
            advance()
            return node
        if tok is not None and tok.isdigit():
            advance()
            idx = int(tok)
            if not 0 <= idx < n_subsigs:
                raise ValueError(f"subsig index {idx} out of range in {expr!r}")
            return ("lit", idx)
        raise ValueError(f"unexpected token {tok!r} in {expr!r}")

    ast = parse_or()
    if pos != len(tokens):
        raise ValueError(f"trailing tokens in {expr!r}")
    return ast


def evaluate(ast, matches: list[bool]) -> bool:
    """Evaluate a parsed expression AST against per-subsig match booleans."""
    kind = ast[0]
    if kind == "lit":
        return matches[ast[1]]
    if kind == "and":
        return evaluate(ast[1], matches) and evaluate(ast[2], matches)
    if kind == "or":
        return evaluate(ast[1], matches) or evaluate(ast[2], matches)
    raise ValueError(f"bad AST node: {ast!r}")  # pragma: no cover


class _Rule:
    __slots__ = ("name", "severity", "techniques", "ast", "patterns")

    def __init__(self, name, severity, techniques, ast, patterns):
        self.name = name
        self.severity = severity
        self.techniques = techniques
        self.ast = ast
        self.patterns = patterns


def _parse_rule(line: str) -> _Rule:
    fields = [f.strip() for f in line.split(";")]
    if len(fields) < 5:
        raise ValueError("rule needs name;severity;techniques;expression;subsig...")
    name, sev_text, tech_text, expr = fields[0], fields[1], fields[2], fields[3]
    subsig_texts = [f for f in fields[4:] if f]
    if not name or not subsig_texts:
        raise ValueError("rule missing a name or sub-signatures")
    try:
        severity = Severity(sev_text) if sev_text else Severity.MALICIOUS
    except ValueError:
        severity = Severity.MALICIOUS
    patterns = [compile_pattern(s) for s in subsig_texts]
    ast = parse_expression(expr, len(patterns))
    techniques = _ATTACK_ID.findall(tech_text)
    return _Rule(name, severity, techniques, ast, patterns)


def load_rules(rules_dir: Path) -> tuple[list[_Rule], list[str]]:
    """Load every ``*.msig`` rule under ``rules_dir``; return (rules, errors)."""
    rules: list[_Rule] = []
    errors: list[str] = []
    for path in sorted(rules_dir.glob("*.msig")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rules.append(_parse_rule(line))
            except ValueError as exc:
                errors.append(f"{path.name}:{lineno}: {exc}")
    return rules, errors


class LogicalSignatureEngine:
    name = "logical"

    def __init__(self, rules_dir: Path):
        self._rules, self.errors = load_rules(rules_dir)

    @property
    def available(self) -> bool:
        return bool(self._rules)

    @property
    def status(self) -> str:
        if self._rules:
            return f"ready ({len(self._rules)} rules)"
        return "no rules"

    def scan(self, path: str, data: bytes) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            matches = [bool(p.search(data)) for p in rule.patterns]
            if evaluate(rule.ast, matches):
                findings.append(Finding(
                    engine=self.name,
                    severity=rule.severity,
                    message=f"Logical signature matched: {rule.name}",
                    detail={"rule": rule.name},
                    techniques=rule.techniques,
                ))
        return findings
