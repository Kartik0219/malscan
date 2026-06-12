"""Tests for Claude-powered triage. No network: the Anthropic client is faked."""

from __future__ import annotations

from malscan.ai import triage


def _results():
    return [
        {"path": "C:/Users/secret/clean.txt", "size": 10, "sha256": "a" * 64,
         "findings": [], "error": None, "verdict": "clean"},
        {"path": "C:/Users/secret/evil.exe", "size": 2048, "sha256": "b" * 64,
         "findings": [{"engine": "hash", "severity": "malicious",
                       "message": "Matches known-bad hash: EICAR-Test-File", "detail": {}}],
         "error": None, "verdict": "malicious"},
    ]


# --- build_prompt ---------------------------------------------------------

def test_prompt_omits_clean_files():
    prompt = triage.build_prompt(_results())
    assert "evil.exe" in prompt
    assert "clean.txt" not in prompt


def test_prompt_includes_metadata():
    prompt = triage.build_prompt(_results())
    assert "malicious" in prompt
    assert "Matches known-bad hash" in prompt
    assert "b" * 64 in prompt  # the hash


def test_prompt_basenames_paths_no_directory_leak():
    prompt = triage.build_prompt(_results())
    # The sensitive directory must not appear — only the basename.
    assert "secret" not in prompt
    assert "C:/Users" not in prompt


def test_prompt_empty_when_all_clean():
    clean_only = [r for r in _results() if r["verdict"] == "clean"]
    assert triage.build_prompt(clean_only) == ""


# --- triage_results (faked client) ---------------------------------------

class _FakeStream:
    def __init__(self, chunks):
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    @property
    def text_stream(self):
        return iter(self._chunks)


class _FakeMessages:
    def __init__(self, capture):
        self.capture = capture

    def stream(self, **kwargs):
        self.capture.update(kwargs)
        return _FakeStream(["This is the ", "EICAR test file — harmless."])


class _FakeClient:
    def __init__(self):
        self.capture: dict = {}
        self.messages = _FakeMessages(self.capture)


def test_triage_streams_and_returns_text():
    client = _FakeClient()
    out = triage.triage_results(_results(), client=client)
    assert out == "This is the EICAR test file — harmless."


def test_triage_uses_opus_and_adaptive_thinking():
    client = _FakeClient()
    triage.triage_results(_results(), client=client)
    assert client.capture["model"] == "claude-opus-4-8"
    assert client.capture["thinking"] == {"type": "adaptive"}
    assert client.capture["system"]  # a system prompt was sent


def test_triage_sends_metadata_only_no_paths():
    client = _FakeClient()
    triage.triage_results(_results(), client=client)
    sent = client.capture["messages"][0]["content"]
    assert "evil.exe" in sent
    assert "secret" not in sent  # no leaked directory


def test_triage_noop_when_nothing_flagged():
    client = _FakeClient()
    clean_only = [{"path": "ok.txt", "size": 1, "sha256": "c" * 64,
                   "findings": [], "error": None, "verdict": "clean"}]
    out = triage.triage_results(clean_only, client=client)
    assert out == ""
    assert client.capture == {}  # client never called
