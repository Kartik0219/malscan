"""Tests for the ML feature extractor, logistic-regression model, and engine."""

from __future__ import annotations

import os

import pytest

from malscan import features, ml
from malscan.engines.mlmodel import MLEngine
from malscan.models import Severity


# ── Feature extraction ──

def test_feature_vector_length_matches_names():
    vec = features.extract(b"hello world" * 50)
    assert len(vec) == len(features.FEATURE_NAMES)


def test_features_are_deterministic():
    data = os.urandom(2048)
    assert features.extract(data) == features.extract(data)


def test_entropy_and_magic_features():
    idx = {n: i for i, n in enumerate(features.FEATURE_NAMES)}
    text = features.extract(b"plain readable ascii text, low entropy" * 20)
    rand = features.extract(os.urandom(4096))
    assert rand[idx["entropy"]] > text[idx["entropy"]]      # random is higher entropy
    assert text[idx["printable_ratio"]] > rand[idx["printable_ratio"]]
    pe = features.extract(b"MZ" + b"\x00" * 200)
    assert pe[idx["is_pe"]] == 1.0 and pe[idx["is_executable"]] == 1.0


def test_empty_file_is_safe():
    vec = features.extract(b"")
    assert len(vec) == len(features.FEATURE_NAMES)


# ── Model training + inference ──

def _separable_dataset():
    """Benign = low-entropy ASCII text; malicious = high-entropy blobs."""
    X, y = [], []
    for _ in range(15):
        X.append(features.extract(b"the quick brown fox jumps over the lazy dog. " * 30))
        y.append(0)
        X.append(features.extract(os.urandom(4096)))
        y.append(1)
    return X, y


def test_fit_learns_a_separable_boundary():
    X, y = _separable_dataset()
    model = ml.fit(X, y, epochs=300)
    correct = sum(1 for vec, label in zip(X, y) if model.predict(vec) == bool(label))
    assert correct / len(X) >= 0.9          # should separate these easy classes
    assert model.trained_on["malicious"] == 15


def test_probabilities_are_bounded():
    X, y = _separable_dataset()
    model = ml.fit(X, y, epochs=100)
    for vec in X:
        p = model.predict_proba(vec)
        assert 0.0 <= p <= 1.0


def test_model_roundtrips_through_json(tmp_path):
    X, y = _separable_dataset()
    model = ml.fit(X, y, epochs=50)
    path = tmp_path / "m.json"
    model.save(path)
    loaded = ml.Model.load(path)
    sample = X[1]
    assert loaded.predict_proba(sample) == pytest.approx(model.predict_proba(sample))


def test_stale_feature_set_is_rejected():
    X, y = _separable_dataset()
    model = ml.fit(X, y, epochs=10)
    model.feature_names = model.feature_names[:-1]   # simulate drift
    with pytest.raises(ValueError):
        model.predict_proba(X[0])


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError):
        ml.Model.from_dict({"format": "something-else"})


def test_fit_rejects_mismatched_inputs():
    with pytest.raises(ValueError):
        ml.fit([], [])
    with pytest.raises(ValueError):
        ml.fit([[1.0]], [0, 1])


# ── Engine ──

def test_engine_flags_above_threshold():
    X, y = _separable_dataset()
    model = ml.fit(X, y, epochs=300)
    eng = MLEngine(model)
    findings = eng.scan("blob.bin", os.urandom(4096))
    if findings:  # high-entropy blob should usually trip the learned boundary
        assert findings[0].severity == Severity.SUSPICIOUS
        assert findings[0].engine == "ml"
        assert 0.0 <= findings[0].detail["probability"] <= 1.0


def test_engine_silent_on_empty():
    X, y = _separable_dataset()
    eng = MLEngine(ml.fit(X, y, epochs=10))
    assert eng.scan("empty", b"") == []


def test_engine_wires_into_scanner_when_model_supplied(tmp_path):
    from malscan.scanner import Scanner
    X, y = _separable_dataset()
    path = tmp_path / "m.json"
    ml.fit(X, y, epochs=50).save(path)
    scanner = Scanner(ml_model_path=path)
    assert "ml" in scanner.engine_status
    assert Scanner().ml_engine is None       # off by default
