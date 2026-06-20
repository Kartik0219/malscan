"""A tiny, dependency-free logistic-regression model for malware classification.

Inference is pure stdlib: a model is just per-feature standardisation stats plus a
weight vector and bias, so scoring a file is one dot product and a sigmoid. That
keeps the runtime classifier dependency-free (it works in the frozen binary) while
still being a genuine, trainable linear model rather than hand-tuned weights.

Training (``fit``) is plain batch gradient descent with L2 regularisation — small,
readable, and good enough for a baseline on a real labelled corpus (e.g. EMBER).
For serious work you would swap in gradient boosting, but the *interface* — extract
features, standardise, score — is exactly what production pipelines use.

The model serialises to JSON (``Model.to_dict`` / ``Model.load``) and carries its
own copy of ``FEATURE_NAMES`` so a stale model is detected rather than silently
mis-scored.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

from .features import FEATURE_NAMES

FORMAT = "malscan-logreg/v1"


def sigmoid(z: float) -> float:
    # Numerically stable logistic function.
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


@dataclass
class Model:
    feature_names: list[str]
    mean: list[float]
    std: list[float]
    weights: list[float]
    bias: float
    threshold: float = 0.5
    trained_on: dict | None = None
    malscan_version: str = ""

    def _check(self) -> None:
        if list(self.feature_names) != list(FEATURE_NAMES):
            raise ValueError(
                "model was trained on a different feature set than this build "
                "exposes — retrain it (see `malscan ml-train`)."
            )

    def predict_proba(self, raw_features: list[float]) -> float:
        """Probability in [0, 1] that ``raw_features`` is malicious."""
        self._check()
        z = self.bias
        for x, mu, sigma, w in zip(raw_features, self.mean, self.std, self.weights):
            std = sigma if sigma > 1e-9 else 1.0
            z += w * ((x - mu) / std)
        return sigmoid(z)

    def predict(self, raw_features: list[float]) -> bool:
        return self.predict_proba(raw_features) >= self.threshold

    # ── persistence ──
    def to_dict(self) -> dict:
        return {
            "format": FORMAT,
            "feature_names": list(self.feature_names),
            "mean": self.mean, "std": self.std,
            "weights": self.weights, "bias": self.bias,
            "threshold": self.threshold,
            "trained_on": self.trained_on or {},
            "malscan_version": self.malscan_version,
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def from_dict(cls, d: dict) -> "Model":
        if d.get("format") != FORMAT:
            raise ValueError(f"unrecognised model format: {d.get('format')!r}")
        return cls(
            feature_names=d["feature_names"],
            mean=d["mean"], std=d["std"],
            weights=d["weights"], bias=d["bias"],
            threshold=d.get("threshold", 0.5),
            trained_on=d.get("trained_on"),
            malscan_version=d.get("malscan_version", ""),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Model":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _standardise_columns(rows: list[list[float]]) -> tuple[list[float], list[float]]:
    """Per-column mean and (population) standard deviation."""
    n = len(rows)
    cols = len(rows[0])
    mean = [0.0] * cols
    for row in rows:
        for j, v in enumerate(row):
            mean[j] += v
    mean = [m / n for m in mean]
    std = [0.0] * cols
    for row in rows:
        for j, v in enumerate(row):
            std[j] += (v - mean[j]) ** 2
    std = [math.sqrt(s / n) for s in std]
    return mean, std


def fit(
    X: list[list[float]],
    y: list[int],
    *,
    epochs: int = 400,
    lr: float = 0.1,
    l2: float = 1e-3,
    threshold: float = 0.5,
    malscan_version: str = "",
) -> Model:
    """Train a logistic-regression model via batch gradient descent.

    ``X`` is a list of raw feature vectors (as produced by ``features.extract``),
    ``y`` the matching 0/1 labels (1 = malicious). Features are standardised using
    statistics learned here and stored in the model for inference-time reuse.
    """
    if not X or len(X) != len(y):
        raise ValueError("X must be non-empty and the same length as y")
    cols = len(X[0])
    mean, std = _standardise_columns(X)
    norm = [
        [(v - mean[j]) / (std[j] if std[j] > 1e-9 else 1.0) for j, v in enumerate(row)]
        for row in X
    ]

    weights = [0.0] * cols
    bias = 0.0
    n = len(norm)
    for _ in range(epochs):
        grad_w = [0.0] * cols
        grad_b = 0.0
        for row, label in zip(norm, y):
            pred = sigmoid(bias + sum(w * v for w, v in zip(weights, row)))
            err = pred - label
            for j, v in enumerate(row):
                grad_w[j] += err * v
            grad_b += err
        weights = [
            w - lr * (grad_w[j] / n + l2 * w) for j, w in enumerate(weights)
        ]
        bias -= lr * (grad_b / n)

    return Model(
        feature_names=list(FEATURE_NAMES),
        mean=mean, std=std, weights=weights, bias=bias,
        threshold=threshold,
        trained_on={"samples": n, "malicious": sum(y), "benign": n - sum(y)},
        malscan_version=malscan_version,
    )
