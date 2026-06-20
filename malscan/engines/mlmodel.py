"""ML engine: score a file with a trained logistic-regression model.

This is the *learned* counterpart to the hand-written heuristic engine. Where the
heuristic engine encodes an analyst's rules ("high entropy + injection imports =
suspicious"), this engine lets those weights be *learned* from a labelled corpus,
which is how modern AV catches novel samples it has no signature for.

Like the VirusTotal engine, it is opt-in and only attached when a model is
supplied — a scan never loads a model implicitly. Being inference, not a
signature, it raises at most SUSPICIOUS (never MALICIOUS) and reports the model's
probability so a human can weigh it. Scoring is pure stdlib (see ``malscan.ml``),
so it works in the frozen binary with no ML runtime installed.
"""

from __future__ import annotations

from pathlib import Path

from .. import features
from ..ml import Model
from ..models import Finding, Severity


class MLEngine:
    name = "ml"

    def __init__(self, model: Model):
        self.model = model

    @classmethod
    def from_path(cls, path: str | Path) -> "MLEngine":
        """Load a model from JSON. Raises if the file is missing or incompatible."""
        return cls(Model.load(path))

    def scan(self, path: str, data: bytes) -> list[Finding]:
        if not data:
            return []
        prob = self.model.predict_proba(features.extract(data))
        if prob < self.model.threshold:
            return []
        return [
            Finding(
                engine=self.name,
                severity=Severity.SUSPICIOUS,
                message=f"ML model flags this file as likely malicious "
                        f"(probability {prob:.2f})",
                detail={"probability": round(prob, 4),
                        "threshold": self.model.threshold},
            )
        ]
