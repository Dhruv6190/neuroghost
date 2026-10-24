"""Drift (D in the score): how far a new memory is from what this agent normally remembers.

The profile vector starts as the mean of the baseline persona statements and is
slowly updated with every memory that is committed to verified memory.
"""

from __future__ import annotations

import threading

import numpy as np


def _unit(v: np.ndarray) -> np.ndarray:
    n = float(np.linalg.norm(v))
    return v / n if n > 0 else v


class DriftProfile:
    def __init__(self, embedder, baseline_texts: list[str], learning_rate: float = 0.05):
        self.embedder = embedder
        self.learning_rate = learning_rate
        self._lock = threading.Lock()
        if baseline_texts:
            vecs = embedder.embed(baseline_texts)
            self._baseline_vectors = vecs
            self.vector = _unit(vecs.mean(axis=0))
        else:
            self._baseline_vectors = np.zeros((0, embedder.dimensions), dtype=np.float32)
            self.vector = np.zeros(embedder.dimensions, dtype=np.float32)

    def distance(self, vec: np.ndarray) -> float:
        """D = 1 - max(cosine to profile, cosine to closest baseline statement), clipped to [0, 1]."""
        with self._lock:
            if not np.any(self.vector):
                return 0.0
            sims = [float(np.dot(_unit(vec), self.vector))]
            if len(self._baseline_vectors):
                sims.append(float(np.max(self._baseline_vectors @ _unit(vec))))
        return float(np.clip(1.0 - max(sims), 0.0, 1.0))

    def absorb(self, vec: np.ndarray) -> None:
        """Move the profile a little toward a newly verified memory."""
        with self._lock:
            if not np.any(self.vector):
                self.vector = _unit(vec.astype(np.float32))
            else:
                self.vector = _unit((1 - self.learning_rate) * self.vector + self.learning_rate * _unit(vec))
