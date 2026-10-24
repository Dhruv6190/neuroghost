"""Text embeddings for the drift check.

`auto` uses sentence-transformers (all-MiniLM-L6-v2) when installed, otherwise a
deterministic local hashing embedder so NeuroGhost still runs fully offline.
"""

from __future__ import annotations

import hashlib
import logging
import re

import numpy as np

log = logging.getLogger("neuroghost.embeddings")
TOKEN_RE = re.compile(r"[a-z0-9]+")


class HashingEmbedder:
    """Signed feature hashing over word unigrams and bigrams. No downloads, fully deterministic."""

    name = "hashing"

    def __init__(self, dimensions: int = 384):
        self.dimensions = dimensions

    def _index(self, feature: str) -> tuple[int, float]:
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "little")
        return value % self.dimensions, (1.0 if (value >> 63) & 1 else -1.0)

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dimensions), dtype=np.float32)
        for row, text in enumerate(texts):
            tokens = TOKEN_RE.findall(text.lower())
            features = tokens + [f"{a}_{b}" for a, b in zip(tokens, tokens[1:])]
            for feat in features:
                idx, sign = self._index(feat)
                out[row, idx] += sign
            norm = np.linalg.norm(out[row])
            if norm > 0:
                out[row] /= norm
        return out


_MODEL_CACHE: dict[str, object] = {}


def _load_model(model_name: str):
    """Load each model once per process (tests and demos create many NeuroGhost objects)."""
    if model_name not in _MODEL_CACHE:
        from sentence_transformers import SentenceTransformer  # imported lazily

        _MODEL_CACHE[model_name] = SentenceTransformer(model_name)
    return _MODEL_CACHE[model_name]


class SentenceTransformerEmbedder:
    name = "sentence-transformers"

    def __init__(self, model_name: str):
        self.model = _load_model(model_name)
        get_dim = getattr(self.model, "get_embedding_dimension", None) or self.model.get_sentence_embedding_dimension
        self.dimensions = int(get_dim())

    def embed(self, texts: list[str]) -> np.ndarray:
        vecs = self.model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
        return np.asarray(vecs, dtype=np.float32)


def build_embedder(backend: str, model_name: str, dimensions: int):
    backend = (backend or "auto").lower()
    if backend in ("auto", "sentence-transformers"):
        try:
            emb = SentenceTransformerEmbedder(model_name)
            log.info("Embeddings: sentence-transformers (%s)", model_name)
            return emb
        except Exception as exc:  # not installed, or model not downloaded
            if backend == "sentence-transformers":
                raise
            log.warning("sentence-transformers unavailable (%s); using local hashing embedder", exc)
    log.info("Embeddings: local hashing embedder (%d dims)", dimensions)
    return HashingEmbedder(dimensions)
