"""Two separate memory stores: `verified` (agent can search) and `quarantine` (agent cannot).

Backends:
  * ChromaStore  - ChromaDB persistent client, cosine space (used when chromadb is installed)
  * LocalStore   - numpy + JSON files, no dependencies (fallback)

Only `PartitionedMemory.search_verified` is ever exposed to the agent's retrieval path.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from pathlib import Path
from typing import Any

import numpy as np

log = logging.getLogger("neuroghost.store")

VERIFIED = "verified_memory"
QUARANTINE = "quarantine_memory"


class LocalStore:
    name = "local"

    def __init__(self, path: Path | None):
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, dict[str, Any]]] = {VERIFIED: {}, QUARANTINE: {}}
        if path:
            path.mkdir(parents=True, exist_ok=True)
            for col in self._data:
                f = path / f"{col}.json"
                if f.exists():
                    self._data[col] = json.loads(f.read_text(encoding="utf-8"))

    def _save(self, collection: str) -> None:
        if self.path:
            tmp = self.path / f"{collection}.json.tmp"
            tmp.write_text(json.dumps(self._data[collection]), encoding="utf-8")
            tmp.replace(self.path / f"{collection}.json")

    def add(self, collection: str, item_id: str, text: str, embedding: np.ndarray, metadata: dict) -> None:
        with self._lock:
            self._data[collection][item_id] = {
                "text": text,
                "embedding": [float(x) for x in embedding],
                "metadata": metadata,
            }
            self._save(collection)

    def get(self, collection: str, item_id: str) -> dict | None:
        with self._lock:
            row = self._data[collection].get(item_id)
            if row is None:
                return None
            return {"id": item_id, "text": row["text"], "metadata": dict(row["metadata"]),
                    "embedding": np.asarray(row["embedding"], dtype=np.float32)}

    def delete(self, collection: str, item_id: str) -> bool:
        with self._lock:
            existed = self._data[collection].pop(item_id, None) is not None
            self._save(collection)
            return existed

    def count(self, collection: str) -> int:
        with self._lock:
            return len(self._data[collection])

    def ids(self, collection: str) -> list[str]:
        with self._lock:
            return list(self._data[collection].keys())

    def query(self, collection: str, embedding: np.ndarray, k: int) -> list[dict]:
        with self._lock:
            rows = list(self._data[collection].items())
        if not rows:
            return []
        mat = np.asarray([r["embedding"] for _, r in rows], dtype=np.float32)
        q = embedding / (np.linalg.norm(embedding) or 1.0)
        norms = np.linalg.norm(mat, axis=1)
        norms[norms == 0] = 1.0
        sims = (mat @ q) / norms
        order = np.argsort(-sims)[:k]
        return [{"id": rows[i][0], "text": rows[i][1]["text"], "metadata": dict(rows[i][1]["metadata"]),
                 "similarity": float(sims[i])} for i in order]

    # used only by tests to simulate an attacker writing straight into the database
    def raw_insert(self, collection: str, item_id: str, text: str, embedding: np.ndarray, metadata: dict) -> None:
        self.add(collection, item_id, text, embedding, metadata)


class ChromaStore:
    name = "chroma"

    def __init__(self, path: Path | None):
        import chromadb  # imported lazily

        if path:
            path.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(path=str(path))
            suffix = ""
        else:
            # In-memory Chroma clients share one database inside a Python process, so give
            # each NeuroGhost instance its own collection names to keep them fully separate.
            self.client = chromadb.EphemeralClient()
            suffix = "_" + uuid.uuid4().hex[:12]
        self._names = {VERIFIED: VERIFIED + suffix, QUARANTINE: QUARANTINE + suffix}
        self._cols = {
            logical: self.client.get_or_create_collection(real, metadata={"hnsw:space": "cosine"})
            for logical, real in self._names.items()
        }

    @staticmethod
    def _clean_meta(metadata: dict) -> dict:
        # Chroma accepts only str/int/float/bool values
        out = {}
        for k, v in metadata.items():
            out[k] = v if isinstance(v, (str, int, float, bool)) else json.dumps(v)
        return out

    def add(self, collection: str, item_id: str, text: str, embedding: np.ndarray, metadata: dict) -> None:
        self._cols[collection].upsert(ids=[item_id], documents=[text],
                                      embeddings=[[float(x) for x in embedding]],
                                      metadatas=[self._clean_meta(metadata)])

    def get(self, collection: str, item_id: str) -> dict | None:
        res = self._cols[collection].get(ids=[item_id], include=["documents", "metadatas", "embeddings"])
        if not res["ids"]:
            return None
        return {"id": item_id, "text": res["documents"][0], "metadata": dict(res["metadatas"][0] or {}),
                "embedding": np.asarray(res["embeddings"][0], dtype=np.float32)}

    def delete(self, collection: str, item_id: str) -> bool:
        existed = bool(self._cols[collection].get(ids=[item_id])["ids"])
        if existed:
            self._cols[collection].delete(ids=[item_id])
        return existed

    def count(self, collection: str) -> int:
        return int(self._cols[collection].count())

    def ids(self, collection: str) -> list[str]:
        return list(self._cols[collection].get()["ids"])

    def query(self, collection: str, embedding: np.ndarray, k: int) -> list[dict]:
        n = self.count(collection)
        if n == 0:
            return []
        res = self._cols[collection].query(query_embeddings=[[float(x) for x in embedding]],
                                           n_results=min(k, n), include=["documents", "metadatas", "distances"])
        return [{"id": res["ids"][0][i], "text": res["documents"][0][i], "metadata": dict(res["metadatas"][0][i] or {}),
                 "similarity": 1.0 - float(res["distances"][0][i])} for i in range(len(res["ids"][0]))]

    def raw_insert(self, collection: str, item_id: str, text: str, embedding: np.ndarray, metadata: dict) -> None:
        self.add(collection, item_id, text, embedding, metadata)


def build_store(backend: str, path: Path | None):
    backend = (backend or "auto").lower()
    if backend in ("auto", "chroma"):
        try:
            store = ChromaStore(path / "chroma" if path else None)
            log.info("Vector store: ChromaDB")
            return store
        except Exception as exc:
            if backend == "chroma":
                raise
            log.warning("ChromaDB unavailable (%s); using local store", exc)
    log.info("Vector store: local numpy store")
    return LocalStore(path / "local_store" if path else None)
