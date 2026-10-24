"""Loads settings from config/settings.json, with environment overrides."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
DEFAULT_CONFIG_DIR = PROJECT_ROOT / "config"


@dataclass
class Settings:
    user_id: str
    baseline_persona: list[str]
    weights: dict[str, float]
    threshold: float
    trusted_threshold: float
    obfuscation_counts_as_directive: bool
    trusted_sources: set[str]
    embedding_backend: str
    embedding_model: str
    embedding_dimensions: int
    vector_backend: str
    data_dir: Path
    privileged_tools: set[str]
    money_tools: set[str]
    allowlist: dict[str, str]
    per_transaction_limit: float
    per_day_limit: float
    currency: str
    chain: dict[str, Any]
    directive_rules: dict[str, list[str]] = field(default_factory=dict)

    def copy_with(self, **changes: Any) -> "Settings":
        data = dict(self.__dict__)
        data.update(changes)
        return Settings(**data)


def _read_json(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_settings(config_dir: str | os.PathLike | None = None, data_dir: str | None = None) -> Settings:
    """Load settings.json and directive_rules.json from `config_dir`.

    Environment overrides:
      NEUROGHOST_CONFIG_DIR, NEUROGHOST_DATA_DIR,
      NEUROGHOST_EMBEDDING_BACKEND (auto|sentence-transformers|hashing),
      NEUROGHOST_VECTOR_BACKEND (auto|chroma|memory)
    """
    cdir = Path(config_dir or os.environ.get("NEUROGHOST_CONFIG_DIR") or DEFAULT_CONFIG_DIR)
    raw = _read_json(cdir / "settings.json")
    rules_path = cdir / "directive_rules.json"
    rules = _read_json(rules_path) if rules_path.exists() else {}
    rules = {k: v for k, v in rules.items() if not k.startswith("_")}

    scoring = raw.get("scoring", {})
    tools = raw.get("tools", {})
    tx = raw.get("transactions", {})
    emb = raw.get("embedding", {})

    ddir = Path(data_dir or os.environ.get("NEUROGHOST_DATA_DIR") or raw.get("data_dir", ".neuroghost"))
    if not ddir.is_absolute():
        ddir = Path.cwd() / ddir

    return Settings(
        user_id=raw.get("user_id", "user"),
        baseline_persona=list(raw.get("baseline_persona", [])),
        weights={"directive": 0.5, "drift": 0.3, "money": 0.2, **scoring.get("weights", {})},
        threshold=float(scoring.get("threshold", 0.55)),
        trusted_threshold=float(scoring.get("trusted_threshold", 0.85)),
        obfuscation_counts_as_directive=bool(scoring.get("obfuscation_counts_as_directive", True)),
        trusted_sources=set(raw.get("trusted_sources", ["user"])),
        embedding_backend=os.environ.get("NEUROGHOST_EMBEDDING_BACKEND", emb.get("backend", "auto")),
        embedding_model=emb.get("model", "sentence-transformers/all-MiniLM-L6-v2"),
        embedding_dimensions=int(emb.get("dimensions", 384)),
        vector_backend=os.environ.get("NEUROGHOST_VECTOR_BACKEND", raw.get("vector_store", {}).get("backend", "auto")),
        data_dir=ddir,
        privileged_tools=set(tools.get("privileged", [])),
        money_tools=set(tools.get("money", [])),
        allowlist={k.lower(): v for k, v in tx.get("allowlist", {}).items()},
        per_transaction_limit=float(tx.get("per_transaction_limit", 1.0)),
        per_day_limit=float(tx.get("per_day_limit", 2.0)),
        currency=tx.get("currency", "ETH"),
        chain=dict(raw.get("chain", {})),
        directive_rules=rules,
    )
