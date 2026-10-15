"""Resource files and runtime settings."""

from __future__ import annotations

import importlib.resources
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]
    official_domains: frozenset[str]


@dataclass(frozen=True)
class Resources:
    brands: tuple[Brand, ...]
    shorteners: frozenset[str]
    risky_tlds: frozenset[str]
    suspicious_keywords: tuple[str, ...]
    rule_weights: Mapping[str, int]
    rule_thresholds: tuple[int, int]


def resource_dir() -> Path:
    return Path(str(importlib.resources.files("phishguard") / "resources"))


def _read_lines(path: Path) -> list[str]:
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip().lower()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _read_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_resources(directory: Path | None = None) -> Resources:
    base = directory if directory is not None else resource_dir()

    brands = tuple(
        Brand(
            name=item["name"],
            keywords=tuple(str(k).lower() for k in item["keywords"]),
            official_domains=frozenset(str(d).lower() for d in item["official_domains"]),
        )
        for item in _read_yaml(base / "brands.yaml")["brands"]
    )

    rules = _read_yaml(base / "rules.yaml")
    weights = {str(k): int(v) for k, v in rules["weights"].items()}
    suspicious = int(rules["thresholds"]["suspicious"])
    dangerous = int(rules["thresholds"]["dangerous"])
    if suspicious >= dangerous:
        raise ValueError(
            f"thresholds must satisfy suspicious < dangerous (got {suspicious}, {dangerous})"
        )

    return Resources(
        brands=brands,
        shorteners=frozenset(_read_lines(base / "shorteners.txt")),
        risky_tlds=frozenset(_read_lines(base / "risky_tlds.txt")),
        suspicious_keywords=tuple(_read_lines(base / "suspicious_keywords.txt")),
        rule_weights=weights,
        rule_thresholds=(suspicious, dangerous),
    )


@dataclass(frozen=True)
class Settings:
    cache_path: Path
    model_path: Path
    psl_refresh: bool
    http_timeout: float = 5.0
    lookup_timeout: float = 8.0


def load_settings() -> Settings:
    cache = os.environ.get("PHISHGUARD_CACHE_PATH")
    model = os.environ.get("PHISHGUARD_MODEL_PATH")
    return Settings(
        cache_path=Path(cache) if cache else Path.cwd() / "cache.sqlite3",
        model_path=Path(model) if model else Path.cwd() / "models" / "model.joblib",
        psl_refresh=os.environ.get("PHISHGUARD_PSL_REFRESH") == "1",
    )
