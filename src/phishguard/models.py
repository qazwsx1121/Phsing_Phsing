"""Core domain types shared by every PhishGuard component."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Literal

FEATURE_SCHEMA_VERSION: int = 1

FEATURE_NAMES: tuple[str, ...] = (
    "url_length", "host_length", "path_length", "num_subdomains",
    "num_dots_host", "num_hyphens_host", "num_digits_host", "is_ip_host",
    "has_userinfo", "has_punycode", "is_https", "has_nonstandard_port",
    "num_query_params", "num_suspicious_keywords", "brand_in_subdomain",
    "brand_in_path", "brand_in_domain_label", "is_shortener", "redirect_count",
    "is_private_suffix", "is_risky_tld", "host_entropy", "has_embedded_url",
    "domain_age_days", "domain_age_unknown",
)


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"

    @property
    def severity(self) -> int:
        return {Verdict.SAFE: 0, Verdict.SUSPICIOUS: 1, Verdict.DANGEROUS: 2}[self]

    @staticmethod
    def most_severe(*verdicts: Verdict) -> Verdict:
        return max(verdicts, key=lambda v: v.severity)


@dataclass(frozen=True)
class NormalizedURL:
    original: str
    normalized: str
    scheme: str
    userinfo: str
    host: str
    port: int | None
    path: str
    query: str
    was_refanged: bool
    scheme_added: bool


@dataclass(frozen=True)
class RedirectHop:
    url: str
    status_code: int


@dataclass(frozen=True)
class RedirectResult:
    final_url: str
    hops: tuple[RedirectHop, ...]
    is_shortener: bool
    complete: bool
    error: str | None

    @classmethod
    def not_followed(cls, url: str) -> RedirectResult:
        return cls(final_url=url, hops=(), is_shortener=False, complete=True, error=None)


@dataclass(frozen=True)
class URLParts:
    host: str
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str  # ICANN-based "domain.suffix", "" if none
    site_domain: str  # includes PSL private section, "" if none
    is_ip: bool
    is_private_suffix: bool


@dataclass(frozen=True)
class DomainInfo:
    domain: str
    creation_date: datetime | None
    age_days: float | None
    source: Literal["rdap", "whois", "snapshot", "none"]
    cached: bool
    error: str | None

    @classmethod
    def unknown(cls, domain: str, error: str | None = None) -> DomainInfo:
        return cls(
            domain=domain,
            creation_date=None,
            age_days=None,
            source="none",
            cached=False,
            error=error,
        )


@dataclass(frozen=True)
class FeatureVector:
    values: Mapping[str, float]  # keys == set(FEATURE_NAMES); missing -> math.nan
    evidence: Mapping[str, str]  # e.g. {"brand_in_subdomain": "네이버"}

    def __post_init__(self) -> None:
        keys = set(self.values)
        expected = set(FEATURE_NAMES)
        if keys != expected:
            missing = sorted(expected - keys)
            extra = sorted(keys - expected)
            raise ValueError(f"feature keys mismatch: missing={missing}, extra={extra}")

    def to_list(self) -> list[float]:
        return [self.values[name] for name in FEATURE_NAMES]


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    weight: int
    message: str


@dataclass(frozen=True)
class RuleResult:
    score: int
    verdict: Verdict
    hits: tuple[RuleHit, ...]


@dataclass(frozen=True)
class ModelResult:
    probability: float
    verdict: Verdict
    model_version: str


def _json_float(value: float | None) -> float | None:
    if value is None or math.isnan(value):
        return None
    return value


@dataclass(frozen=True)
class AnalysisResult:
    input_url: str
    normalized: NormalizedURL
    redirect: RedirectResult
    parts: URLParts
    domain: DomainInfo
    features: FeatureVector
    rule: RuleResult
    model: ModelResult | None
    warnings: tuple[str, ...]

    @property
    def final_verdict(self) -> Verdict:
        if self.model is None:
            return self.rule.verdict
        return Verdict.most_severe(self.rule.verdict, self.model.verdict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_url": self.input_url,
            "normalized_url": self.normalized.normalized,
            "final_url": self.redirect.final_url,
            "redirect": {
                "is_shortener": self.redirect.is_shortener,
                "complete": self.redirect.complete,
                "error": self.redirect.error,
                "hops": [
                    {"url": hop.url, "status_code": hop.status_code}
                    for hop in self.redirect.hops
                ],
            },
            "domain": {
                "host": self.parts.host,
                "registered_domain": self.parts.registered_domain,
                "subdomain": self.parts.subdomain,
                "suffix": self.parts.suffix,
                "is_ip": self.parts.is_ip,
                "creation_date": (
                    self.domain.creation_date.isoformat()
                    if self.domain.creation_date is not None
                    else None
                ),
                "age_days": _json_float(self.domain.age_days),
                "source": self.domain.source,
            },
            "features": {
                name: _json_float(self.features.values[name]) for name in FEATURE_NAMES
            },
            "rule": {
                "score": self.rule.score,
                "verdict": self.rule.verdict.value,
                "hits": [
                    {"rule_id": h.rule_id, "weight": h.weight, "message": h.message}
                    for h in self.rule.hits
                ],
            },
            "model": (
                None
                if self.model is None
                else {
                    "probability": _json_float(self.model.probability),
                    "verdict": self.model.verdict.value,
                    "model_version": self.model.model_version,
                }
            ),
            "final_verdict": self.final_verdict.value,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class LabeledURL:
    url: str
    label: int
    source: str
    collected_at: datetime | None
    domain_age_days: float | None
