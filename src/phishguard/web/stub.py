"""Stub analyzer used while the UI/API is built before the real business logic."""

import math

from phishguard.errors import InvalidURLError
from phishguard.models import (
    FEATURE_NAMES,
    AnalysisResult,
    DomainInfo,
    FeatureVector,
    NormalizedURL,
    RedirectResult,
    RuleHit,
    RuleResult,
    URLParts,
    Verdict,
)

_SAMPLE_URL = "http://naver.com.login-check.xyz/a"


def make_sample_result(raw_url: str = _SAMPLE_URL) -> AnalysisResult:
    host = "naver.com.login-check.xyz"
    normalized = NormalizedURL(
        original=raw_url,
        normalized=_SAMPLE_URL,
        scheme="http",
        userinfo="",
        host=host,
        port=None,
        path="/a",
        query="",
        was_refanged=False,
        scheme_added=False,
    )
    parts = URLParts(
        host=host,
        subdomain="naver.com",
        domain="login-check",
        suffix="xyz",
        registered_domain="login-check.xyz",
        site_domain="login-check.xyz",
        is_ip=False,
        is_private_suffix=False,
    )
    values = {name: 0.0 for name in FEATURE_NAMES}
    values["domain_age_days"] = math.nan
    values["domain_age_unknown"] = 1.0
    rule = RuleResult(
        45,
        Verdict.SUSPICIOUS,
        (RuleHit("R03", 35, "'네이버' 브랜드명이 실제 등록 도메인이 아닌 서브도메인에 있습니다"),),
    )
    return AnalysisResult(
        input_url=raw_url,
        normalized=normalized,
        redirect=RedirectResult.not_followed(_SAMPLE_URL),
        parts=parts,
        domain=DomainInfo.unknown("login-check.xyz"),
        features=FeatureVector(values=values, evidence={}),
        rule=rule,
        model=None,
        warnings=(),
    )


class StubAnalyzer:
    def analyze(self, raw_url: str) -> AnalysisResult:
        if raw_url.strip() == "invalid":
            raise InvalidURLError("올바른 URL 형식이 아닙니다.")
        return make_sample_result(raw_url)
