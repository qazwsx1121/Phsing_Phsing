import math

import pytest

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


@pytest.fixture
def sample_result() -> AnalysisResult:
    # Temporary inline construction; Task 3 replaces this with
    # phishguard.web.stub.make_sample_result().
    url = "http://naver.com.login-check.xyz/a"
    host = "naver.com.login-check.xyz"
    normalized = NormalizedURL(
        original=url,
        normalized=url,
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
        input_url=url,
        normalized=normalized,
        redirect=RedirectResult.not_followed(url),
        parts=parts,
        domain=DomainInfo.unknown("login-check.xyz"),
        features=FeatureVector(values=values, evidence={}),
        rule=rule,
        model=None,
        warnings=(),
    )
