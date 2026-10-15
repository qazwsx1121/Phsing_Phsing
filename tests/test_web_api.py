import pytest
from fastapi.testclient import TestClient

from phishguard.web.app import create_app


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_api_analyze_returns_schema(client):
    r = client.post("/api/analyze", json={"url": "http://naver.com.login-check.xyz/a"})
    assert r.status_code == 200
    body = r.json()
    assert {"input_url", "normalized_url", "final_url", "redirect", "domain",
            "features", "rule", "model", "final_verdict", "warnings"} <= set(body)
    assert body["final_verdict"] in {"safe", "suspicious", "dangerous"}


def test_api_invalid_url_returns_400_korean(client):
    r = client.post("/api/analyze", json={"url": "invalid"})
    assert r.status_code == 400 and r.json()["error"] == "올바른 URL 형식이 아닙니다."


@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": "   "}])
def test_api_empty_url_returns_400(client, payload):
    r = client.post("/api/analyze", json=payload)
    assert r.status_code == 400 and r.json()["error"] == "URL을 입력해 주세요."


def test_api_too_long_url_returns_400(client):
    r = client.post("/api/analyze", json={"url": "http://a.com/" + "a" * 2100})
    assert r.status_code == 400
    assert r.json()["error"] == "URL이 너무 깁니다."


def test_api_unexpected_error_returns_500():
    class Boom:
        def analyze(self, raw_url):
            raise RuntimeError("x")

    r = TestClient(create_app(Boom()), raise_server_exceptions=False).post(
        "/api/analyze", json={"url": "http://a.com"}
    )
    assert r.status_code == 500 and r.json() == {"error": "분석 중 오류가 발생했습니다."}
