import logging
from typing import Any, Protocol

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from phishguard.errors import InvalidURLError
from phishguard.models import AnalysisResult

logger = logging.getLogger(__name__)

MAX_URL_LENGTH = 2048


class SupportsAnalyze(Protocol):
    def analyze(self, raw_url: str) -> AnalysisResult: ...


def _error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def create_app(analyzer: SupportsAnalyze) -> FastAPI:
    app = FastAPI(title="PhishGuard")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # Sync endpoint: FastAPI runs it in the threadpool, so blocking httpx calls
    # inside the analyzer do not stall the event loop.
    @app.post("/api/analyze")
    def api_analyze(payload: dict[str, Any]) -> JSONResponse:
        url = payload.get("url")
        if not isinstance(url, str) or not url.strip():
            return _error(400, "URL을 입력해 주세요.")
        if len(url) > MAX_URL_LENGTH:
            return _error(400, "URL이 너무 깁니다.")
        try:
            result = analyzer.analyze(url)
        except InvalidURLError as exc:
            return _error(400, str(exc))
        except Exception:
            logger.exception("unexpected error while analyzing URL")
            return _error(500, "분석 중 오류가 발생했습니다.")
        return JSONResponse(result.to_dict())

    return app
