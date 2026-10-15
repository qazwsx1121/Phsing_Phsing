from fastapi import FastAPI

from phishguard.web.app import SupportsAnalyze, create_app
from phishguard.web.stub import StubAnalyzer


def build_default_analyzer() -> SupportsAnalyze:
    # Phase 2: stub analyzer; replaced by the real Analyzer in Task 11.
    return StubAnalyzer()


app: FastAPI = create_app(build_default_analyzer())
