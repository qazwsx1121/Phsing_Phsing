import pytest
from fastapi.testclient import TestClient

from phishguard.models import AnalysisResult
from phishguard.web.app import create_app
from phishguard.web.stub import StubAnalyzer, make_sample_result


@pytest.fixture
def sample_result() -> AnalysisResult:
    return make_sample_result()


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(StubAnalyzer()))
