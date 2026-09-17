"""API-level tests for the DevSentinel AI service.

These run in rule-only mode (no transformer download), so they are fast and
work offline. Set DEVSENTINEL_SKIP_MODEL=1 before importing the app so startup
does not attempt to fetch ~500 MB of weights.

Run with:  pytest tests/ -v
"""

import os

import pytest
from fastapi.testclient import TestClient

# Must be set BEFORE `main` is imported — it is read at module load time.
os.environ["DEVSENTINEL_SKIP_MODEL"] = "1"

from main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    # The context manager form triggers FastAPI's lifespan startup/shutdown.
    with TestClient(app) as test_client:
        yield test_client


SQL_INJECTION_SNIPPET = """
public User findUser(String name) throws SQLException {
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    return map(rs);
}
"""

CLEAN_SNIPPET = """
public int add(int a, int b) {
    return a + b;
}
"""


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


def test_health_returns_up(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "UP"


def test_health_reports_model_state_in_camel_case(client):
    """Spring Boot's AiAnalysisClient reads `modelLoaded` from this payload."""
    body = client.get("/health").json()
    assert "modelLoaded" in body
    assert "modelName" in body
    # SKIP_MODEL is set, so no weights should be loaded.
    assert body["modelLoaded"] is False


# ---------------------------------------------------------------------------
# /api/v1/predict — contract with the Java client
# ---------------------------------------------------------------------------


def test_predict_detects_sql_injection(client):
    response = client.post("/api/v1/predict", json={
        "className": "UserDao",
        "methodName": "findUser",
        "codeSnippet": SQL_INJECTION_SNIPPET,
        "startLine": 10,
        "staticAnalysisHint": "possible_sql_injection",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["vulnerabilityType"] == "SQL_INJECTION"
    assert body["owaspCategory"] == "A03:2021-Injection"
    assert body["suggestedFix"]


def test_predict_returns_camel_case_keys(client):
    """Field names must match the Java DTO exactly or deserialization breaks."""
    body = client.post("/api/v1/predict", json={
        "codeSnippet": SQL_INJECTION_SNIPPET,
    }).json()

    for key in ("vulnerabilityType", "severityScore", "issueDescription",
                "suggestedFix", "owaspCategory", "confidence", "modelVersion"):
        assert key in body, f"missing key {key} expected by the Java client"


def test_predict_clean_code_returns_none(client):
    body = client.post("/api/v1/predict", json={
        "className": "Calc",
        "methodName": "add",
        "codeSnippet": CLEAN_SNIPPET,
        "startLine": 1,
    }).json()
    assert body["vulnerabilityType"] == "NONE"
    assert body["severityScore"] == 0.0


def test_predict_accepts_snake_case_too(client):
    """populate_by_name lets you test the service with curl using snake_case."""
    response = client.post("/api/v1/predict", json={
        "code_snippet": SQL_INJECTION_SNIPPET,
        "method_name": "findUser",
    })
    assert response.status_code == 200
    assert response.json()["vulnerabilityType"] == "SQL_INJECTION"


def test_predict_rejects_empty_snippet(client):
    response = client.post("/api/v1/predict", json={"codeSnippet": ""})
    assert response.status_code == 422


def test_predict_rejects_missing_snippet(client):
    response = client.post("/api/v1/predict", json={"methodName": "x"})
    assert response.status_code == 422


def test_predict_handles_very_large_snippet(client):
    """Oversized input is truncated, not rejected, and must not 500."""
    huge = CLEAN_SNIPPET + ("\n// padding comment line" * 5000)
    response = client.post("/api/v1/predict", json={"codeSnippet": huge})
    assert response.status_code == 200


def test_predict_severity_score_within_bounds(client):
    body = client.post("/api/v1/predict", json={
        "codeSnippet": SQL_INJECTION_SNIPPET,
    }).json()
    assert 0.0 <= body["severityScore"] <= 10.0
    assert 0.0 <= body["confidence"] <= 1.0


def test_rule_only_mode_reports_model_version(client):
    body = client.post("/api/v1/predict", json={
        "codeSnippet": SQL_INJECTION_SNIPPET,
    }).json()
    # Honest reporting: without weights loaded this must not claim CodeBERT.
    assert body["modelVersion"] == "rule-only"


def test_timing_header_present(client):
    response = client.get("/health")
    assert "X-Inference-Time-Ms" in response.headers
