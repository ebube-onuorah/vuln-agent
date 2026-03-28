"""
Integration tests for FastAPI endpoints.
Uses TestClient (sync) — no running server needed.
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from fastapi.testclient import TestClient

from advanced_predictor.api import app

client = TestClient(app, raise_server_exceptions=False)

RISKY_DIFF = """--- a/utils.c
+++ b/utils.c
@@ -5,3 +5,5 @@
 void process(char *input) {
+    char buf[64];
+    strcpy(buf, input);
+    system(buf);
 }
"""

SAFE_DIFF = """--- a/app.py
+++ b/app.py
@@ -10,4 +10,6 @@
 def get_user(user_id: int):
+    if not isinstance(user_id, int):
+        raise ValueError("Invalid user_id")
     return db.query(User).filter_by(id=user_id).first()
"""


class TestHealth:
    def test_health_returns_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert "models_loaded" in data
        assert data["n_features"] == 11

    def test_health_no_auth_required(self):
        """Health endpoint should always be public."""
        resp = client.get("/health", headers={"X-API-Key": "wrong-key"})
        # Auth is not applied to /health — should still be 200
        assert resp.status_code == 200


class TestPredict:
    def test_predict_risky_diff(self):
        resp = client.post("/predict", json={"diff": RISKY_DIFF})
        # Models may not be loaded in CI, accept 200 or 503
        assert resp.status_code in (200, 503)
        if resp.status_code == 200:
            data = resp.json()
            assert 0.0 <= data["risk_score"] <= 1.0
            assert data["prediction"] in ("vulnerable", "benign")
            assert data["confidence"] in ("high", "medium", "low")
            assert "model_scores" in data
            assert "features" in data

    def test_predict_safe_diff(self):
        resp = client.post("/predict", json={"diff": SAFE_DIFF})
        assert resp.status_code in (200, 503)

    def test_predict_empty_diff_rejected(self):
        resp = client.post("/predict", json={"diff": ""})
        assert resp.status_code == 422  # Pydantic min_length validation

    def test_predict_missing_diff_rejected(self):
        resp = client.post("/predict", json={})
        assert resp.status_code == 422

    def test_predict_with_repo_metadata(self):
        resp = client.post("/predict", json={
            "diff": SAFE_DIFF,
            "repo": "owner/repo",
            "commit_id": "abc123",
        })
        assert resp.status_code in (200, 503)
        if resp.status_code == 200:
            assert resp.json()["repo"] == "owner/repo"
            assert resp.json()["commit_id"] == "abc123"


class TestExplain:
    def test_explain_risky_diff(self):
        resp = client.post("/explain", json={"diff": RISKY_DIFF, "model": "xgboost"})
        assert resp.status_code in (200, 400, 503)
        if resp.status_code == 200:
            data = resp.json()
            assert "prediction" in data
            assert "top_risk_factors" in data
            assert isinstance(data["top_risk_factors"], list)

    def test_explain_invalid_model(self):
        resp = client.post("/explain", json={"diff": RISKY_DIFF, "model": "nonexistent_model"})
        # Either 400 (bad model) or 503 (models not loaded) — not 200 with garbage
        assert resp.status_code in (400, 503)

    def test_explain_default_model_is_xgboost(self):
        resp = client.post("/explain", json={"diff": SAFE_DIFF})
        assert resp.status_code in (200, 503)


class TestAuth:
    def setup_method(self):
        # Clear API_KEY so auth is disabled for most tests
        os.environ.pop("API_KEY", None)
        # Reload auth module to pick up env change
        import importlib
        import advanced_predictor.auth as auth_mod
        importlib.reload(auth_mod)

    def test_open_mode_no_key_needed(self):
        """When API_KEY env var is not set, requests pass without a key."""
        os.environ.pop("API_KEY", None)
        resp = client.post("/predict", json={"diff": SAFE_DIFF})
        assert resp.status_code in (200, 503)  # 503 if models not loaded, but NOT 401

    def test_bearer_token_accepted(self):
        """Valid Bearer token passes auth."""
        os.environ["API_KEY"] = "test-secret-key"
        import importlib
        import advanced_predictor.auth as auth_mod
        importlib.reload(auth_mod)
        resp = client.post(
            "/predict",
            json={"diff": SAFE_DIFF},
            headers={"Authorization": "Bearer test-secret-key"},
        )
        assert resp.status_code in (200, 503)  # Not 401/403

    def test_x_api_key_header_accepted(self):
        """X-API-Key header also works."""
        os.environ["API_KEY"] = "test-secret-key"
        import importlib
        import advanced_predictor.auth as auth_mod
        importlib.reload(auth_mod)
        resp = client.post(
            "/predict",
            json={"diff": SAFE_DIFF},
            headers={"X-API-Key": "test-secret-key"},
        )
        assert resp.status_code in (200, 503)

    def teardown_method(self):
        os.environ.pop("API_KEY", None)


class TestScanGithub:
    def test_invalid_pr_url_rejected(self):
        resp = client.post("/scan/github", json={"pr_url": "not-a-url"})
        assert resp.status_code == 400

    def test_missing_pr_url_rejected(self):
        resp = client.post("/scan/github", json={})
        assert resp.status_code == 422

    def test_valid_url_format_accepted(self):
        """URL is valid format — will fail at network fetch in CI (expected 502/404)."""
        resp = client.post("/scan/github", json={
            "pr_url": "https://github.com/nonexistent-org/nonexistent-repo/pull/1"
        })
        # 404 (repo not found) or 502 (network error in CI) — but not 422 (invalid request)
        assert resp.status_code in (400, 404, 429, 502, 503)
