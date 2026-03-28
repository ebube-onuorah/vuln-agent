"""Unit tests for inference engine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from advanced_predictor.inference import VulnerabilityPredictor

RISKY_DIFF = """--- a/utils.c
+++ b/utils.c
@@ -5,3 +5,4 @@
 void process(char *input) {
+    strcpy(buf, input);
 }
"""

SAFE_DIFF = """--- a/app.py
+++ b/app.py
@@ -1,3 +1,5 @@
 def calculate(x, y):
+    if not isinstance(x, (int, float)):
+        raise TypeError("x must be numeric")
     return x + y
"""


class TestPredictor:
    def setup_method(self):
        self.predictor = VulnerabilityPredictor()

    def test_models_loaded(self):
        assert self.predictor.is_ready()

    def test_predict_returns_dict(self):
        result = self.predictor.predict(RISKY_DIFF)
        assert isinstance(result, dict)

    def test_predict_has_required_keys(self):
        result = self.predictor.predict(RISKY_DIFF)
        for key in ("risk_score", "risk_percent", "confidence", "prediction", "model_scores", "features"):
            assert key in result, f"Missing key: {key}"

    def test_risk_score_range(self):
        result = self.predictor.predict(RISKY_DIFF)
        assert 0.0 <= result["risk_score"] <= 1.0

    def test_risk_percent_format(self):
        result = self.predictor.predict(SAFE_DIFF)
        assert result["risk_percent"].endswith("%")

    def test_confidence_valid_values(self):
        result = self.predictor.predict(RISKY_DIFF)
        assert result["confidence"] in ("high", "medium", "low")

    def test_prediction_valid_values(self):
        result = self.predictor.predict(SAFE_DIFF)
        assert result["prediction"] in ("vulnerable", "benign")

    def test_model_scores_present(self):
        result = self.predictor.predict(RISKY_DIFF)
        assert len(result["model_scores"]) >= 1
        for score in result["model_scores"].values():
            assert 0.0 <= score <= 1.0

    def test_features_breakdown(self):
        result = self.predictor.predict(RISKY_DIFF)
        features = result["features"]
        assert "has_dangerous_apis" in features
        assert "entropy" in features
        assert "lines_added" in features

    def test_empty_diff_handled(self):
        result = self.predictor.predict("")
        assert "error" in result or result["risk_score"] == 0.0

    def test_dangerous_api_flagged(self):
        result = self.predictor.predict(RISKY_DIFF)
        assert result["features"]["has_dangerous_apis"] is True

    def test_risky_ranks_higher_than_safe(self):
        risky = self.predictor.predict(RISKY_DIFF)
        safe = self.predictor.predict(SAFE_DIFF)
        # Risky diff (strcpy) should score >= safe diff
        assert risky["risk_score"] >= safe["risk_score"]
