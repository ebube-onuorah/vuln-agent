"""
Inference Engine: Load trained models and run predictions.

Usage:
    from inference import VulnerabilityPredictor
    predictor = VulnerabilityPredictor()
    result = predictor.predict(diff_text)
"""

import os
import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional

from training.feature_engineering import DiffParser


MODELS_DIR = Path(__file__).parent / "training" / "models"


class VulnerabilityPredictor:
    """Load trained models and predict vulnerability risk from git diffs."""

    def __init__(self, models_dir: str = str(MODELS_DIR)):
        self.models_dir = Path(models_dir)
        self.xgb_model = None
        self.rf_model = None
        self.scaler = None
        self._load_models()

    def _load_models(self):
        """Load serialized models from disk."""
        xgb_path = self.models_dir / "xgboost_model.pkl"
        rf_path = self.models_dir / "rf_model.pkl"
        scaler_path = self.models_dir / "scaler.pkl"

        if xgb_path.exists():
            with open(xgb_path, "rb") as f:
                self.xgb_model = pickle.load(f)
            print(f"[OK] Loaded XGBoost from {xgb_path}")
        else:
            print(f"[WARN] XGBoost model not found at {xgb_path}")

        if rf_path.exists():
            with open(rf_path, "rb") as f:
                self.rf_model = pickle.load(f)
            print(f"[OK] Loaded Random Forest from {rf_path}")
        else:
            print(f"[WARN] Random Forest model not found at {rf_path}")

        if scaler_path.exists():
            with open(scaler_path, "rb") as f:
                self.scaler = pickle.load(f)
            print(f"[OK] Loaded scaler from {scaler_path}")
        else:
            print("[INFO] No scaler found — features will not be scaled")

    def _extract_features(self, diff_text: str) -> np.ndarray:
        """Parse diff and extract 11-feature vector."""
        parser = DiffParser(diff_text)
        metrics = parser.extract_features()
        features = np.array(metrics.to_feature_vector()).reshape(1, -1)
        return features, metrics

    def _scale_features(self, features: np.ndarray) -> np.ndarray:
        """Apply StandardScaler if available."""
        if self.scaler is not None:
            return self.scaler.transform(features)
        return features

    def predict(self, diff_text: str) -> Dict:
        """
        Predict vulnerability risk from git diff.

        Returns:
            {
                risk_score: float (0-1),
                risk_percent: str ("87%"),
                confidence: str ("high"|"medium"|"low"),
                prediction: str ("vulnerable"|"benign"),
                model_scores: {xgboost: float, random_forest: float},
                features: dict,
            }
        """
        if not diff_text or not diff_text.strip():
            return {
                "error": "Empty diff provided",
                "risk_score": 0.0,
                "prediction": "unknown",
            }

        # Extract features
        features, metrics = self._extract_features(diff_text)
        features_scaled = self._scale_features(features)

        model_scores = {}

        # XGBoost prediction
        if self.xgb_model is not None:
            xgb_prob = float(self.xgb_model.predict_proba(features_scaled)[0][1])
            model_scores["xgboost"] = round(xgb_prob, 4)

        # Random Forest prediction
        if self.rf_model is not None:
            rf_prob = float(self.rf_model.predict_proba(features_scaled)[0][1])
            model_scores["random_forest"] = round(rf_prob, 4)

        # Ensemble: average available model scores
        if model_scores:
            risk_score = float(np.mean(list(model_scores.values())))
        else:
            risk_score = 0.0

        # Confidence based on model agreement
        if len(model_scores) >= 2:
            spread = max(model_scores.values()) - min(model_scores.values())
            if spread < 0.10:
                confidence = "high"
            elif spread < 0.25:
                confidence = "medium"
            else:
                confidence = "low"
        elif len(model_scores) == 1:
            confidence = "medium"
        else:
            confidence = "low"

        prediction = "vulnerable" if risk_score >= 0.5 else "benign"

        return {
            "risk_score": round(risk_score, 4),
            "risk_percent": f"{risk_score * 100:.1f}%",
            "confidence": confidence,
            "prediction": prediction,
            "model_scores": model_scores,
            "features": {
                "lines_added": metrics.lines_added,
                "lines_deleted": metrics.lines_deleted,
                "files_changed": metrics.files_changed,
                "has_dangerous_apis": bool(metrics.has_dangerous_apis),
                "entropy": round(metrics.entropy, 4),
                "cyclomatic_complexity": metrics.cyclomatic_complexity,
                "language_type": metrics.language_type,
            },
        }

    def is_ready(self) -> bool:
        """Check if at least one model is loaded."""
        return self.xgb_model is not None or self.rf_model is not None


# Singleton for FastAPI reuse
_predictor: Optional[VulnerabilityPredictor] = None


def get_predictor() -> VulnerabilityPredictor:
    """Return cached predictor instance (lazy init)."""
    global _predictor
    if _predictor is None:
        _predictor = VulnerabilityPredictor()
    return _predictor


if __name__ == "__main__":
    predictor = VulnerabilityPredictor()

    # Test with sample diffs
    SAFE_DIFF = """
--- a/app.py
+++ b/app.py
@@ -10,4 +10,6 @@
 def get_user(user_id: int):
+    if not isinstance(user_id, int):
+        raise ValueError("user_id must be an integer")
     return db.query(User).filter_by(id=user_id).first()
"""

    RISKY_DIFF = """
--- a/utils.c
+++ b/utils.c
@@ -5,3 +5,4 @@
 void process(char *input) {
+    char buf[64];
+    strcpy(buf, input);  // Buffer overflow risk
 }
"""

    print("[TEST 1] Safe commit:")
    result = predictor.predict(SAFE_DIFF)
    print(f"  Prediction: {result['prediction']} ({result['risk_percent']} risk)")
    print(f"  Confidence: {result['confidence']}")
    print(f"  Dangerous APIs: {result['features']['has_dangerous_apis']}\n")

    print("[TEST 2] Risky commit:")
    result = predictor.predict(RISKY_DIFF)
    print(f"  Prediction: {result['prediction']} ({result['risk_percent']} risk)")
    print(f"  Confidence: {result['confidence']}")
    print(f"  Dangerous APIs: {result['features']['has_dangerous_apis']}\n")
