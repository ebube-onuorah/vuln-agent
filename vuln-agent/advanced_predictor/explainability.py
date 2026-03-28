"""
SHAP Explainability: explain which features drove a vulnerability prediction.

Uses TreeExplainer (fast, exact for XGBoost/RF) to compute Shapley values.
"""

import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Any

import shap

from training.feature_engineering import DiffParser

MODELS_DIR = Path(__file__).parent / "training" / "models"

FEATURE_NAMES = [
    "lines_added",
    "lines_deleted",
    "lines_modified",
    "files_changed",
    "cyclomatic_complexity",
    "avg_function_size",
    "has_dangerous_apis",
    "entropy",
    "is_test_file",
    "language_type",
    "comment_ratio",
]

FEATURE_DESCRIPTIONS = {
    "lines_added": "Lines of code added",
    "lines_deleted": "Lines of code removed",
    "lines_modified": "Lines changed (min of added/deleted)",
    "files_changed": "Number of files in commit",
    "cyclomatic_complexity": "Control flow complexity (if/for/while count)",
    "avg_function_size": "Average lines per function",
    "has_dangerous_apis": "Contains unsafe API calls (eval, strcpy, system...)",
    "entropy": "Code randomness/obfuscation score",
    "is_test_file": "Modifies test files",
    "language_type": "Programming language (C=2, Python=1, JS=4...)",
    "comment_ratio": "Ratio of comment lines to total lines",
}


class SHAPExplainer:
    """Compute SHAP values for vulnerability predictions."""

    def __init__(self, models_dir: str = str(MODELS_DIR)):
        self.models_dir = Path(models_dir)
        self.xgb_model = None
        self.rf_model = None
        self.scaler = None
        self._xgb_explainer = None
        self._rf_explainer = None
        self._load()

    def _load(self):
        xgb_path = self.models_dir / "xgboost_model.pkl"
        rf_path = self.models_dir / "rf_model.pkl"
        scaler_path = self.models_dir / "scaler.pkl"

        if xgb_path.exists():
            with open(xgb_path, "rb") as f:
                self.xgb_model = pickle.load(f)
            self._xgb_explainer = shap.TreeExplainer(self.xgb_model)

        if rf_path.exists():
            with open(rf_path, "rb") as f:
                self.rf_model = pickle.load(f)
            self._rf_explainer = shap.TreeExplainer(self.rf_model)

        if scaler_path.exists():
            with open(scaler_path, "rb") as f:
                self.scaler = pickle.load(f)

    def explain(self, diff_text: str, model: str = "xgboost") -> Dict[str, Any]:
        """
        Compute SHAP values for a git diff.

        Returns ranked feature contributions with plain-English explanations.
        """
        parser = DiffParser(diff_text)
        metrics = parser.extract_features()
        features = np.array(metrics.to_feature_vector()).reshape(1, -1)

        if self.scaler is not None:
            features_scaled = self.scaler.transform(features)
        else:
            features_scaled = features

        # Select explainer
        if model == "xgboost" and self._xgb_explainer:
            explainer = self._xgb_explainer
            ml_model = self.xgb_model
        elif model == "random_forest" and self._rf_explainer:
            explainer = self._rf_explainer
            ml_model = self.rf_model
        else:
            return {"error": f"Model '{model}' not available"}

        # Compute SHAP values
        shap_values = explainer.shap_values(features_scaled)

        # For binary classification, shap_values may be a list [neg_class, pos_class]
        if isinstance(shap_values, list):
            sv = shap_values[1][0]  # positive class (vulnerable)
        else:
            sv = shap_values[0]

        base_value = float(explainer.expected_value)
        if isinstance(explainer.expected_value, (list, np.ndarray)):
            base_value = float(explainer.expected_value[1])

        # Build ranked contributions
        contributions = []
        for i, (name, shap_val) in enumerate(zip(FEATURE_NAMES, sv)):
            raw_value = float(features[0][i])
            contributions.append({
                "feature": name,
                "description": FEATURE_DESCRIPTIONS.get(name, name),
                "shap_value": round(float(shap_val), 4),
                "feature_value": round(raw_value, 4),
                "direction": "increases_risk" if shap_val > 0 else "decreases_risk",
                "magnitude": abs(float(shap_val)),
            })

        # Sort by absolute SHAP value (most impactful first)
        contributions.sort(key=lambda x: x["magnitude"], reverse=True)

        # Prediction
        pred_proba = float(ml_model.predict_proba(features_scaled)[0][1])

        return {
            "model": model,
            "prediction": "vulnerable" if pred_proba >= 0.5 else "benign",
            "risk_score": round(pred_proba, 4),
            "base_value": round(base_value, 4),
            "top_contributors": contributions[:5],  # top 5 most impactful
            "all_contributions": contributions,
            "plain_english": _build_explanation(contributions, pred_proba),
        }


def _build_explanation(contributions: List[Dict], risk_score: float) -> str:
    """Generate a plain-English explanation from SHAP values."""
    top_risk = [c for c in contributions if c["direction"] == "increases_risk"][:3]
    top_safe = [c for c in contributions if c["direction"] == "decreases_risk"][:2]

    lines = []

    if risk_score >= 0.5:
        lines.append(f"This commit is flagged as high risk ({risk_score * 100:.1f}%).")
    else:
        lines.append(f"This commit appears low risk ({risk_score * 100:.1f}%).")

    if top_risk:
        risk_factors = ", ".join(f'"{c["description"]}"' for c in top_risk)
        lines.append(f"Main risk drivers: {risk_factors}.")

    if top_safe:
        safe_factors = ", ".join(f'"{c["description"]}"' for c in top_safe)
        lines.append(f"Mitigating factors: {safe_factors}.")

    return " ".join(lines)


# Singleton
_explainer = None


def get_explainer() -> SHAPExplainer:
    global _explainer
    if _explainer is None:
        _explainer = SHAPExplainer()
    return _explainer


if __name__ == "__main__":
    explainer = SHAPExplainer()

    RISKY = """--- a/utils.c
+++ b/utils.c
@@ -5,3 +5,4 @@
 void process(char *input) {
+    strcpy(buf, input);
 }"""

    result = explainer.explain(RISKY, model="xgboost")
    print(f"Prediction: {result['prediction']} ({result['risk_score'] * 100:.1f}%)")
    print(f"\nPlain English:\n  {result['plain_english']}")
    print("\nTop 5 Contributors:")
    for c in result["top_contributors"]:
        arrow = "+" if c["direction"] == "increases_risk" else "-"
        print(f"  [{arrow}{c['shap_value']:+.4f}] {c['description']} (value={c['feature_value']})")
