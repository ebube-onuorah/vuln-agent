"""
Phase 2: Train ML Models
Train XGBoost, Random Forest, and Neural Network for vulnerability prediction.

Models:
1. XGBoost - Primary (fast, interpretable, good with imbalanced data)
2. Random Forest - Cross-check (robust, feature importance)
3. Neural Network (TensorFlow) - Ensemble voting

Evaluation:
- Precision, Recall, F1
- ROC-AUC (ranking ability)
- Feature importance (SHAP)
"""

import os
import pickle
import json
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    auc,
)
import xgboost as xgb
from pipeline import DataPipeline

# TensorFlow not available in this environment
# Will use XGBoost + Random Forest ensemble


class VulnerabilityModelTrainer:
    """Train and evaluate vulnerability prediction models."""

    def __init__(self, csv_path: str, output_dir: str = "models"):
        self.csv_path = csv_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.pipeline = DataPipeline(csv_path)
        self.data = None
        self.models = {}
        self.metrics = {}

    def prepare_data(self) -> Dict:
        """Load and prepare data."""
        print("[PHASE 2] Preparing data...\n")
        self.data = self.pipeline.build_pipeline(test_size=0.2, balance_strategy="oversample")
        return self.data

    def train_xgboost(self) -> xgb.XGBClassifier:
        """Train XGBoost model."""
        print("[MODEL 1/3] Training XGBoost...\n")

        X_train = self.data["X_train"]
        y_train = self.data["y_train"]

        model = xgb.XGBClassifier(
            max_depth=6,
            learning_rate=0.1,
            n_estimators=100,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=(len(y_train) - np.sum(y_train)) / np.sum(y_train),
            random_state=42,
            verbosity=1,
        )

        model.fit(
            X_train,
            y_train,
            eval_set=[(X_train, y_train)],
            verbose=False,
        )

        print("[OK] XGBoost trained\n")
        return model

    def train_random_forest(self) -> RandomForestClassifier:
        """Train Random Forest model."""
        print("[MODEL 2/3] Training Random Forest...\n")

        X_train = self.data["X_train"]
        y_train = self.data["y_train"]

        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )

        model.fit(X_train, y_train)

        print("[OK] Random Forest trained\n")
        return model


    def evaluate_model(
        self, model: Any, model_name: str
    ) -> Dict:
        """Evaluate model on test set."""
        X_test = self.data["X_test"]
        y_test = self.data["y_test"]

        # Get predictions
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        y_pred = model.predict(X_test)

        # Calculate metrics
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_test, y_pred_proba)

        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

        metrics = {
            "model_name": model_name,
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "roc_auc": float(roc_auc),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "accuracy": float((tp + tn) / (tp + tn + fp + fn)),
        }

        print(f"[EVAL] {model_name.upper()}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1:        {f1:.4f}")
        print(f"  ROC-AUC:   {roc_auc:.4f}")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}\n")

        return metrics

    def save_model(self, model: Any, model_name: str) -> str:
        """Save trained model to disk."""
        if model_name == "xgboost":
            filepath = self.output_dir / "xgboost_model.pkl"
        elif model_name == "random_forest":
            filepath = self.output_dir / "rf_model.pkl"
        else:
            raise ValueError(f"Unknown model: {model_name}")

        with open(filepath, "wb") as f:
            pickle.dump(model, f)

        print(f"[OK] Saved {model_name} to {filepath}")
        return str(filepath)

    def train_all_models(self) -> Dict[str, Any]:
        """Train both models (XGBoost + Random Forest)."""
        # Prepare data
        self.prepare_data()

        # Train models
        self.models["xgboost"] = self.train_xgboost()
        self.models["random_forest"] = self.train_random_forest()

        # Evaluate models
        print("[EVALUATION RESULTS]\n")
        for model_name, model in self.models.items():
            metrics = self.evaluate_model(model, model_name)
            self.metrics[model_name] = metrics

        # Save models
        print("[SAVING MODELS]\n")
        for model_name, model in self.models.items():
            self.save_model(model, model_name)

        # Save metrics
        self.save_metrics()

        return self.metrics

    def save_metrics(self):
        """Save evaluation metrics to JSON."""
        filepath = self.output_dir / "metrics.json"

        # Add metadata
        all_metrics = {
            "timestamp": datetime.now().isoformat(),
            "dataset_size": len(self.data["X_train"]) + len(self.data["X_test"]),
            "train_samples": len(self.data["X_train"]),
            "test_samples": len(self.data["X_test"]),
            "n_features": self.data["X_train"].shape[1],
            "feature_names": self.data["feature_names"],
            "models": self.metrics,
        }

        with open(filepath, "w") as f:
            json.dump(all_metrics, f, indent=2)

        print(f"[OK] Saved metrics to {filepath}\n")
        return str(filepath)

    def print_summary(self):
        """Print training summary."""
        print("\n" + "=" * 60)
        print("TRAINING SUMMARY".center(60))
        print("=" * 60)

        # Find best model by ROC-AUC
        best_model = max(self.metrics.items(), key=lambda x: x[1]["roc_auc"])
        print(f"\nBest Model: {best_model[0].upper()}")
        print(f"  ROC-AUC: {best_model[1]['roc_auc']:.4f}")
        print(f"  Precision: {best_model[1]['precision']:.4f}")
        print(f"  Recall: {best_model[1]['recall']:.4f}")
        print(f"  F1: {best_model[1]['f1']:.4f}")

        print("\n" + "-" * 60)
        print("All Models Comparison:")
        print("-" * 60)
        for model_name, metrics in self.metrics.items():
            print(
                f"{model_name:20} | ROC-AUC: {metrics['roc_auc']:.4f} | F1: {metrics['f1']:.4f}"
            )

        print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    sample_csv = Path(__file__).parent / "data" / "big_vul_sample.csv"

    if sample_csv.exists():
        trainer = VulnerabilityModelTrainer(str(sample_csv))
        metrics = trainer.train_all_models()
        trainer.print_summary()
    else:
        print(f"[ERROR] {sample_csv} not found")
