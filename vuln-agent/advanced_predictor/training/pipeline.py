"""
Data Pipeline: Load, prepare, and validate data for ML training.

Responsibilities:
1. Load CSV dataset
2. Extract features using feature_engineering.py
3. Handle missing values
4. Balance classes (vulnerable vs benign)
5. Perform train/test split (temporal split)
6. Normalize/scale features
7. Validate data quality
"""

import csv
import numpy as np
from pathlib import Path
from typing import Tuple, List, Dict
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils import shuffle

from feature_engineering import DiffParser


class DataPipeline:
    """Load and prepare vulnerability prediction dataset."""

    def __init__(self, csv_path: str):
        self.csv_path = Path(csv_path)
        self.data = None
        self.X = None
        self.y = None
        self.feature_names = [
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

    def load_data(self) -> Dict:
        """Load CSV data."""
        data = []
        with open(self.csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                try:
                    diff = row.get("diff", "")
                    vuln = int(row.get("vuln", 0))

                    parser = DiffParser(diff)
                    metrics = parser.extract_features()

                    data.append(
                        {
                            "commit_id": row.get("commit_id"),
                            "date": row.get("date", ""),
                            "features": metrics.to_feature_vector(),
                            "label": vuln,
                            "repo": row.get("repo", ""),
                        }
                    )

                    if (i + 1) % 50 == 0:
                        print(f"[INFO] Loaded {i + 1} samples")

                except Exception as e:
                    print(f"[WARN] Skipping row {i + 1}: {e}")
                    continue

        self.data = data
        print(f"[OK] Loaded {len(data)} samples from {self.csv_path}")
        return {"total_samples": len(data), "data": data}

    def validate_data(self) -> Dict:
        """Validate data quality and class balance."""
        if not self.data:
            raise ValueError("No data loaded. Call load_data() first.")

        labels = [d["label"] for d in self.data]
        features = [d["features"] for d in self.data]

        total = len(labels)
        vulnerable = sum(labels)
        benign = total - vulnerable

        print(f"\n[INFO] Data Validation:")
        print(f"  Total samples: {total}")
        print(f"  Vulnerable: {vulnerable} ({100 * vulnerable / total:.1f}%)")
        print(f"  Benign: {benign} ({100 * benign / total:.1f}%)")
        print(f"  Features per sample: {len(features[0])}")

        # Check for missing values
        missing_count = 0
        for features in features:
            if any(f is None or (isinstance(f, float) and np.isnan(f)) for f in features):
                missing_count += 1

        print(f"  Samples with missing values: {missing_count}")

        return {
            "total_samples": total,
            "vulnerable": vulnerable,
            "benign": benign,
            "class_balance_ratio": vulnerable / benign if benign > 0 else 0,
            "missing_values": missing_count,
        }

    def prepare_features(self) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features and labels as numpy arrays."""
        if not self.data:
            raise ValueError("No data loaded. Call load_data() first.")

        X = np.array([d["features"] for d in self.data])
        y = np.array([d["label"] for d in self.data])

        # Handle missing values (fill with 0)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        self.X = X
        self.y = y

        print(f"[OK] Prepared features: X.shape={X.shape}, y.shape={y.shape}")
        return X, y

    def temporal_train_test_split(
        self, test_size: float = 0.2
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Temporal split: older commits → train, recent commits → test.
        This simulates real-world scenario where we predict on future data.
        """
        if self.X is None or self.y is None:
            self.prepare_features()

        # For simplicity, assume data is already sorted by date
        # In practice, sort by self.data[i]['date']
        split_idx = int(len(self.X) * (1 - test_size))

        X_train = self.X[:split_idx]
        y_train = self.y[:split_idx]
        X_test = self.X[split_idx:]
        y_test = self.y[split_idx:]

        print(
            f"[OK] Temporal split: train={len(X_train)}, test={len(X_test)}"
        )
        return X_train, X_test, y_train, y_test

    def scale_features(
        self, X_train: np.ndarray, X_test: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, StandardScaler]:
        """
        Normalize features using StandardScaler.
        Fit on training data, apply to test data.
        """
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Persist scaler for inference
        import pickle, pathlib
        scaler_path = pathlib.Path(self.csv_path).parent.parent / "models" / "scaler.pkl"
        scaler_path.parent.mkdir(parents=True, exist_ok=True)
        with open(scaler_path, "wb") as f:
            pickle.dump(scaler, f)
        print(f"[OK] Saved scaler to {scaler_path}")

        print(
            f"[OK] Scaled features: mean={X_train_scaled.mean():.4f}, std={X_train_scaled.std():.4f}"
        )
        return X_train_scaled, X_test_scaled, scaler

    def handle_class_imbalance(
        self, X_train: np.ndarray, y_train: np.ndarray, strategy: str = "oversample"
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Handle class imbalance (vulnerable samples are rarer).
        Strategies: 'oversample' (duplicate minority), 'undersample' (remove majority), 'weighted' (weight in model)
        """
        from collections import Counter

        vulnerable_count = np.sum(y_train)
        benign_count = len(y_train) - vulnerable_count

        print(f"[INFO] Before balance: vulnerable={vulnerable_count}, benign={benign_count}")

        if strategy == "oversample":
            # Duplicate minority class
            vuln_indices = np.where(y_train == 1)[0]
            benign_indices = np.where(y_train == 0)[0]

            # Repeat vulnerable samples to match benign count
            oversample_vuln = np.random.choice(
                vuln_indices, size=benign_count, replace=True
            )
            all_indices = np.concatenate([benign_indices, oversample_vuln])

            X_balanced = X_train[all_indices]
            y_balanced = y_train[all_indices]

        elif strategy == "undersample":
            # Remove majority class samples
            vuln_indices = np.where(y_train == 1)[0]
            benign_indices = np.where(y_train == 0)[0]

            # Keep only vulnerable_count * 2 benign samples
            undersample_benign = np.random.choice(
                benign_indices, size=vulnerable_count * 2, replace=False
            )
            all_indices = np.concatenate([vuln_indices, undersample_benign])

            X_balanced = X_train[all_indices]
            y_balanced = y_train[all_indices]

        else:  # 'weighted' - no resampling, just return
            X_balanced = X_train
            y_balanced = y_train

        # Shuffle
        X_balanced, y_balanced = shuffle(X_balanced, y_balanced)

        vulnerable_count_after = np.sum(y_balanced)
        benign_count_after = len(y_balanced) - vulnerable_count_after

        print(
            f"[OK] After balance ({strategy}): vulnerable={vulnerable_count_after}, benign={benign_count_after}"
        )

        return X_balanced, y_balanced

    def build_pipeline(
        self, test_size: float = 0.2, balance_strategy: str = "oversample"
    ) -> Dict:
        """
        Execute full pipeline:
        1. Load data
        2. Validate
        3. Extract features
        4. Temporal split
        5. Handle imbalance
        6. Scale features

        Returns: {X_train, X_test, y_train, y_test, scaler, metadata}
        """
        print("[INFO] Starting data pipeline...\n")

        # Step 1: Load
        self.load_data()

        # Step 2: Validate
        validation_info = self.validate_data()

        # Step 3: Prepare features
        self.prepare_features()

        # Step 4: Temporal split
        X_train, X_test, y_train, y_test = self.temporal_train_test_split(test_size)

        # Step 5: Handle imbalance
        X_train_balanced, y_train_balanced = self.handle_class_imbalance(
            X_train, y_train, strategy=balance_strategy
        )

        # Step 6: Scale
        X_train_scaled, X_test_scaled, scaler = self.scale_features(
            X_train_balanced, X_test
        )

        print(f"\n[OK] Pipeline complete!\n")

        return {
            "X_train": X_train_scaled,
            "X_test": X_test_scaled,
            "y_train": y_train_balanced,
            "y_test": y_test,
            "scaler": scaler,
            "feature_names": self.feature_names,
            "metadata": {
                "total_samples": len(self.data),
                "train_samples": len(X_train_scaled),
                "test_samples": len(X_test_scaled),
                "class_balance": validation_info,
                "timestamp": datetime.now().isoformat(),
            },
        }


if __name__ == "__main__":
    sample_csv = Path(__file__).parent / "data" / "big_vul_sample.csv"

    if sample_csv.exists():
        pipeline = DataPipeline(str(sample_csv))
        result = pipeline.build_pipeline(test_size=0.2, balance_strategy="oversample")

        print("\n[SUMMARY]")
        print(f"Training set: {result['X_train'].shape}")
        print(f"Test set: {result['X_test'].shape}")
        print(f"Features: {result['feature_names']}")
    else:
        print(f"[ERROR] {sample_csv} not found")
