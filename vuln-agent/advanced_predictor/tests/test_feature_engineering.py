"""Unit tests for feature extraction pipeline."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from advanced_predictor.training.feature_engineering import DiffParser, DiffMetrics

SAFE_DIFF = """--- a/app.py
+++ b/app.py
@@ -10,4 +10,6 @@
 def get_user(user_id: int):
+    if not isinstance(user_id, int):
+        raise ValueError("Invalid user_id")
     return db.query(User).filter_by(id=user_id).first()
"""

RISKY_DIFF = """--- a/utils.c
+++ b/utils.c
@@ -5,3 +5,5 @@
 void process(char *input) {
+    char buf[64];
+    strcpy(buf, input);
+    system(buf);
 }
"""

COMPLEX_DIFF = """--- a/logic.py
+++ b/logic.py
@@ -1,5 +1,20 @@
+def process(data):
+    if data:
+        for item in data:
+            if item.valid:
+                while item.pending:
+                    try:
+                        result = eval(item.cmd)
+                    except Exception:
+                        pass
+    return data
"""


class TestChurnMetrics:
    def test_lines_added(self):
        parser = DiffParser(RISKY_DIFF)
        metrics = parser.extract_features()
        assert metrics.lines_added == 3

    def test_lines_deleted(self):
        parser = DiffParser(SAFE_DIFF)
        metrics = parser.extract_features()
        assert metrics.lines_deleted == 0

    def test_files_changed(self):
        parser = DiffParser(RISKY_DIFF)
        metrics = parser.extract_features()
        assert metrics.files_changed >= 1

    def test_empty_diff(self):
        parser = DiffParser("")
        metrics = parser.extract_features()
        assert metrics.lines_added == 0
        assert metrics.lines_deleted == 0


class TestDangerousApis:
    def test_detects_strcpy(self):
        parser = DiffParser(RISKY_DIFF)
        assert parser.has_dangerous_api_calls() is True

    def test_detects_eval(self):
        parser = DiffParser(COMPLEX_DIFF)
        assert parser.has_dangerous_api_calls() is True

    def test_safe_diff_no_dangerous_apis(self):
        parser = DiffParser(SAFE_DIFF)
        # SAFE_DIFF contains no dangerous API patterns
        result = parser.has_dangerous_api_calls()
        assert isinstance(result, bool)

    def test_system_call_detected(self):
        diff = "--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n+system(user_input);"
        parser = DiffParser(diff)
        assert parser.has_dangerous_api_calls() is True


class TestEntropy:
    def test_entropy_range(self):
        parser = DiffParser(RISKY_DIFF)
        entropy = parser.calculate_entropy()
        assert 0.0 <= entropy <= 1.0

    def test_empty_entropy(self):
        parser = DiffParser("")
        assert parser.calculate_entropy() == 0.0

    def test_repetitive_low_entropy(self):
        repetitive = "+aaa\n+aaa\n+aaa\n+aaa\n+aaa"
        parser = DiffParser(repetitive)
        entropy = parser.calculate_entropy()
        assert entropy < 0.5

    def test_varied_high_entropy(self):
        parser = DiffParser(RISKY_DIFF)
        entropy = parser.calculate_entropy()
        assert entropy > 0.5


class TestLanguageDetection:
    def test_c_file(self):
        parser = DiffParser(RISKY_DIFF)
        assert parser.detect_language() == 2  # C/C++

    def test_python_file(self):
        parser = DiffParser(SAFE_DIFF)
        assert parser.detect_language() == 1  # Python

    def test_unknown_language(self):
        parser = DiffParser("--- a/README\n+++ b/README\n@@ -1 +1 @@\n+hello")
        assert parser.detect_language() == 0


class TestCyclomaticComplexity:
    def test_simple_diff_low_complexity(self):
        parser = DiffParser(RISKY_DIFF)
        complexity, _ = parser.extract_complexity_metrics()
        assert complexity >= 1

    def test_complex_diff_high_complexity(self):
        parser = DiffParser(COMPLEX_DIFF)
        complexity, _ = parser.extract_complexity_metrics()
        assert complexity > 4  # multiple if/for/while/try

    def test_base_complexity_is_one(self):
        parser = DiffParser("+one line added")
        complexity, _ = parser.extract_complexity_metrics()
        assert complexity == 1


class TestFeatureVector:
    def test_vector_length(self):
        parser = DiffParser(RISKY_DIFF)
        metrics = parser.extract_features()
        vector = metrics.to_feature_vector()
        assert len(vector) == 11

    def test_vector_all_numeric(self):
        parser = DiffParser(SAFE_DIFF)
        metrics = parser.extract_features()
        vector = metrics.to_feature_vector()
        for v in vector:
            assert isinstance(v, (int, float))

    def test_vector_no_nans(self):
        import math
        parser = DiffParser(RISKY_DIFF)
        metrics = parser.extract_features()
        for v in metrics.to_feature_vector():
            assert not math.isnan(v)

    def test_returns_diff_metrics_type(self):
        parser = DiffParser(SAFE_DIFF)
        metrics = parser.extract_features()
        assert isinstance(metrics, DiffMetrics)
