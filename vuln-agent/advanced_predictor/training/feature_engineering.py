"""
Feature Engineering Pipeline
Extract vulnerability prediction features from git diffs and commit metadata.

11 Features extracted:
1. lines_added
2. lines_deleted
3. lines_modified
4. files_changed
5. cyclomatic_complexity (estimated via control flow keywords)
6. avg_function_size
7. has_dangerous_apis (eval, exec, system, etc.)
8. entropy (code entropy/randomness)
9. is_test_file (bool → int)
10. language_type (based on file extension)
11. comment_ratio
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple
from pathlib import Path


@dataclass
class DiffMetrics:
    """Extracted metrics from a git diff."""

    lines_added: int
    lines_deleted: int
    lines_modified: int
    files_changed: int
    cyclomatic_complexity: int
    avg_function_size: float
    has_dangerous_apis: int  # bool as int
    entropy: float
    is_test_file: int  # bool as int
    language_type: int  # 0=unknown, 1=python, 2=c/cpp, 3=java, 4=javascript
    comment_ratio: float

    def to_feature_vector(self) -> List[float]:
        """Convert to ML feature vector (11 features)."""
        return [
            float(self.lines_added),
            float(self.lines_deleted),
            float(self.lines_modified),
            float(self.files_changed),
            float(self.cyclomatic_complexity),
            self.avg_function_size,
            float(self.has_dangerous_apis),
            self.entropy,
            float(self.is_test_file),
            float(self.language_type),
            self.comment_ratio,
        ]


class DiffParser:
    """Parse git diffs and extract metrics."""

    DANGEROUS_APIS = {
        "eval",
        "exec",
        "system",
        "popen",
        "subprocess",
        "os.system",
        "execfile",
        "pickle",
        "yaml.load",
        "marshal",
        "compile",
        "input",
        "raw_input",
        "strcpy",
        "sprintf",
        "gets",
        "scanf",
        "strcat",
        "memcpy",
        "__import__",
        "importlib",
        "sql",  # Raw SQL
        "query",  # Database query without parameterization
    }

    LANGUAGE_MAP = {
        ".py": 1,
        ".java": 3,
        ".js": 4,
        ".ts": 4,
        ".c": 2,
        ".cpp": 2,
        ".cc": 2,
        ".h": 2,
        ".go": 0,
        ".rs": 0,
    }

    def __init__(self, diff_text: str):
        self.diff_text = diff_text
        self.lines = diff_text.split("\n")

    def extract_churn_metrics(self) -> Tuple[int, int, int, int]:
        """Extract lines added, deleted, modified, files changed."""
        lines_added = 0
        lines_deleted = 0
        files_changed = 0

        for line in self.lines:
            if line.startswith("+++") or line.startswith("---"):
                files_changed += 1
            elif line.startswith("+") and not line.startswith("+++"):
                lines_added += 1
            elif line.startswith("-") and not line.startswith("---"):
                lines_deleted += 1

        # Lines modified = min(added, deleted) in same hunk
        lines_modified = min(lines_added, lines_deleted)

        return lines_added, lines_deleted, lines_modified, files_changed

    def extract_complexity_metrics(self) -> Tuple[int, float]:
        """
        Estimate cyclomatic complexity and average function size.
        Heuristic: count control flow keywords (if, else, for, while, case, catch).
        """
        control_flow_keywords = {
            "if",
            "else",
            "for",
            "while",
            "switch",
            "case",
            "catch",
            "try",
            "&&",
            "||",
            "?",  # ternary
        }

        complexity = 1  # Base complexity
        function_count = 0
        function_lines = 0

        for line in self.lines:
            # Skip diff metadata
            if line.startswith(("+++", "---", "@@")):
                continue

            # Count control flow keywords
            for keyword in control_flow_keywords:
                if keyword in line:
                    complexity += 1

            # Count functions (heuristic: lines with 'def', 'function', '{')
            if re.search(r"(def |function |async |class |fn )", line):
                function_count += 1

            # Count lines in functions
            if line.startswith("+") or line.startswith("-"):
                function_lines += 1

        avg_function_size = (
            function_lines / max(function_count, 1) if function_count > 0 else 0
        )

        return complexity, avg_function_size

    def has_dangerous_api_calls(self) -> bool:
        """Check if diff contains dangerous API calls."""
        diff_lower = self.diff_text.lower()
        return any(api in diff_lower for api in self.DANGEROUS_APIS)

    def calculate_entropy(self) -> float:
        """
        Calculate Shannon entropy of the diff.
        Higher entropy = more random/obfuscated code = potentially risky.
        """
        if not self.diff_text:
            return 0.0

        # Remove whitespace and special chars, focus on tokens
        tokens = re.findall(r"\w+", self.diff_text)
        if not tokens:
            return 0.0

        # Count token frequencies
        freq = {}
        for token in tokens:
            freq[token] = freq.get(token, 0) + 1

        # Shannon entropy: -sum(p_i * log2(p_i))
        import math

        total = len(tokens)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        # Normalize to 0-1
        max_entropy = math.log2(len(freq)) if freq else 1.0
        return min(entropy / max_entropy if max_entropy > 0 else 0.0, 1.0)

    def detect_language(self) -> int:
        """Detect programming language from file extensions in diff."""
        # Extract filenames from diff headers
        filenames = []
        for line in self.lines:
            if line.startswith("+++") or line.startswith("---"):
                # Extract filename
                filename = line[6:].split("\t")[0]  # Remove +++ or ---, extract path
                filenames.append(filename)

        # Determine language from extensions
        for filename in filenames:
            ext = Path(filename).suffix.lower()
            if ext in self.LANGUAGE_MAP:
                return self.LANGUAGE_MAP[ext]

        return 0  # Unknown

    def is_test_file(self) -> bool:
        """Check if diff contains test files."""
        test_patterns = {"test", "spec", "_test", ".test", "tests/"}
        diff_lower = self.diff_text.lower()
        return any(pattern in diff_lower for pattern in test_patterns)

    def calculate_comment_ratio(self) -> float:
        """Calculate ratio of comment lines to total lines."""
        comment_lines = 0
        total_lines = 0

        for line in self.lines:
            if line.startswith("+") or line.startswith("-"):
                total_lines += 1
                # Simple heuristic: lines with # or // or /* */ are comments
                if re.search(r"(#|//|/\*|\*/)", line):
                    comment_lines += 1

        return (
            comment_lines / total_lines if total_lines > 0 else 0.0
        )  # 0.0 = no comments

    def extract_features(self) -> DiffMetrics:
        """Extract all features from diff."""
        lines_added, lines_deleted, lines_modified, files_changed = (
            self.extract_churn_metrics()
        )
        complexity, avg_func_size = self.extract_complexity_metrics()

        return DiffMetrics(
            lines_added=lines_added,
            lines_deleted=lines_deleted,
            lines_modified=lines_modified,
            files_changed=files_changed,
            cyclomatic_complexity=complexity,
            avg_function_size=avg_func_size,
            has_dangerous_apis=int(self.has_dangerous_api_calls()),
            entropy=self.calculate_entropy(),
            is_test_file=int(self.is_test_file()),
            language_type=self.detect_language(),
            comment_ratio=self.calculate_comment_ratio(),
        )


def extract_features_from_csv(csv_path: str) -> List[Dict]:
    """Extract features from CSV dataset."""
    import csv

    results = []
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            diff = row.get("diff", "")
            vuln = int(row.get("vuln", 0))

            parser = DiffParser(diff)
            metrics = parser.extract_features()

            results.append(
                {
                    "commit_id": row.get("commit_id"),
                    "features": metrics.to_feature_vector(),
                    "label": vuln,
                    "metrics": metrics,
                }
            )

            if (i + 1) % 10 == 0:
                print(f"[INFO] Processed {i + 1} commits")

    return results


if __name__ == "__main__":
    # Test with sample dataset
    sample_csv = (
        Path(__file__).parent / "data" / "big_vul_sample.csv"
    )

    if sample_csv.exists():
        print(f"[INFO] Processing {sample_csv}")
        results = extract_features_from_csv(str(sample_csv))

        print(f"\n[OK] Extracted features from {len(results)} commits\n")

        # Show sample
        for i in range(min(3, len(results))):
            result = results[i]
            print(f"Commit {i + 1}: {result['commit_id']}")
            print(f"  Label (vuln): {result['label']}")
            print(f"  Features: {result['features']}")
            print(f"  Metrics: {result['metrics']}\n")
    else:
        print(f"[ERROR] {sample_csv} not found")
