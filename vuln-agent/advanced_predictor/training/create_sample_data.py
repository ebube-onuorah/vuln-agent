#!/usr/bin/env python3
"""
Create sample Big-Vul-like dataset for feature engineering development.
Real dataset can be downloaded from: https://github.com/ZeoVan/MSR_VCS
"""

import csv
import os
from pathlib import Path

# Sample dataset schema (mimics Big-Vul structure)
HEADERS = [
    "commit_id",
    "repo",
    "author",
    "date",
    "diff",  # Actual git diff
    "vuln",  # 1 = vulnerable, 0 = benign
]

# Sample commits (mix of vulnerable and benign)
SAMPLE_DATA = [
    {
        "commit_id": "abc1234",
        "repo": "openssl/openssl",
        "author": "alice",
        "date": "2021-01-15",
        "diff": """--- a/crypto/buffer.c
+++ b/crypto/buffer.c
@@ -100,7 +100,9 @@
-    char *data = malloc(size);
+    char *data = malloc(size);
+    strcpy(data, input);  // Buffer overflow vulnerability
     return data;
""",
        "vuln": 1,
    },
    {
        "commit_id": "def5678",
        "repo": "django/django",
        "author": "bob",
        "date": "2021-02-20",
        "diff": """--- a/django/views.py
+++ b/django/views.py
@@ -45,3 +45,8 @@
 def get_user(request):
     user_id = request.GET.get('id')
+    # Input validation added
+    if not user_id.isdigit():
+        raise ValueError('Invalid user ID')
     user = User.objects.get(id=user_id)
""",
        "vuln": 0,
    },
    {
        "commit_id": "ghi9012",
        "repo": "python/cpython",
        "author": "charlie",
        "date": "2021-03-10",
        "diff": """--- a/Modules/socketmodule.c
+++ b/Modules/socketmodule.c
@@ -200,5 +200,6 @@
 int socket_connect(struct socket *s, char *addr) {
-    return system(addr);  // Command injection
+    // Fixed: use proper socket API
+    return socket_connect_safe(addr);
 }
""",
        "vuln": 1,
    },
    {
        "commit_id": "jkl3456",
        "repo": "nodejs/node",
        "author": "diana",
        "date": "2021-04-05",
        "diff": """--- a/lib/crypto.js
+++ b/lib/crypto.js
@@ -50,4 +50,6 @@
 function encrypt(key, plaintext) {
     const cipher = crypto.createCipher('aes-256-cbc', key);
+    // Proper key derivation added
+    const derived = crypto.pbkdf2(key, salt, 100000, 32, 'sha256');
-    return cipher.update(plaintext, 'utf8', 'hex');
""",
        "vuln": 0,
    },
]

def create_sample_dataset(output_path: str, num_samples: int = 100):
    """Generate sample dataset for testing feature extraction."""
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()

        # Write base samples
        for row in SAMPLE_DATA:
            writer.writerow(row)

        # Generate additional synthetic samples (variations)
        for i in range(num_samples - len(SAMPLE_DATA)):
            vuln = i % 3 == 0  # 33% vulnerable
            row = {
                "commit_id": f"syn{i:05d}",
                "repo": f"repo{i % 5}",
                "author": f"author{i % 10}",
                "date": f"2021-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}",
                "diff": f"Sample diff #{i}\n+Added {i} lines\n-Removed {i % 5} lines",
                "vuln": 1 if vuln else 0,
            }
            writer.writerow(row)

    print(f"[OK] Created {output_file} with {num_samples} samples")
    return str(output_file)

if __name__ == "__main__":
    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    output = create_sample_dataset(data_dir / "big_vul_sample.csv", num_samples=100)
    print(f"[OK] Dataset saved to: {output}")
