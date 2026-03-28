#!/usr/bin/env python3
"""
Create representative synthetic dataset for training.
Each sample has a realistic git diff that exercises the feature extractor.

Vulnerable samples contain:
  - Dangerous API calls (strcpy, sprintf, system, gets, eval, exec, pickle...)
  - Missing input validation
  - High cyclomatic complexity
  - C/C++ files (higher-risk language)

Benign samples contain:
  - Input validation additions
  - Safe API replacements
  - Test / documentation changes
  - Python/JS code

Real performance requires the Big-Vul dataset (~35k commits):
  https://github.com/ZeoVan/MSR_VCS
"""

import csv
import random
from pathlib import Path

HEADERS = ["commit_id", "repo", "author", "date", "diff", "vuln"]

# ─── Template pools ────────────────────────────────────────────────────────────

VULN_DIFFS = [
    # Buffer overflow — strcpy
    """--- a/src/utils.c
+++ b/src/utils.c
@@ -12,6 +12,10 @@
 void process_input(char *input) {
+    char buf[64];
+    strcpy(buf, input);
+    printf("Processing: %s\\n", buf);
+    return;
 }""",

    # Buffer overflow — sprintf
    """--- a/lib/format.c
+++ b/lib/format.c
@@ -8,4 +8,6 @@
 char *build_path(char *dir, char *file) {
+    char path[128];
+    sprintf(path, "%s/%s", dir, file);
+    return path;
 }""",

    # Command injection — system()
    """--- a/admin/exec.c
+++ b/admin/exec.c
@@ -5,3 +5,5 @@
 void run_command(char *cmd) {
+    char full[256];
+    sprintf(full, "sudo %s", cmd);
+    system(full);
 }""",

    # Command injection — gets()
    """--- a/src/input.c
+++ b/src/input.c
@@ -3,3 +3,5 @@
 void read_username() {
+    char name[32];
+    gets(name);
+    printf("Hello %s\\n", name);
 }""",

    # Python eval injection
    """--- a/app/views.py
+++ b/app/views.py
@@ -15,3 +15,5 @@
 def calculate(request):
     expr = request.POST.get('expression')
+    result = eval(expr)
+    return JsonResponse({'result': result})
 """,

    # Python exec injection
    """--- a/utils/runner.py
+++ b/utils/runner.py
@@ -8,3 +8,4 @@
 def run_script(script_name):
     code = open(script_name).read()
+    exec(code, globals())
 """,

    # Pickle deserialization
    """--- a/cache/loader.py
+++ b/cache/loader.py
@@ -6,5 +6,7 @@
 import pickle

 def load_cache(path):
+    with open(path, 'rb') as f:
+        return pickle.load(f)
 """,

    # yaml.load without Loader
    """--- a/config/parser.py
+++ b/config/parser.py
@@ -3,4 +3,5 @@
 import yaml

 def parse_config(data):
+    return yaml.load(data)
 """,

    # SQL injection
    """--- a/db/queries.c
+++ b/db/queries.c
@@ -10,5 +10,7 @@
 void get_user(char *username) {
+    char query[512];
+    sprintf(query, "SELECT * FROM users WHERE name='%s'", username);
+    db_execute(query);
 }""",

    # Format string vulnerability
    """--- a/log/logger.c
+++ b/log/logger.c
@@ -7,3 +7,4 @@
 void log_message(char *msg) {
+    printf(msg);  // format string bug
 }""",

    # Integer overflow leading to bad malloc
    """--- a/alloc/memory.c
+++ b/alloc/memory.c
@@ -5,5 +5,7 @@
 void *alloc_buffer(int count, int size) {
+    int total = count * size;  // integer overflow possible
+    void *buf = malloc(total);
+    return buf;
 }""",

    # Race condition — TOCTOU
    """--- a/fs/file_ops.c
+++ b/fs/file_ops.c
@@ -8,5 +8,8 @@
 int safe_open(char *path) {
+    if (access(path, R_OK) == 0) {
+        // TOCTOU: file may change between check and open
+        return open(path, O_RDONLY);
+    }
+    return -1;
 }""",

    # Dangerous subprocess in Python
    """--- a/tools/runner.py
+++ b/tools/runner.py
@@ -4,4 +4,6 @@
 import subprocess

 def run(cmd):
+    subprocess.call(cmd, shell=True)
 """,

    # C++ memcpy with user-controlled size
    """--- a/net/packet.cpp
+++ b/net/packet.cpp
@@ -12,4 +12,6 @@
 void handle_packet(char *data, int len) {
+    char local[128];
+    memcpy(local, data, len);  // len not validated
+    process(local);
 }""",

    # Hardcoded credentials
    """--- a/auth/login.py
+++ b/auth/login.py
@@ -5,3 +5,5 @@
 def authenticate(user, password):
+    if user == "admin" and password == "secret123":
+        return True
+    return check_db(user, password)
 """,

    # Popen with user input
    """--- a/scripts/deploy.py
+++ b/scripts/deploy.py
@@ -7,4 +7,5 @@
 import subprocess
 def deploy(branch):
+    subprocess.Popen(f"git checkout {branch} && make deploy", shell=True)
 """,

    # XSS via template rendering
    """--- a/views/render.py
+++ b/views/render.py
@@ -9,3 +9,4 @@
 def render_comment(comment_text):
+    return f"<div>{comment_text}</div>"  # unescaped user content
 """,

    # sscanf buffer overflow
    """--- a/parse/scanner.c
+++ b/parse/scanner.c
@@ -5,3 +5,4 @@
 void parse_input(char *raw) {
+    char token[16]; sscanf(raw, "%s", token);
 }""",

    # Unsafe deserialization Java-like
    """--- a/rpc/handler.py
+++ b/rpc/handler.py
@@ -3,4 +3,6 @@
 import pickle, base64

 def handle_rpc(data):
+    obj = pickle.loads(base64.b64decode(data))
+    obj.execute()
 """,

    # Null pointer dereference risk
    """--- a/core/node.c
+++ b/core/node.c
@@ -15,4 +15,6 @@
 void process_node(Node *n) {
+    char *value = n->data;
+    if (strlen(value) > 0) {  // dereference before null check
+        strcpy(output, value);
+    }
 }""",
]

BENIGN_DIFFS = [
    # Input validation
    """--- a/app/views.py
+++ b/app/views.py
@@ -10,4 +10,8 @@
 def get_user(user_id):
+    if not isinstance(user_id, int) or user_id <= 0:
+        raise ValueError("Invalid user_id")
+    if user_id > MAX_USER_ID:
+        raise ValueError("user_id out of range")
     return db.query(User).filter_by(id=user_id).first()
""",

    # Safe replacement for strcpy
    """--- a/src/utils.c
+++ b/src/utils.c
@@ -5,5 +5,6 @@
 void copy_string(char *dest, char *src, size_t n) {
-    strcpy(dest, src);
+    strncpy(dest, src, n - 1);
+    dest[n - 1] = '\\0';
 }""",

    # Add unit test
    """--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -0,0 +1,14 @@
+import pytest
+from app.auth import authenticate
+
+def test_valid_user():
+    assert authenticate('alice', 'pass123') == True
+
+def test_invalid_password():
+    assert authenticate('alice', 'wrong') == False
+
+def test_sql_injection_blocked():
+    result = authenticate("' OR '1'='1", "any")
+    assert result == False
""",

    # Documentation update
    """--- a/README.md
+++ b/README.md
@@ -1,3 +1,8 @@
 # Project
+
+## Security
+
+All user inputs are sanitized before database queries.
+SQL injection protection is built into the ORM layer.
""",

    # Dependency bump
    """--- a/requirements.txt
+++ b/requirements.txt
@@ -3,3 +3,3 @@
-Django==3.2.18
+Django==4.2.1
 requests==2.28.0
""",

    # Type annotation / refactor
    """--- a/utils/parser.py
+++ b/utils/parser.py
@@ -5,5 +5,7 @@
-def parse(data):
+def parse(data: str) -> dict:
+    \"\"\"Parse config string into dict. Raises ValueError on invalid input.\"\"\"
+    if not isinstance(data, str):
+        raise TypeError("data must be str")
     return json.loads(data)
""",

    # Fix memory leak (benign — no new dangerous APIs)
    """--- a/memory/pool.c
+++ b/memory/pool.c
@@ -8,4 +8,6 @@
 void destroy_pool(Pool *p) {
     free(p->data);
+    p->data = NULL;
+    p->size = 0;
     free(p);
 }""",

    # Add CSRF protection
    """--- a/middleware/csrf.py
+++ b/middleware/csrf.py
@@ -3,3 +3,9 @@
 def process_request(request):
+    token = request.session.get('csrf_token')
+    if not token:
+        token = generate_secure_token()
+        request.session['csrf_token'] = token
+    if request.method == 'POST':
+        if request.POST.get('csrf_token') != token:
+            raise PermissionDenied("CSRF token mismatch")
""",

    # Lint / style fix
    """--- a/api/serializers.py
+++ b/api/serializers.py
@@ -12,4 +12,4 @@
 class UserSerializer(serializers.ModelSerializer):
     class Meta:
         model = User
-        fields = '__all__'
+        fields = ['id', 'username', 'email', 'created_at']
""",

    # Add logging
    """--- a/services/email.py
+++ b/services/email.py
@@ -1,5 +1,8 @@
+import logging
+logger = logging.getLogger(__name__)
+
 def send_email(to, subject, body):
+    logger.info(f"Sending email to {to}: {subject}")
     smtp.sendmail(FROM, to, body)
""",

    # Use parameterized query
    """--- a/db/queries.py
+++ b/db/queries.py
@@ -5,5 +5,5 @@
 def get_user(username):
-    query = f"SELECT * FROM users WHERE name='{username}'"
-    return db.execute(query)
+    query = "SELECT * FROM users WHERE name=?"
+    return db.execute(query, (username,))
""",

    # Frontend validation
    """--- a/static/js/form.js
+++ b/static/js/form.js
@@ -3,3 +3,8 @@
 function submitForm() {
+    const email = document.getElementById('email').value;
+    if (!email.match(/^[^@]+@[^@]+\\.[^@]+$/)) {
+        showError('Invalid email address');
+        return false;
+    }
     return true;
 }""",

    # Add rate limiting
    """--- a/api/views.py
+++ b/api/views.py
@@ -1,4 +1,6 @@
+from django.utils.decorators import method_decorator
+from ratelimit.decorators import ratelimit
+
+@method_decorator(ratelimit(key='ip', rate='10/m'), name='dispatch')
 class LoginView(APIView):
     pass
""",

    # CI configuration
    """--- a/.github/workflows/test.yml
+++ b/.github/workflows/test.yml
@@ -0,0 +1,10 @@
+name: Tests
+on: [push]
+jobs:
+  test:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@v4
+      - run: pip install -r requirements.txt
+      - run: pytest tests/ -v
""",

    # Password hashing fix
    """--- a/auth/models.py
+++ b/auth/models.py
@@ -8,5 +8,6 @@
 def set_password(self, raw_password):
-    self.password = raw_password  # plain text!
+    from django.contrib.auth.hashers import make_password
+    self.password = make_password(raw_password)
     self.save()
""",

    # Timeout added to requests
    """--- a/integrations/api_client.py
+++ b/integrations/api_client.py
@@ -5,3 +5,3 @@
 def fetch(url):
-    return requests.get(url)
+    return requests.get(url, timeout=10)
""",

    # Error handling
    """--- a/handlers/upload.py
+++ b/handlers/upload.py
@@ -8,3 +8,7 @@
 def handle_upload(file):
+    ALLOWED = {'.jpg', '.png', '.pdf'}
+    ext = Path(file.name).suffix.lower()
+    if ext not in ALLOWED:
+        raise ValueError(f"File type {ext} not allowed")
     save_file(file)
""",

    # Null check added
    """--- a/core/node.c
+++ b/core/node.c
@@ -4,4 +4,6 @@
 void process_node(Node *n) {
+    if (n == NULL || n->data == NULL) {
+        return;
+    }
     strncpy(output, n->data, sizeof(output) - 1);
 }""",

    # API versioning
    """--- a/api/urls.py
+++ b/api/urls.py
@@ -3,3 +3,4 @@
 urlpatterns = [
+    path('v2/', include('api.v2.urls')),
     path('v1/', include('api.v1.urls')),
 ]""",
]


def create_sample_dataset(output_path: str, num_samples: int = 200):
    """
    Generate synthetic dataset with realistic diffs that exercise the feature extractor.
    50/50 class balance for robust training.
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(42)
    rows = []

    vuln_pool = VULN_DIFFS * ((num_samples // 2) // len(VULN_DIFFS) + 1)
    benign_pool = BENIGN_DIFFS * ((num_samples // 2) // len(BENIGN_DIFFS) + 1)
    rng.shuffle(vuln_pool)
    rng.shuffle(benign_pool)

    repos = ["openssl/openssl", "linux/linux", "django/django", "nodejs/node",
             "python/cpython", "curl/curl", "apache/httpd", "nginx/nginx"]
    authors = ["alice", "bob", "charlie", "diana", "evan", "fiona"]
    years = [2020, 2021, 2022, 2023, 2024]

    for i in range(num_samples // 2):
        rows.append({
            "commit_id": f"vuln{i:05d}",
            "repo": rng.choice(repos),
            "author": rng.choice(authors),
            "date": f"{rng.choice(years)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
            "diff": vuln_pool[i],
            "vuln": 1,
        })

    for i in range(num_samples // 2):
        rows.append({
            "commit_id": f"safe{i:05d}",
            "repo": rng.choice(repos),
            "author": rng.choice(authors),
            "date": f"{rng.choice(years)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
            "diff": benign_pool[i],
            "vuln": 0,
        })

    rng.shuffle(rows)

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(rows)

    vuln_count = sum(1 for r in rows if r["vuln"] == 1)
    print(f"[OK] Created {output_file} with {len(rows)} samples ({vuln_count} vulnerable, {len(rows) - vuln_count} benign)")
    return str(output_file)


if __name__ == "__main__":
    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    create_sample_dataset(data_dir / "big_vul_sample.csv", num_samples=200)
