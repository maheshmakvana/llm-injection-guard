"""
Script to publish files to the remote code hosting service.
"""
import base64
import json
import urllib.request
import urllib.error
import os

TOKEN = os.environ.get("GITHUB_TOKEN", "")
OWNER = "maheshmakvana"
REPO = "llm-injection-guard"
MSG = "Initial release: llm-injection-guard 0.1.0 - prompt injection defense for LLM apps"
SRC = os.path.dirname(os.path.abspath(__file__))

FILES = [
    ("README.md", "README.md"),
    ("setup.py", "setup.py"),
    ("example_usage.py", "example_usage.py"),
    (".gitignore", ".gitignore"),
    ("promptshield/__init__.py", "promptshield/__init__.py"),
    ("promptshield/detector.py", "promptshield/detector.py"),
    ("promptshield/patterns.py", "promptshield/patterns.py"),
    ("promptshield/scanner.py", "promptshield/scanner.py"),
    ("promptshield/middleware.py", "promptshield/middleware.py"),
    ("promptshield/audit.py", "promptshield/audit.py"),
    ("promptshield/exceptions.py", "promptshield/exceptions.py"),
    ("tests/__init__.py", "tests/__init__.py"),
    ("tests/test_promptshield.py", "tests/test_promptshield.py"),
]

def create_file(remote_path, local_rel_path):
    local = os.path.join(SRC, local_rel_path.replace("/", os.sep))
    if not os.path.exists(local):
        print(f"  MISSING: {local}")
        return False
    with open(local, "rb") as f:
        content = base64.b64encode(f.read()).decode()
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/{remote_path}"
    data = json.dumps({"message": MSG, "content": content}).encode()
    req = urllib.request.Request(
        url, data=data, method="PUT",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )
    try:
        with urllib.request.urlopen(req) as r:
            print(f"  OK ({r.status}): {remote_path}")
            return True
    except urllib.error.HTTPError as e:
        err = e.read().decode()[:120]
        print(f"  FAIL ({e.code}): {remote_path} - {err}")
        return False

ok = 0
for remote, local in FILES:
    if create_file(remote, local):
        ok += 1

print(f"\n{ok}/{len(FILES)} files uploaded")
print(f"https://github.com/{OWNER}/{REPO}")
