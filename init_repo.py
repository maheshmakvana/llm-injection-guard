"""
Initialize git repo and create initial commit for llm-injection-guard.
Uses Python's subprocess to run git commands.
"""
import subprocess
import sys
import os
import base64
import json
import urllib.request
import urllib.error

repo_dir = os.path.dirname(os.path.abspath(__file__))
source_dir = os.path.join(os.path.dirname(repo_dir), "promptshield")

# Files to push to GitHub
files_to_push = {
    "README.md": os.path.join(source_dir, "README.md"),
    "setup.py": os.path.join(source_dir, "setup.py"),
    "example_usage.py": os.path.join(source_dir, "example_usage.py"),
    ".gitignore": os.path.join(source_dir, ".gitignore"),
    "promptshield/__init__.py": os.path.join(source_dir, "promptshield", "__init__.py"),
    "promptshield/detector.py": os.path.join(source_dir, "promptshield", "detector.py"),
    "promptshield/patterns.py": os.path.join(source_dir, "promptshield", "patterns.py"),
    "promptshield/scanner.py": os.path.join(source_dir, "promptshield", "scanner.py"),
    "promptshield/middleware.py": os.path.join(source_dir, "promptshield", "middleware.py"),
    "promptshield/audit.py": os.path.join(source_dir, "promptshield", "audit.py"),
    "promptshield/exceptions.py": os.path.join(source_dir, "promptshield", "exceptions.py"),
    "tests/__init__.py": os.path.join(source_dir, "tests", "__init__.py"),
    "tests/test_promptshield.py": os.path.join(source_dir, "tests", "test_promptshield.py"),
}

# Get token from gh CLI
token_result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
token = token_result.stdout.strip()
if not token:
    print("ERROR: Could not get GitHub token")
    sys.exit(1)

print(f"Got token: {token[:10]}...")

owner = "maheshmakvana"
repo = "llm-injection-guard"
commit_message = "Initial release: llm-injection-guard 0.1.0 - prompt injection defense for LLM apps"

def github_put_file(path, content_bytes, message, token):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    b64_content = base64.b64encode(content_bytes).decode()
    payload = json.dumps({
        "message": message,
        "content": b64_content,
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        method="PUT",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read())
            print(f"  OK: {path} -> {data.get('content', {}).get('html_url', '')}")
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  ERROR {e.code}: {path} -> {body[:200]}")
        return False

print(f"\nPushing {len(files_to_push)} files to GitHub...")
success_count = 0
for gh_path, local_path in files_to_push.items():
    if not os.path.exists(local_path):
        print(f"  SKIP (not found): {local_path}")
        continue
    with open(local_path, "rb") as f:
        content = f.read()
    if github_put_file(gh_path, content, commit_message, token):
        success_count += 1

print(f"\nDone: {success_count}/{len(files_to_push)} files pushed.")
print(f"GitHub URL: https://github.com/{owner}/{repo}")
