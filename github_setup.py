"""
Script to initialize git repo and push to GitHub.
Run: python github_setup.py
"""
import subprocess
import sys
import os

base = os.path.dirname(os.path.abspath(__file__))

def run(cmd, cwd=None):
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd or base, capture_output=False)
    if result.returncode != 0:
        print(f"ERROR: command failed with code {result.returncode}")
        sys.exit(result.returncode)
    return result

# Init git
run(["git", "init"])
run(["git", "checkout", "-b", "main"])
run(["git", "add", "README.md", "setup.py", "example_usage.py", ".gitignore"])
run(["git", "add", "promptshield/"])
run(["git", "add", "tests/"])
run(["git", "commit", "-m", "Initial release: llm-injection-guard 0.1.0 - prompt injection defense for LLM apps"])
run([
    "gh", "repo", "create", "llm-injection-guard",
    "--public",
    "--source=.",
    "--remote=origin",
    "--push",
    "--description", "Drop-in prompt injection defense for LLM apps and AI agents — detect, block, and audit injection attacks in real time"
])
print("\nDone! GitHub repo created and pushed.")
