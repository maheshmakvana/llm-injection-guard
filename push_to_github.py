"""
Push files to GitHub using the API via subprocess git.
"""
import subprocess
import sys
import os

repo_dir = os.path.dirname(os.path.abspath(__file__))

def run(args, **kwargs):
    print("$", " ".join(args))
    r = subprocess.run(args, cwd=repo_dir, **kwargs)
    return r

# Configure git
run(["git", "config", "user.email", "noreply@github.com"])
run(["git", "config", "user.name", "PromptShield Contributors"])

# Set branch to main
run(["git", "checkout", "-b", "main"])

# Stage all files
run(["git", "add", "."])

# Commit
run(["git", "commit", "-m", "Initial release: llm-injection-guard 0.1.0 - prompt injection defense for LLM apps"])

# Push
result = run(["git", "push", "-u", "origin", "main"], capture_output=False)
print("Push result:", result.returncode)
