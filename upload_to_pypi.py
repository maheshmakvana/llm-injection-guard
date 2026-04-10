"""
PyPI upload script for promptshield.
Run: python upload_to_pypi.py
"""
import subprocess
import sys
import os

dist_dir = os.path.join(os.path.dirname(__file__), "dist")
pypirc = os.path.join(os.path.dirname(__file__), "..", ".pypirc")

files = [
    os.path.join(dist_dir, "promptshield-0.1.0-py3-none-any.whl"),
    os.path.join(dist_dir, "promptshield-0.1.0.tar.gz"),
]

cmd = [sys.executable, "-m", "twine", "upload"] + files + ["--config-file", pypirc]
print("Running:", " ".join(cmd))
result = subprocess.run(cmd, capture_output=False)
sys.exit(result.returncode)
