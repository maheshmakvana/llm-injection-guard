from setuptools import setup, find_packages

setup(
    name="llm-injection-guard",
    version="0.3.0",
    description=(
        "Drop-in prompt injection defense for LLM apps and AI agents — "
        "detect, sanitize, block, and audit injection attacks in real time. "
        "Includes multi-turn session scanning, allow-lists, rate-abuse detection, "
        "multi-layer scanner, FastAPI and Flask middleware."
    ),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/maheshmakvana/llm-injection-guard",
    packages=find_packages(exclude=["tests*", "venv*"]),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "fastapi": ["fastapi>=0.100.0"],
        "flask": ["flask>=2.0.0"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords=[
        "prompt injection", "llm security", "ai security", "jailbreak detection",
        "prompt injection defense", "llm middleware", "ai safety", "owasp llm",
        "fastapi security", "flask security", "agent security", "eu ai act",
        "prompt injection detection", "prompt injection prevention",
        "llm input sanitization", "ai input validation",
        "session injection scan", "multi-turn llm security",
        "allow list llm", "rate abuse detection llm",
        "jailbreak prevention", "jailbreak detector python",
        "llm firewall", "ai guardrails", "llm guardrails",
        "prompt hacking defense", "injection blocker",
        "openai safety", "anthropic safety", "llm owasp top 10",
        "ai red teaming defense", "multi layer llm scanner",
        "llm sanitizer", "llm threat detection",
    ],
    project_urls={
        "Bug Reports": "https://github.com/maheshmakvana/llm-injection-guard/issues",
        "Source": "https://github.com/maheshmakvana/llm-injection-guard",
    },
)
