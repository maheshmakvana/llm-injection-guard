"""
promptshield — Drop-in prompt injection defense for LLM apps and AI agents.

Detect, block, sanitize, and audit prompt injection attacks in real time.
Supports FastAPI, Flask, multi-turn session scanning, allow-lists,
rate-abuse detection, and any Python LLM application.
"""

from .detector import InjectionDetector, DetectionResult
from .scanner import PromptScanner
from .audit import AuditLogger, AuditEvent
from .exceptions import PromptShieldError, InjectionDetectedError, ScanError
from .patterns import INJECTION_PATTERNS, SUSPICIOUS_KEYWORDS

# Advanced (0.2.0)
from .advanced import (
    InputSanitizer,
    SessionScanner,
    AllowList,
    RateAbuseDetector,
    MultiLayerScanner,
)

__version__ = "0.2.0"
__all__ = [
    # Core
    "InjectionDetector",
    "DetectionResult",
    "PromptScanner",
    "AuditLogger",
    "AuditEvent",
    "PromptShieldError",
    "InjectionDetectedError",
    "ScanError",
    "INJECTION_PATTERNS",
    "SUSPICIOUS_KEYWORDS",
    # Advanced (0.2.0)
    "InputSanitizer",
    "SessionScanner",
    "AllowList",
    "RateAbuseDetector",
    "MultiLayerScanner",
]
