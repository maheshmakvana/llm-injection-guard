import time
import logging
from typing import Optional, Dict, Any
from .detector import InjectionDetector, DetectionResult
from .audit import AuditLogger, AuditEvent, hash_input
from .exceptions import InjectionDetectedError

logger = logging.getLogger(__name__)

class PromptScanner:
    """
    High-level scanner: detects injection, logs audit events, and optionally blocks.

    Usage:
        scanner = PromptScanner()
        result = scanner.scan(user_input)
        if result.is_injection:
            # handle threat
    """
    def __init__(
        self,
        threshold_score: float = 7.0,
        block_on_detection: bool = True,
        audit_logger: Optional[AuditLogger] = None,
        custom_patterns=None,
    ):
        self.detector = InjectionDetector(
            threshold_score=threshold_score,
            custom_patterns=custom_patterns,
        )
        self.block_on_detection = block_on_detection
        self.audit = audit_logger or AuditLogger()

    def scan(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> DetectionResult:
        result = self.detector.scan(text)
        action = "block" if (result.is_injection and self.block_on_detection) else (
            "flag" if result.is_injection else "allow"
        )

        event = AuditEvent(
            timestamp=time.time(),
            event_type="scan",
            input_hash=hash_input(text),
            input_length=len(text),
            threat_level=result.threat_level,
            risk_score=result.risk_score,
            patterns_matched=result.patterns_matched,
            action_taken=action,
            metadata=metadata or {},
        )
        self.audit.log(event)

        if result.is_injection and self.block_on_detection:
            raise InjectionDetectedError(
                f"Prompt injection blocked (risk_score={result.risk_score:.1f}, "
                f"threat_level={result.threat_level}). "
                f"Patterns matched: {[p['category'] for p in result.patterns_matched]}",
                threat_level=result.threat_level,
                patterns_matched=result.patterns_matched,
            )

        return result

    def is_safe(self, text: str) -> bool:
        try:
            result = self.detector.scan(text)
            return not result.is_injection
        except Exception:
            return False

    def get_audit_summary(self) -> Dict:
        return self.audit.get_summary()
