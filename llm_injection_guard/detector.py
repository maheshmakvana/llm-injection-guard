import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from .patterns import INJECTION_PATTERNS, SUSPICIOUS_KEYWORDS
from .exceptions import InjectionDetectedError

logger = logging.getLogger(__name__)

SEVERITY_SCORES = {"critical": 10, "high": 7, "medium": 4, "low": 1}

@dataclass
class DetectionResult:
    is_injection: bool
    threat_level: str  # "none", "low", "medium", "high", "critical"
    risk_score: float  # 0.0 to 100.0
    patterns_matched: List[Dict] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    input_length: int = 0
    sanitized_input: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "is_injection": self.is_injection,
            "threat_level": self.threat_level,
            "risk_score": self.risk_score,
            "patterns_matched": self.patterns_matched,
            "suspicious_keywords": self.suspicious_keywords,
            "input_length": self.input_length,
        }

class InjectionDetector:
    def __init__(
        self,
        threshold_score: float = 7.0,
        custom_patterns: Optional[List[Dict]] = None,
        check_keywords: bool = True,
    ):
        self.threshold_score = threshold_score
        self.check_keywords = check_keywords
        self._compiled = self._compile_patterns(INJECTION_PATTERNS + (custom_patterns or []))

    def _compile_patterns(self, patterns: List[Dict]) -> List[Dict]:
        compiled = []
        for p in patterns:
            try:
                compiled.append({
                    **p,
                    "compiled": re.compile(p["pattern"], re.IGNORECASE | re.DOTALL)
                })
            except re.error as e:
                logger.warning(f"Invalid pattern '{p['pattern']}': {e}")
        return compiled

    def scan(self, text: str) -> DetectionResult:
        matched = []
        total_score = 0.0

        for p in self._compiled:
            if p["compiled"].search(text):
                score = SEVERITY_SCORES.get(p["severity"], 1)
                matched.append({
                    "pattern": p["pattern"],
                    "category": p["category"],
                    "severity": p["severity"],
                    "score": score,
                })
                total_score += score

        keywords_found = []
        if self.check_keywords:
            lower_text = text.lower()
            for kw in SUSPICIOUS_KEYWORDS:
                if kw.lower() in lower_text:
                    keywords_found.append(kw)
                    total_score += 3.0

        # Normalize to 0-100
        risk_score = min(100.0, total_score * 5)

        if total_score == 0:
            threat_level = "none"
        elif total_score < 4:
            threat_level = "low"
        elif total_score < 7:
            threat_level = "medium"
        elif total_score < 10:
            threat_level = "high"
        else:
            threat_level = "critical"

        is_injection = total_score >= self.threshold_score

        if is_injection:
            logger.warning(
                f"Injection detected: score={total_score:.1f}, level={threat_level}, "
                f"patterns={len(matched)}"
            )

        return DetectionResult(
            is_injection=is_injection,
            threat_level=threat_level,
            risk_score=risk_score,
            patterns_matched=matched,
            suspicious_keywords=keywords_found,
            input_length=len(text),
        )

    def scan_and_raise(self, text: str) -> DetectionResult:
        result = self.scan(text)
        if result.is_injection:
            raise InjectionDetectedError(
                f"Prompt injection detected (score={result.risk_score:.1f}, "
                f"level={result.threat_level})",
                threat_level=result.threat_level,
                patterns_matched=result.patterns_matched,
            )
        return result
