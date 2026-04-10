import json
import time
import logging
import hashlib
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

@dataclass
class AuditEvent:
    timestamp: float
    event_type: str  # "scan", "block", "allow", "sanitize"
    input_hash: str  # SHA256 of input (never store raw input)
    input_length: int
    threat_level: str
    risk_score: float
    patterns_matched: List[Dict]
    action_taken: str
    metadata: Dict[str, Any] = field(default_factory=dict)

class AuditLogger:
    """Immutable audit trail for compliance (EU AI Act, SOC2, etc.)"""
    def __init__(self, log_to_file: Optional[str] = None):
        self._events: List[AuditEvent] = []
        self._log_to_file = log_to_file

    def log(self, event: AuditEvent):
        self._events.append(event)
        log_data = {
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "input_hash": event.input_hash[:16] + "...",
            "threat_level": event.threat_level,
            "risk_score": event.risk_score,
            "action_taken": event.action_taken,
        }
        if event.threat_level in ("high", "critical"):
            logger.warning(f"AUDIT: {json.dumps(log_data)}")
        else:
            logger.info(f"AUDIT: {json.dumps(log_data)}")

        if self._log_to_file:
            with open(self._log_to_file, "a") as f:
                f.write(json.dumps(asdict(event)) + "\n")

    def get_events(self) -> List[AuditEvent]:
        return list(self._events)

    def get_summary(self) -> Dict:
        if not self._events:
            return {"total": 0}
        blocked = sum(1 for e in self._events if e.action_taken == "block")
        threats = [e for e in self._events if e.threat_level != "none"]
        return {
            "total_scans": len(self._events),
            "total_blocked": blocked,
            "total_threats_detected": len(threats),
            "block_rate": blocked / len(self._events) if self._events else 0,
            "threat_breakdown": {
                level: sum(1 for e in self._events if e.threat_level == level)
                for level in ["none", "low", "medium", "high", "critical"]
            }
        }

def hash_input(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
