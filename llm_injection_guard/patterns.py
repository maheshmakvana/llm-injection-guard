"""
Prompt injection attack patterns database.
Covers direct injection, indirect injection, jailbreaks, and role manipulation.
"""
from typing import List, Dict

INJECTION_PATTERNS: List[Dict] = [
    # Direct instruction override
    {"pattern": r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)", "category": "instruction_override", "severity": "critical"},
    {"pattern": r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)", "category": "instruction_override", "severity": "critical"},
    {"pattern": r"forget\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|training|rules?)", "category": "instruction_override", "severity": "critical"},
    {"pattern": r"override\s+(your\s+)?(instructions?|rules?|guidelines?|training|system\s+prompt)", "category": "instruction_override", "severity": "critical"},

    # System prompt extraction
    {"pattern": r"(print|show|reveal|display|output|repeat|tell\s+me)\s+(your\s+)?(system\s+prompt|initial\s+prompt|original\s+instructions?|base\s+prompt)", "category": "system_prompt_extraction", "severity": "high"},
    {"pattern": r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|rules?|guidelines?|system\s+prompt)", "category": "system_prompt_extraction", "severity": "high"},

    # Role manipulation / jailbreak
    {"pattern": r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as|simulate\s+being)\s+.{0,50}(without\s+(restrictions?|filters?|limits?|guidelines?))", "category": "role_manipulation", "severity": "high"},
    {"pattern": r"DAN\s+(mode|prompt|jailbreak)", "category": "jailbreak", "severity": "critical"},
    {"pattern": r"jailbreak", "category": "jailbreak", "severity": "high"},
    {"pattern": r"(developer|debug|admin|god|unrestricted|uncensored)\s+mode", "category": "mode_switch", "severity": "high"},

    # Prompt injection markers
    {"pattern": r"<\s*(system|assistant|human|user)\s*>", "category": "injection_marker", "severity": "medium"},
    {"pattern": r"\[INST\]|\[\/INST\]|\[SYSTEM\]|\[USER\]|\[ASSISTANT\]", "category": "injection_marker", "severity": "medium"},
    {"pattern": r"###\s*(Instruction|System|Human|Assistant|Context)\s*:", "category": "injection_marker", "severity": "medium"},

    # Indirect / data exfiltration
    {"pattern": r"(when\s+you\s+see|if\s+you\s+read|upon\s+receiving)\s+.{0,30}(execute|run|perform|do)\s+the\s+following", "category": "indirect_injection", "severity": "high"},
    {"pattern": r"<!--\s*INJECT", "category": "indirect_injection", "severity": "critical"},

    # Prompt leaking
    {"pattern": r"repeat\s+(the\s+)?(above|everything|all)\s+(verbatim|exactly|word\s+for\s+word)", "category": "prompt_leak", "severity": "high"},
    {"pattern": r"(translate|encode|encode\s+to\s+base64)\s+(the\s+)?(above|previous|system)\s+(text|prompt|message|instructions?)", "category": "prompt_leak", "severity": "high"},

    # Multi-turn attacks
    {"pattern": r"(in\s+your\s+next\s+response|from\s+now\s+on|for\s+all\s+future)\s+.{0,50}(ignore|disregard|forget|override)", "category": "persistent_injection", "severity": "high"},

    # Token manipulation
    {"pattern": r"\\n\\n(human|assistant|system|user)\s*:", "category": "token_injection", "severity": "medium"},
    {"pattern": r"\x00|\x01|\x02|\x03", "category": "null_byte_injection", "severity": "critical"},
]

SUSPICIOUS_KEYWORDS = [
    "prompt injection", "jailbreak", "bypass filter", "ignore safety",
    "unlock mode", "unrestricted", "without limitations", "no restrictions",
    "as an AI without", "pretend you have no", "act without guidelines"
]
