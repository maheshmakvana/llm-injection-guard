class InjectionGuardError(Exception):
    pass

class InjectionDetectedError(InjectionGuardError):
    def __init__(self, message: str, threat_level: str = "high", patterns_matched: list = None):
        super().__init__(message)
        self.threat_level = threat_level
        self.patterns_matched = patterns_matched or []

class ScanError(InjectionGuardError):
    pass
