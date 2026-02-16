"""
AI Gateway - Interception layer between agents and the LLM/tools.

Implements:
- Input: Prompt injection detection before data reaches the LLM
- Output: PII/sensitive data scanning before data leaves the system boundary
- Output: PII redaction for safe logging

Zero Trust principle: Trust nothing, scan everything.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a gateway scan."""
    is_safe: bool
    threats: List[str] = field(default_factory=list)
    details: str = ""


class AIGateway:
    """
    AI Firewall that sits between agents and external interfaces.

    Scans inputs for prompt injection attacks.
    Scans outputs for PII and sensitive data leakage.
    """

    # --- Prompt Injection Patterns ---
    INJECTION_PATTERNS = [
        # System prompt override attempts
        (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "prompt_injection"),
        (r"(?i)ignore\s+(all\s+)?prior\s+instructions", "prompt_injection"),
        (r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+", "prompt_injection"),
        (r"(?i)forget\s+(all\s+)?(previous|prior|your)\s+instructions", "prompt_injection"),
        (r"(?i)override\s+(system|safety)\s+(prompt|instructions|rules)", "prompt_injection"),
        # Role hijacking
        (r"(?i)^SYSTEM:\s*you\s+are\s+now", "role_hijack"),
        (r"(?i)you\s+are\s+now\s+in\s+unrestricted\s+mode", "role_hijack"),
        (r"(?i)enter\s+(god|admin|root|unrestricted)\s+mode", "role_hijack"),
        (r"(?i)act\s+as\s+(if\s+)?(you\s+have\s+)?(no|zero)\s+(restrictions|limits|safety)", "role_hijack"),
        # Delimiter injection
        (r"</system>", "delimiter_injection"),
        (r"<system>", "delimiter_injection"),
        (r"<\|im_start\|>", "delimiter_injection"),
        (r"<\|im_end\|>", "delimiter_injection"),
        (r"\[INST\]", "delimiter_injection"),
        (r"\[/INST\]", "delimiter_injection"),
        # Command injection via prompt
        (r"(?i)execute\s+(any|all)\s+command", "command_injection"),
        (r"(?i)run\s+rm\s+-rf", "command_injection"),
        (r"(?i)ignore\s+safety\s+rules", "prompt_injection"),
    ]

    # --- PII / Sensitive Data Patterns ---
    PII_PATTERNS = [
        # Email addresses
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "pii_email"),
        # API keys (common formats)
        (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*\S+", "pii_api_key"),
        (r"sk-[a-zA-Z0-9-]{20,}", "pii_api_key"),
        # Passwords
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+", "pii_password"),
        # Internal IP addresses (RFC 1918)
        (r"(?:192\.168\.\d{1,3}\.\d{1,3})", "pii_internal_ip"),
        (r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})", "pii_internal_ip"),
        (r"(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})", "pii_internal_ip"),
        # SSH private keys
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "pii_private_key"),
        # AWS credentials
        (r"AKIA[0-9A-Z]{16}", "pii_aws_key"),
        # Credit card numbers (basic)
        (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "pii_credit_card"),
        # Social Security Numbers
        (r"\b\d{3}-\d{2}-\d{4}\b", "pii_ssn"),
    ]

    def scan_input(self, text: str) -> ScanResult:
        """
        Scan input for prompt injection attacks.
        Returns ScanResult with is_safe=False if threats detected.
        """
        threats = []
        for pattern, threat_type in self.INJECTION_PATTERNS:
            if re.search(pattern, text):
                threats.append(threat_type)
                logger.warning(f"PROMPT INJECTION DETECTED: {threat_type} in input")

        # Deduplicate
        threats = list(set(threats))

        if threats:
            return ScanResult(
                is_safe=False,
                threats=threats,
                details=f"Detected {len(threats)} injection threat(s)",
            )
        return ScanResult(is_safe=True)

    def scan_output(self, text: str) -> ScanResult:
        """
        Scan output for PII and sensitive data.
        Returns ScanResult with is_safe=False if PII detected.
        """
        threats = []
        for pattern, threat_type in self.PII_PATTERNS:
            if re.search(pattern, text):
                threats.append(threat_type)
                logger.warning(f"PII DETECTED in output: {threat_type}")

        # Deduplicate
        threats = list(set(threats))

        if threats:
            return ScanResult(
                is_safe=False,
                threats=threats,
                details=f"Detected {len(threats)} PII type(s) in output",
            )
        return ScanResult(is_safe=True)

    def redact_output(self, text: str) -> str:
        """
        Redact PII from output text, replacing with [REDACTED_TYPE].
        """
        result = text
        for pattern, threat_type in self.PII_PATTERNS:
            tag = f"[REDACTED_{threat_type.upper()}]"
            result = re.sub(pattern, tag, result)
        return result
