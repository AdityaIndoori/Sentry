"""
Pydantic schemas for structured LLM output parsing.
These enforce clean, typed responses from the LLM instead of raw markdown.
"""

import re
from pydantic import BaseModel, Field
from typing import Optional


class TriageResult(BaseModel):
    """Structured output from the triage phase."""
    severity: str = Field(description="One of: low, medium, high, critical")
    verdict: str = Field(description="One of: INVESTIGATE, FALSE_POSITIVE")
    summary: str = Field(description="One-line description of the issue")

    @classmethod
    def parse_from_text(cls, text: str) -> "TriageResult":
        """Parse structured fields from LLM free-text response."""
        text_lower = text.lower()

        # Parse severity - look for "SEVERITY:" prefix to avoid matching keywords
        # in explanatory text (e.g., "this is not critical" would wrongly match "critical")
        severity = "medium"
        severity_match = re.search(r"severity:\s*(low|medium|high|critical)", text_lower)
        if severity_match:
            severity = severity_match.group(1)
        else:
            # Fallback: scan for standalone keywords, but prefer earlier/stronger matches
            for level in ["critical", "high", "medium", "low"]:
                if level in text_lower:
                    severity = level
                    break

        # Parse verdict
        verdict = "INVESTIGATE"
        if "verdict: false positive" in text_lower or "false_positive" in text_lower:
            verdict = "FALSE_POSITIVE"

        # Parse summary - look for "SUMMARY:" line
        summary = ""
        for line in text.split("\n"):
            line_stripped = line.strip()
            if line_stripped.upper().startswith("SUMMARY:"):
                summary = line_stripped[len("SUMMARY:"):].strip()
                break
        if not summary:
            # Fallback: use first non-empty line that isn't severity/verdict
            for line in text.split("\n"):
                line_stripped = line.strip()
                if (line_stripped and
                    not line_stripped.upper().startswith("SEVERITY") and
                    not line_stripped.upper().startswith("VERDICT")):
                    summary = line_stripped[:200]
                    break
        if not summary:
            summary = text[:200]

        return cls(severity=severity, verdict=verdict, summary=summary)


class DiagnosisResult(BaseModel):
    """Structured output from the diagnosis phase."""
    root_cause: str = Field(description="Clear, concise root cause statement")
    evidence: list[str] = Field(
        default_factory=list,
        description="Key evidence found during investigation"
    )
    recommended_fix: str = Field(
        default="",
        description="Recommended remediation action"
    )

    @classmethod
    def parse_from_text(cls, text: str) -> "DiagnosisResult":
        """Parse structured fields from LLM diagnosis text."""
        root_cause = ""
        recommended_fix = ""
        evidence = []

        lines = text.split("\n")
        current_section = None

        for line in lines:
            stripped = line.strip()
            upper = stripped.upper()

            # Detect section headers
            if "ROOT CAUSE" in upper and (":" in stripped or "#" in stripped):
                current_section = "root_cause"
                # Check if content is on the same line after colon
                after_colon = stripped.split(":", 1)[-1].strip() if ":" in stripped else ""
                if after_colon and not after_colon.startswith("#"):
                    root_cause = after_colon
                continue
            elif ("RECOMMENDED FIX" in upper or "FIX:" in upper or
                  "REMEDIATION" in upper or "RESOLUTION" in upper):
                current_section = "fix"
                after_colon = stripped.split(":", 1)[-1].strip() if ":" in stripped else ""
                if after_colon and not after_colon.startswith("#"):
                    recommended_fix = after_colon
                continue
            elif "EVIDENCE" in upper or "FINDINGS" in upper:
                current_section = "evidence"
                continue

            # Collect content under sections
            if stripped and not stripped.startswith("#"):
                if current_section == "root_cause" and not root_cause:
                    root_cause = stripped.lstrip("- *")
                elif current_section == "root_cause" and root_cause:
                    root_cause += " " + stripped.lstrip("- *")
                elif current_section == "fix" and not recommended_fix:
                    recommended_fix = stripped.lstrip("- *")
                elif current_section == "fix" and recommended_fix:
                    recommended_fix += " " + stripped.lstrip("- *")
                elif current_section == "evidence":
                    evidence.append(stripped.lstrip("- *"))

        # Fallback: if we couldn't parse sections, use heuristics
        if not root_cause:
            # Take first substantive paragraph
            for line in lines:
                stripped = line.strip()
                if (stripped and len(stripped) > 30 and
                    not stripped.startswith("#") and
                    not stripped.startswith("---")):
                    root_cause = stripped[:500]
                    break
            if not root_cause:
                root_cause = text[:500].strip()

        # Clean up markdown formatting
        root_cause = _clean_markdown(root_cause)
        recommended_fix = _clean_markdown(recommended_fix)
        evidence = [_clean_markdown(e) for e in evidence[:5]]

        return cls(
            root_cause=root_cause[:500],
            evidence=evidence,
            recommended_fix=recommended_fix[:500],
        )


class RemediationResult(BaseModel):
    """Structured output from the remediation phase."""
    fix_description: str = Field(description="What fix was applied or proposed")
    tools_used: list[str] = Field(default_factory=list, description="Tools invoked")
    success: bool = Field(default=False, description="Whether the fix succeeded")

    @classmethod
    def parse_from_text(cls, text: str, tool_names: list[str] = None) -> "RemediationResult":
        """Parse fix description from remediation output."""
        fix_description = ""
        text_lower = text.lower()

        # Look for "FIX PROPOSED:" or "FIX APPLIED:" line
        for line in text.split("\n"):
            stripped = line.strip()
            upper = stripped.upper()
            if (upper.startswith("FIX PROPOSED:") or
                upper.startswith("FIX APPLIED:") or
                upper.startswith("FIX:")):
                fix_description = stripped.split(":", 1)[-1].strip()
                break

        if not fix_description:
            # Summarize the whole text
            fix_description = _clean_markdown(text[:400])

        return cls(
            fix_description=fix_description[:500],
            tools_used=tool_names or [],
            success="success" in text_lower or "applied" in text_lower,
        )


class VerificationResult(BaseModel):
    """Structured output from the verification phase."""
    resolved: bool = Field(description="Whether the incident is resolved")
    reason: str = Field(default="", description="Why resolved or not")

    @classmethod
    def parse_from_text(cls, text: str) -> "VerificationResult":
        text_lower = text.lower()
        # Bug fix: Check for negation phrases FIRST before checking positive keywords.
        # "not fixed", "not resolved", "not success" should NOT parse as resolved.
        negation_phrases = ["not fixed", "not resolved", "not success", "unsuccessful",
                            "unresolved", "failed", "still broken", "not working"]
        has_negation = any(phrase in text_lower for phrase in negation_phrases)
        has_positive = any(w in text_lower for w in ["fixed", "resolved", "success"])
        resolved = has_positive and not has_negation
        return cls(resolved=resolved, reason=text[:200].strip())


def _clean_markdown(text: str) -> str:
    """Remove markdown formatting artifacts."""
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)  # Bold
    text = re.sub(r'\*(.*?)\*', r'\1', text)  # Italic
    text = re.sub(r'`(.*?)`', r'\1', text)  # Inline code
    text = re.sub(r'^#+\s+', '', text, flags=re.MULTILINE)  # Headers
    text = text.strip()
    return text
