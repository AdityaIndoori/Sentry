"""
TDD tests for Pydantic output schemas (structured LLM response parsing).
Covers: parse_from_text() (regex tier 3), parse_safe() (JSON tier 2 + fallback),
and _try_extract_json() helper.
"""

import json
import pytest
from backend.orchestrator.schemas import (
    TriageResult, DiagnosisResult, RemediationResult,
    VerificationResult, _clean_markdown, _try_extract_json,
)


class TestTriageResult:
    def test_parse_standard_format(self):
        text = "SEVERITY: critical\nVERDICT: INVESTIGATE\nSUMMARY: Backend server down"
        result = TriageResult.parse_from_text(text)
        assert result.severity == "critical"
        assert result.verdict == "INVESTIGATE"
        assert result.summary == "Backend server down"

    def test_parse_false_positive(self):
        text = "SEVERITY: low\nVERDICT: FALSE POSITIVE\nSUMMARY: Scheduled health check"
        result = TriageResult.parse_from_text(text)
        assert result.severity == "low"
        assert result.verdict == "FALSE_POSITIVE"
        assert result.summary == "Scheduled health check"

    def test_parse_messy_llm_output(self):
        text = (
            "Based on my analysis, this appears to be a critical issue.\n"
            "SEVERITY: critical\n"
            "VERDICT: INVESTIGATE\n"
            "SUMMARY: Database connection pool exhausted causing 502 errors"
        )
        result = TriageResult.parse_from_text(text)
        assert result.severity == "critical"
        assert result.verdict == "INVESTIGATE"
        assert "Database connection pool" in result.summary

    def test_parse_no_explicit_format(self):
        text = "This is a high severity error that needs investigation."
        result = TriageResult.parse_from_text(text)
        assert result.severity == "high"
        assert result.verdict == "INVESTIGATE"
        assert len(result.summary) > 0

    def test_defaults_to_medium_investigate(self):
        text = "Something happened."
        result = TriageResult.parse_from_text(text)
        assert result.severity == "medium"
        assert result.verdict == "INVESTIGATE"


class TestDiagnosisResult:
    def test_parse_structured_diagnosis(self):
        text = (
            "## ROOT CAUSE:\n"
            "The backend server on port 3000 is not responding.\n\n"
            "## RECOMMENDED FIX:\n"
            "Restart the backend service.\n\n"
            "## EVIDENCE:\n"
            "- Connection refused on port 3000\n"
            "- No process listening on port 3000\n"
        )
        result = DiagnosisResult.parse_from_text(text)
        assert "port 3000" in result.root_cause
        assert "Restart" in result.recommended_fix
        assert len(result.evidence) == 2

    def test_parse_markdown_diagnosis(self):
        text = (
            "# FINAL DIAGNOSIS\n\n"
            "## ROOT CAUSE\n\n"
            "**All backend servers** in the `app_backend` pool have failed.\n\n"
            "## RECOMMENDED FIX\n\n"
            "Restart the application servers and increase health check timeout.\n"
        )
        result = DiagnosisResult.parse_from_text(text)
        assert "backend servers" in result.root_cause.lower()
        assert "Restart" in result.recommended_fix

    def test_fallback_when_no_headers(self):
        text = "The database credentials are wrong in config/db.py causing auth failures."
        result = DiagnosisResult.parse_from_text(text)
        assert "database credentials" in result.root_cause.lower()

    def test_clean_markdown_from_root_cause(self):
        text = "ROOT CAUSE: **Server** `nginx` crashed due to *memory leak*"
        result = DiagnosisResult.parse_from_text(text)
        assert "**" not in result.root_cause
        assert "`" not in result.root_cause

    def test_empty_text_fallback(self):
        result = DiagnosisResult.parse_from_text("")
        assert result.root_cause == ""  # Empty text = empty root cause


class TestRemediationResult:
    def test_parse_fix_proposed(self):
        text = (
            "I would restart the backend service.\n"
            "FIX PROPOSED: Restart app_service and verify health endpoint"
        )
        result = RemediationResult.parse_from_text(text)
        assert "Restart app_service" in result.fix_description

    def test_parse_fix_applied(self):
        text = "FIX APPLIED: Increased connection pool from 10 to 50"
        result = RemediationResult.parse_from_text(text, ["apply_patch"])
        assert "connection pool" in result.fix_description.lower()
        assert "apply_patch" in result.tools_used

    def test_fallback_to_summary(self):
        text = "The fix is to update the database configuration and restart."
        result = RemediationResult.parse_from_text(text)
        assert "database configuration" in result.fix_description.lower()


class TestVerificationResult:
    def test_resolved(self):
        result = VerificationResult.parse_from_text("The issue is resolved.")
        assert result.resolved is True

    def test_fixed(self):
        result = VerificationResult.parse_from_text("Status: fixed. All checks pass.")
        assert result.resolved is True

    def test_not_resolved(self):
        # Bug #3 fix: "Not fixed" should NOT parse as resolved.
        # The old code matched "fixed" even with negation prefix — now it
        # correctly detects "not fixed" / "not resolved" as unresolved.
        result = VerificationResult.parse_from_text("Still failing. Not fixed.")
        assert result.resolved is False

    def test_no_keywords(self):
        result = VerificationResult.parse_from_text("Cannot determine status.")
        assert result.resolved is False


class TestCleanMarkdown:
    def test_removes_bold(self):
        assert _clean_markdown("**bold text**") == "bold text"

    def test_removes_italic(self):
        assert _clean_markdown("*italic*") == "italic"

    def test_removes_code(self):
        assert _clean_markdown("`code`") == "code"

    def test_removes_headers(self):
        assert _clean_markdown("## Header text") == "Header text"

    def test_preserves_normal_text(self):
        assert _clean_markdown("normal text") == "normal text"


# ===========================================================================
# Hardening tests: _try_extract_json() helper
# ===========================================================================

class TestTryExtractJson:
    """Tests for the JSON extraction helper used by parse_safe() tier-2."""

    def test_pure_json(self):
        text = '{"severity": "high", "verdict": "INVESTIGATE", "summary": "DB down"}'
        result = _try_extract_json(text)
        assert result == {"severity": "high", "verdict": "INVESTIGATE", "summary": "DB down"}

    def test_json_code_block(self):
        text = 'Here is my analysis:\n```json\n{"severity": "critical", "verdict": "INVESTIGATE", "summary": "OOM"}\n```'
        result = _try_extract_json(text)
        assert result["severity"] == "critical"
        assert result["summary"] == "OOM"

    def test_code_block_without_json_tag(self):
        text = '```\n{"resolved": true, "reason": "Service healthy"}\n```'
        result = _try_extract_json(text)
        assert result["resolved"] is True

    def test_embedded_json_in_prose(self):
        text = 'Based on my analysis, the result is {"root_cause": "OOM killer", "evidence": []} and that concludes it.'
        result = _try_extract_json(text)
        assert result["root_cause"] == "OOM killer"

    def test_non_json_text_returns_none(self):
        text = "This is just plain text with no JSON at all."
        assert _try_extract_json(text) is None

    def test_empty_string_returns_none(self):
        assert _try_extract_json("") is None

    def test_none_returns_none(self):
        assert _try_extract_json(None) is None

    def test_whitespace_only_returns_none(self):
        assert _try_extract_json("   \n\t  ") is None

    def test_array_json_returns_none(self):
        """_try_extract_json only returns dicts, not arrays."""
        text = '[1, 2, 3]'
        assert _try_extract_json(text) is None

    def test_malformed_json_returns_none(self):
        text = '{"severity": "high", "verdict": INVESTIGATE}'  # unquoted value
        assert _try_extract_json(text) is None


# ===========================================================================
# Hardening tests: parse_safe() — 3-tier validation (JSON → regex fallback)
# ===========================================================================

class TestTriageResultParseSafe:
    """Tests for TriageResult.parse_safe() — tier 2 (JSON) + tier 3 (regex) fallback."""

    def test_valid_json_object(self):
        text = json.dumps({"severity": "critical", "verdict": "INVESTIGATE", "summary": "Disk full"})
        result = TriageResult.parse_safe(text)
        assert result.severity == "critical"
        assert result.verdict == "INVESTIGATE"
        assert result.summary == "Disk full"

    def test_json_in_code_block(self):
        text = '```json\n{"severity": "low", "verdict": "FALSE_POSITIVE", "summary": "Health check"}\n```'
        result = TriageResult.parse_safe(text)
        assert result.severity == "low"
        assert result.verdict == "FALSE_POSITIVE"

    def test_falls_back_to_regex_on_plain_text(self):
        text = "SEVERITY: high\nVERDICT: INVESTIGATE\nSUMMARY: Nginx 502 errors"
        result = TriageResult.parse_safe(text)
        assert result.severity == "high"
        assert result.verdict == "INVESTIGATE"
        assert "Nginx 502" in result.summary

    def test_invalid_json_values_fall_back_to_regex(self):
        """JSON with wrong field names should fall back to regex."""
        text = '{"sev": "critical", "verd": "INVESTIGATE"}\nSEVERITY: high\nVERDICT: INVESTIGATE\nSUMMARY: fallback'
        result = TriageResult.parse_safe(text)
        # Pydantic validation should fail on missing required fields, falling back to regex
        assert result.severity == "high" or result.severity == "critical"


class TestDiagnosisResultParseSafe:
    def test_valid_json(self):
        text = json.dumps({
            "root_cause": "Connection pool exhausted",
            "evidence": ["Max connections reached", "Timeout logs"],
            "recommended_fix": "Increase pool size"
        })
        result = DiagnosisResult.parse_safe(text)
        assert result.root_cause == "Connection pool exhausted"
        assert len(result.evidence) == 2
        assert "pool size" in result.recommended_fix.lower()

    def test_falls_back_to_regex(self):
        text = "## ROOT CAUSE:\nMemory leak in worker process\n## RECOMMENDED FIX:\nRestart workers"
        result = DiagnosisResult.parse_safe(text)
        assert "memory leak" in result.root_cause.lower()
        assert "Restart" in result.recommended_fix

    def test_partial_json_falls_back(self):
        """JSON missing required field 'root_cause' should trigger regex fallback."""
        text = '{"evidence": ["log1"]}\nROOT CAUSE: Actual root cause here'
        result = DiagnosisResult.parse_safe(text)
        # Should still extract something meaningful
        assert len(result.root_cause) > 0


class TestRemediationResultParseSafe:
    def test_valid_json(self):
        text = json.dumps({
            "fix_description": "Restarted nginx service",
            "tools_used": ["restart_service"],
            "success": True,
        })
        result = RemediationResult.parse_safe(text)
        assert result.fix_description == "Restarted nginx service"
        assert result.success is True
        assert "restart_service" in result.tools_used

    def test_json_without_tools_gets_injected(self):
        text = json.dumps({"fix_description": "Applied config patch", "success": True})
        result = RemediationResult.parse_safe(text, tool_names=["apply_patch"])
        assert "apply_patch" in result.tools_used

    def test_falls_back_to_regex(self):
        text = "FIX APPLIED: Updated database credentials in config/db.py"
        result = RemediationResult.parse_safe(text, tool_names=["apply_patch"])
        assert "database credentials" in result.fix_description.lower()
        assert "apply_patch" in result.tools_used


class TestVerificationResultParseSafe:
    def test_valid_json_resolved(self):
        text = json.dumps({"resolved": True, "reason": "All health checks passing"})
        result = VerificationResult.parse_safe(text)
        assert result.resolved is True
        assert "health checks" in result.reason.lower()

    def test_valid_json_not_resolved(self):
        text = json.dumps({"resolved": False, "reason": "Service still returning 502"})
        result = VerificationResult.parse_safe(text)
        assert result.resolved is False

    def test_falls_back_to_regex(self):
        text = "The issue is resolved. All services are healthy."
        result = VerificationResult.parse_safe(text)
        assert result.resolved is True

    def test_falls_back_negation_handling(self):
        text = "Still failing. Not resolved."
        result = VerificationResult.parse_safe(text)
        assert result.resolved is False
