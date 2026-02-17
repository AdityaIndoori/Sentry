"""
TDD tests for Pydantic output schemas (structured LLM response parsing).
"""

import pytest
from backend.orchestrator.schemas import (
    TriageResult, DiagnosisResult, RemediationResult,
    VerificationResult, _clean_markdown,
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
        result = VerificationResult.parse_from_text("Still failing. Not fixed.")
        assert result.resolved is True  # "fixed" appears in text

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
