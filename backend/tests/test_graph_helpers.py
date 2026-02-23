"""
Tests for graph.py prompt-building helper functions.

These are pure functions that can be tested without mocking LangGraph.
Now that graph.py is included in coverage measurement, these tests
ensure the production prompt logic is verified.
"""

import pytest
from unittest.mock import MagicMock

from backend.shared.models import Incident, IncidentState, IncidentSeverity, MemoryEntry
from backend.shared.config import AppConfig, SecurityConfig, SentryMode, MemoryConfig
from backend.orchestrator.graph import (
    _build_triage_prompt,
    _build_diagnosis_prompt,
    _build_diagnosis_summary_prompt,
    _build_remediation_prompt,
    _build_verify_prompt,
)


# ═══════════════════════════════════════════════════════════════
# TRIAGE PROMPT BUILDER
# ═══════════════════════════════════════════════════════════════

class TestBuildTriagePrompt:
    def test_includes_symptom(self):
        inc = Incident(id="T1", symptom="502 Bad Gateway on /api/login")
        prompt = _build_triage_prompt(inc, [])
        assert "502 Bad Gateway on /api/login" in prompt

    def test_includes_format_instructions(self):
        inc = Incident(id="T2", symptom="error")
        prompt = _build_triage_prompt(inc, [])
        assert "SEVERITY:" in prompt
        assert "VERDICT:" in prompt
        assert "SUMMARY:" in prompt

    def test_includes_service_context(self):
        inc = Incident(id="T3", symptom="error")
        ctx = "=== SERVICE CONTEXT ===\nSource: /app/workspace\n=== END ==="
        prompt = _build_triage_prompt(inc, [], service_context=ctx)
        assert "SERVICE CONTEXT" in prompt
        assert "/app/workspace" in prompt

    def test_no_service_context_when_empty(self):
        inc = Incident(id="T4", symptom="error")
        prompt = _build_triage_prompt(inc, [], service_context="")
        assert "SERVICE CONTEXT" not in prompt

    def test_includes_history(self):
        inc = Incident(id="T5", symptom="timeout")
        history = [
            MemoryEntry(id="H1", symptom="timeout on DB", root_cause="connection pool", fix="increased pool"),
        ]
        prompt = _build_triage_prompt(inc, history)
        assert "connection pool" in prompt
        assert "increased pool" in prompt

    def test_empty_history(self):
        inc = Incident(id="T6", symptom="error")
        prompt = _build_triage_prompt(inc, [])
        assert "Similar past incidents" not in prompt

    def test_limits_history_to_3(self):
        inc = Incident(id="T7", symptom="error")
        history = [
            MemoryEntry(id=f"H{i}", symptom=f"sym{i}", root_cause=f"rc{i}", fix=f"fix{i}")
            for i in range(10)
        ]
        prompt = _build_triage_prompt(inc, history)
        assert "rc0" in prompt
        assert "rc2" in prompt
        # 4th+ should not be included
        assert "rc3" not in prompt

    def test_encourages_investigate_over_false_positive(self):
        inc = Incident(id="T8", symptom="error")
        prompt = _build_triage_prompt(inc, [])
        assert "FALSE POSITIVE" in prompt
        assert "INVESTIGATE" in prompt


# ═══════════════════════════════════════════════════════════════
# DIAGNOSIS PROMPT BUILDER
# ═══════════════════════════════════════════════════════════════

class TestBuildDiagnosisPrompt:
    def _make_config(self, mode=SentryMode.AUDIT):
        return AppConfig(security=SecurityConfig(mode=mode))

    def test_includes_symptom_and_severity(self):
        inc = Incident(id="D1", symptom="Connection refused", severity=IncidentSeverity.HIGH)
        prompt = _build_diagnosis_prompt(inc, self._make_config())
        assert "Connection refused" in prompt
        assert "high" in prompt

    def test_audit_mode_includes_audit_note(self):
        inc = Incident(id="D2", symptom="error")
        prompt = _build_diagnosis_prompt(inc, self._make_config(SentryMode.AUDIT))
        assert "AUDIT" in prompt

    def test_active_mode_no_audit_note(self):
        inc = Incident(id="D3", symptom="error")
        prompt = _build_diagnosis_prompt(inc, self._make_config(SentryMode.ACTIVE))
        assert "AUDIT mode" not in prompt

    def test_includes_service_context(self):
        inc = Incident(id="D4", symptom="error")
        ctx = "=== SERVICE CONTEXT ===\nSource: /app\n=== END ==="
        prompt = _build_diagnosis_prompt(inc, self._make_config(), service_context=ctx)
        assert "SERVICE CONTEXT" in prompt

    def test_no_service_context_when_empty(self):
        inc = Incident(id="D5", symptom="error")
        prompt = _build_diagnosis_prompt(inc, self._make_config(), service_context="")
        assert "read the source code" not in prompt


# ═══════════════════════════════════════════════════════════════
# DIAGNOSIS SUMMARY PROMPT BUILDER
# ═══════════════════════════════════════════════════════════════

class TestBuildDiagnosisSummaryPrompt:
    def test_includes_tool_results(self):
        inc = Incident(id="DS1", symptom="502 error", severity=IncidentSeverity.HIGH)
        results = ["read_file: DB_PORT=5433", "grep_search: found 3 matches"]
        prompt = _build_diagnosis_summary_prompt(inc, results, is_audit=False)
        assert "DB_PORT=5433" in prompt
        assert "3 matches" in prompt

    def test_includes_audit_note_when_audit(self):
        inc = Incident(id="DS2", symptom="error")
        prompt = _build_diagnosis_summary_prompt(inc, [], is_audit=True)
        assert "AUDIT" in prompt

    def test_no_audit_note_when_active(self):
        inc = Incident(id="DS3", symptom="error")
        prompt = _build_diagnosis_summary_prompt(inc, [], is_audit=False)
        assert "AUDIT mode" not in prompt

    def test_asks_for_final_diagnosis(self):
        inc = Incident(id="DS4", symptom="error")
        prompt = _build_diagnosis_summary_prompt(inc, [], is_audit=False)
        assert "ROOT CAUSE" in prompt
        assert "RECOMMENDED FIX" in prompt


# ═══════════════════════════════════════════════════════════════
# REMEDIATION PROMPT BUILDER
# ═══════════════════════════════════════════════════════════════

class TestBuildRemediationPrompt:
    def test_audit_mode_no_tools(self):
        inc = Incident(id="R1", symptom="error", root_cause="bad config")
        prompt = _build_remediation_prompt(inc, is_audit=True)
        assert "Do NOT call any tools" in prompt

    def test_audit_mode_includes_root_cause(self):
        inc = Incident(id="R2", symptom="error", root_cause="port 5433 is wrong")
        prompt = _build_remediation_prompt(inc, is_audit=True)
        assert "port 5433" in prompt

    def test_active_mode_instructs_tool_usage(self):
        inc = Incident(id="R3", symptom="error", root_cause="bad config")
        prompt = _build_remediation_prompt(inc, is_audit=False)
        assert "apply_patch" in prompt
        assert "restart_service" in prompt

    def test_active_mode_includes_tool_results_context(self):
        inc = Incident(id="R4", symptom="error", root_cause="port 5433")
        results = ["read_file config/db.py: DB_PORT=5433"]
        prompt = _build_remediation_prompt(inc, is_audit=False, tool_results=results)
        assert "DB_PORT=5433" in prompt

    def test_active_mode_warns_about_restart(self):
        inc = Incident(id="R5", symptom="error", root_cause="config")
        prompt = _build_remediation_prompt(inc, is_audit=False)
        assert "restart" in prompt.lower()


# ═══════════════════════════════════════════════════════════════
# VERIFICATION PROMPT BUILDER
# ═══════════════════════════════════════════════════════════════

class TestBuildVerifyPrompt:
    def test_audit_mode_says_resolved(self):
        inc = Incident(id="V1", symptom="error", fix_applied="[AUDIT] plan described")
        prompt = _build_verify_prompt(inc, is_audit=True)
        assert "AUDIT" in prompt
        assert "resolved" in prompt.lower()

    def test_active_mode_asks_fixed_or_not(self):
        inc = Incident(id="V2", symptom="error", fix_applied="restarted nginx")
        prompt = _build_verify_prompt(inc, is_audit=False)
        assert "fixed" in prompt.lower()
        assert "not fixed" in prompt.lower()

    def test_includes_symptom_and_fix(self):
        inc = Incident(id="V3", symptom="502 Bad Gateway", fix_applied="patched config")
        prompt = _build_verify_prompt(inc, is_audit=False)
        assert "502 Bad Gateway" in prompt
        assert "patched config" in prompt
