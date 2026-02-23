"""
Tests for LangGraph node implementations in graph.py.

These tests cover the async node methods that form the production AI pipeline:
_triage_node, _diagnosis_node, _remediation_node, _verification_node,
and the routing functions _route_after_triage, _route_after_verification.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from backend.shared.config import AppConfig, SecurityConfig, SentryMode, MemoryConfig, WatcherConfig
from backend.shared.models import (
    Incident, IncidentState, IncidentSeverity, MemoryEntry, ActivityType,
)
from backend.shared.circuit_breaker import CostCircuitBreaker
from backend.shared.interfaces import ILLMClient, IMemoryStore, IToolExecutor
from backend.orchestrator.graph import IncidentGraphBuilder, IncidentGraphState


# ═══════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════

def _make_config(mode=SentryMode.AUDIT):
    return AppConfig(
        security=SecurityConfig(mode=mode, project_root="/tmp/test", max_retries=3),
        memory=MemoryConfig(file_path="/tmp/test/mem.json"),
        watcher=WatcherConfig(watch_paths=()),
    )


def _make_llm_response(text="", tool_calls=None, error=None):
    return {
        "text": text,
        "tool_calls": tool_calls or [],
        "thinking": "",
        "input_tokens": 100,
        "output_tokens": 50,
        "error": error,
    }


@pytest.fixture
def mock_llm():
    llm = AsyncMock(spec=ILLMClient)
    llm.analyze.return_value = _make_llm_response("default response")
    llm.get_usage.return_value = {"total_input_tokens": 0, "total_output_tokens": 0}
    return llm


@pytest.fixture
def mock_tools():
    tools = AsyncMock(spec=IToolExecutor)
    tools.get_tool_definitions.return_value = []
    tools.get_read_only_tool_definitions.return_value = []
    tools.get_remediation_tool_definitions.return_value = []
    return tools


@pytest.fixture
def mock_memory():
    mem = AsyncMock(spec=IMemoryStore)
    mem.load.return_value = []
    mem.get_count.return_value = 0
    mem.get_relevant.return_value = []
    return mem


@pytest.fixture
def circuit_breaker():
    return CostCircuitBreaker(max_cost_usd=5.0, window_minutes=10)


def _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker, mode=SentryMode.AUDIT):
    config = _make_config(mode)
    return IncidentGraphBuilder(config, mock_llm, mock_tools, mock_memory, circuit_breaker)


def _make_state(incident=None, service_context="", tool_results=None):
    if incident is None:
        incident = Incident(id="INC-TEST", symptom="ERROR: Connection refused on port 5432")
    return {
        "incident": incident,
        "service_context": service_context,
        "tool_results": tool_results or [],
        "tool_loop_count": 0,
    }


# ═══════════════════════════════════════════════════════════════
# TRIAGE NODE TESTS
# ═══════════════════════════════════════════════════════════════

class TestTriageNode:
    @pytest.mark.asyncio
    async def test_triage_sets_severity_and_state(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response(
            "SEVERITY: high\nVERDICT: INVESTIGATE\nSUMMARY: Database connection error"
        )
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        state = _make_state()
        result = await builder._triage_node(state)
        inc = result["incident"]
        assert inc.severity == IncidentSeverity.HIGH
        assert inc.state == IncidentState.DIAGNOSIS
        assert "triage" in result

    @pytest.mark.asyncio
    async def test_triage_false_positive_sets_idle(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response(
            "SEVERITY: low\nVERDICT: FALSE POSITIVE\nSUMMARY: Transient noise"
        )
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        state = _make_state()
        result = await builder._triage_node(state)
        assert result["incident"].state == IncidentState.IDLE

    @pytest.mark.asyncio
    async def test_triage_with_memory_hints(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_memory.get_relevant.return_value = [
            MemoryEntry(id="H1", symptom="connection refused", root_cause="DB port wrong", fix="fixed port"),
        ]
        mock_llm.analyze.return_value = _make_llm_response(
            "SEVERITY: high\nVERDICT: INVESTIGATE\nSUMMARY: Known DB issue"
        )
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        state = _make_state()
        result = await builder._triage_node(state)
        assert result["incident"].state == IncidentState.DIAGNOSIS
        # Verify memory was queried
        mock_memory.get_relevant.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_triage_with_service_context(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response(
            "SEVERITY: medium\nVERDICT: INVESTIGATE\nSUMMARY: App error"
        )
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        state = _make_state(service_context="=== SERVICE CONTEXT ===\nSource: /app\n===")
        result = await builder._triage_node(state)
        # Service context should be passed to the LLM prompt
        prompt = mock_llm.analyze.call_args[0][0]
        assert "SERVICE CONTEXT" in prompt

    @pytest.mark.asyncio
    async def test_triage_llm_error_escalates(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response(text="", error="API error")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        state = _make_state()
        result = await builder._triage_node(state)
        assert result["incident"].state == IncidentState.ESCALATED

    @pytest.mark.asyncio
    async def test_triage_exception_escalates(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.side_effect = RuntimeError("LLM crashed")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        state = _make_state()
        result = await builder._triage_node(state)
        assert result["incident"].state == IncidentState.ESCALATED
        assert "error" in result

    @pytest.mark.asyncio
    async def test_triage_logs_activity(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response(
            "SEVERITY: medium\nVERDICT: INVESTIGATE\nSUMMARY: test"
        )
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        state = _make_state()
        result = await builder._triage_node(state)
        inc = result["incident"]
        types = [a.activity_type for a in inc.activity_log]
        assert ActivityType.PHASE_START in types
        assert ActivityType.LLM_CALL in types
        assert ActivityType.PHASE_COMPLETE in types


# ═══════════════════════════════════════════════════════════════
# DIAGNOSIS NODE TESTS
# ═══════════════════════════════════════════════════════════════

class TestDiagnosisNode:
    @pytest.mark.asyncio
    async def test_diagnosis_text_response_sets_root_cause(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response(
            "ROOT CAUSE: Database port is 5433 instead of 5432\nRECOMMENDED FIX: Change port"
        )
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-D1", symptom="Connection refused", severity=IncidentSeverity.HIGH)
        state = _make_state(incident=inc)
        result = await builder._diagnosis_node(state)
        assert "5433" in result["incident"].root_cause or "5432" in result["incident"].root_cause
        assert result["incident"].state == IncidentState.REMEDIATION

    @pytest.mark.asyncio
    async def test_diagnosis_tool_loop(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        # First call: request a tool. Second call: give final answer.
        from backend.shared.models import ToolResult
        mock_llm.analyze.side_effect = [
            _make_llm_response(tool_calls=[{"name": "read_file", "arguments": {"path": "config/db.py"}}]),
            _make_llm_response("ROOT CAUSE: Wrong port\nRECOMMENDED FIX: Fix port"),
        ]
        mock_tools.execute.return_value = ToolResult(
            tool_name="read_file", success=True, output="DB_PORT = 5433"
        )
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-D2", symptom="error", severity=IncidentSeverity.HIGH)
        state = _make_state(incident=inc)
        result = await builder._diagnosis_node(state)
        assert result["incident"].root_cause is not None
        mock_tools.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_diagnosis_audit_mode_forces_summary(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        # In AUDIT mode, after 2 tool loops it should force a summary
        mock_llm.analyze.side_effect = [
            _make_llm_response(tool_calls=[{"name": "read_file", "arguments": {"path": "a.py"}}]),
            _make_llm_response(tool_calls=[{"name": "read_file", "arguments": {"path": "b.py"}}]),
            _make_llm_response("ROOT CAUSE: config issue\nRECOMMENDED FIX: fix config"),
        ]
        from backend.shared.models import ToolResult
        mock_tools.execute.return_value = ToolResult(tool_name="read_file", success=True, output="content")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker, mode=SentryMode.AUDIT)
        inc = Incident(id="INC-D3", symptom="error", severity=IncidentSeverity.MEDIUM)
        state = _make_state(incident=inc)
        result = await builder._diagnosis_node(state)
        assert result["incident"].state == IncidentState.REMEDIATION

    @pytest.mark.asyncio
    async def test_diagnosis_circuit_breaker_tripped(self, mock_llm, mock_tools, mock_memory):
        cb = CostCircuitBreaker(max_cost_usd=0.0, window_minutes=10)
        cb._tripped = True
        builder = _make_builder(mock_llm, mock_tools, mock_memory, cb)
        inc = Incident(id="INC-D4", symptom="error", severity=IncidentSeverity.HIGH)
        state = _make_state(incident=inc)
        result = await builder._diagnosis_node(state)
        assert result["incident"].state == IncidentState.ESCALATED

    @pytest.mark.asyncio
    async def test_diagnosis_exception_escalates(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.side_effect = RuntimeError("LLM crashed")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-D5", symptom="error", severity=IncidentSeverity.HIGH)
        state = _make_state(incident=inc)
        result = await builder._diagnosis_node(state)
        assert result["incident"].state == IncidentState.ESCALATED

    @pytest.mark.asyncio
    async def test_diagnosis_exhausted_loops_forces_summary(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        # Always return tool calls — exhaust all loops
        from backend.shared.models import ToolResult
        mock_llm.analyze.return_value = _make_llm_response(
            tool_calls=[{"name": "read_file", "arguments": {"path": "a.py"}}]
        )
        mock_tools.execute.return_value = ToolResult(tool_name="read_file", success=True, output="content")
        # Override to return text on the summary call
        call_count = [0]
        original_analyze = mock_llm.analyze.side_effect

        async def analyze_with_summary(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] > 3:  # After max_retries loops, return summary
                return _make_llm_response("ROOT CAUSE: Unknown issue\nRECOMMENDED FIX: Investigate manually")
            return _make_llm_response(tool_calls=[{"name": "read_file", "arguments": {"path": "a.py"}}])

        mock_llm.analyze.side_effect = analyze_with_summary
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-D6", symptom="error", severity=IncidentSeverity.HIGH)
        state = _make_state(incident=inc)
        result = await builder._diagnosis_node(state)
        assert result["incident"].state == IncidentState.REMEDIATION


# ═══════════════════════════════════════════════════════════════
# REMEDIATION NODE TESTS
# ═══════════════════════════════════════════════════════════════

class TestRemediationNode:
    @pytest.mark.asyncio
    async def test_remediation_audit_mode_no_tools(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response(
            "FIX PROPOSED: Change port from 5433 to 5432 in config/db.py"
        )
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker, mode=SentryMode.AUDIT)
        inc = Incident(id="INC-R1", symptom="error", root_cause="Wrong port")
        state = _make_state(incident=inc)
        result = await builder._remediation_node(state)
        assert "[AUDIT]" in result["incident"].fix_applied
        assert result["incident"].state == IncidentState.VERIFICATION

    @pytest.mark.asyncio
    async def test_remediation_active_mode_with_tools(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        from backend.shared.models import ToolResult
        mock_llm.analyze.side_effect = [
            _make_llm_response(tool_calls=[{"name": "apply_patch", "arguments": {"file_path": "db.py", "diff": "patch"}}]),
            _make_llm_response("FIX APPLIED: Patched config"),
        ]
        mock_tools.execute.return_value = ToolResult(tool_name="apply_patch", success=True, output="Patch applied")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker, mode=SentryMode.ACTIVE)
        inc = Incident(id="INC-R2", symptom="error", root_cause="Wrong port")
        state = _make_state(incident=inc)
        result = await builder._remediation_node(state)
        assert result["incident"].state == IncidentState.VERIFICATION
        mock_tools.execute.assert_awaited()

    @pytest.mark.asyncio
    async def test_remediation_active_no_tool_calls(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response("FIX PROPOSED: Manual fix needed")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker, mode=SentryMode.ACTIVE)
        inc = Incident(id="INC-R3", symptom="error", root_cause="Complex issue")
        state = _make_state(incident=inc)
        result = await builder._remediation_node(state)
        assert result["incident"].state == IncidentState.VERIFICATION

    @pytest.mark.asyncio
    async def test_remediation_exception_escalates(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.side_effect = RuntimeError("LLM crashed")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-R4", symptom="error", root_cause="issue")
        state = _make_state(incident=inc)
        result = await builder._remediation_node(state)
        assert result["incident"].state == IncidentState.ESCALATED

    @pytest.mark.asyncio
    async def test_remediation_includes_tool_results_in_context(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response("FIX PROPOSED: Update config")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-R5", symptom="error", root_cause="Bad config")
        state = _make_state(incident=inc, tool_results=["read_file: DB_PORT=5433"])
        result = await builder._remediation_node(state)
        assert result["incident"].state == IncidentState.VERIFICATION


# ═══════════════════════════════════════════════════════════════
# VERIFICATION NODE TESTS
# ═══════════════════════════════════════════════════════════════

class TestVerificationNode:
    @pytest.mark.asyncio
    async def test_verification_resolved(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response("The issue is fixed and resolved.")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-V1", symptom="error", fix_applied="patched")
        state = _make_state(incident=inc)
        result = await builder._verification_node(state)
        assert result["incident"].state == IncidentState.RESOLVED
        assert result["incident"].resolved_at is not None

    @pytest.mark.asyncio
    async def test_verification_not_resolved_retries(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response("The issue is not fixed, still broken.")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-V2", symptom="error", fix_applied="attempted fix", retry_count=0)
        state = _make_state(incident=inc)
        result = await builder._verification_node(state)
        assert result["incident"].state == IncidentState.DIAGNOSIS
        assert result["incident"].retry_count == 1

    @pytest.mark.asyncio
    async def test_verification_max_retries_escalates(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response("Still broken, not fixed.")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-V3", symptom="error", fix_applied="fix", retry_count=2)
        state = _make_state(incident=inc)
        result = await builder._verification_node(state)
        assert result["incident"].state == IncidentState.ESCALATED

    @pytest.mark.asyncio
    async def test_verification_audit_mode_resolves(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response("resolved")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker, mode=SentryMode.AUDIT)
        inc = Incident(id="INC-V4", symptom="error", fix_applied="[AUDIT] plan")
        state = _make_state(incident=inc)
        result = await builder._verification_node(state)
        assert result["incident"].state == IncidentState.RESOLVED

    @pytest.mark.asyncio
    async def test_verification_exception_escalates(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.side_effect = RuntimeError("LLM crashed")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-V5", symptom="error", fix_applied="fix")
        state = _make_state(incident=inc)
        result = await builder._verification_node(state)
        assert result["incident"].state == IncidentState.ESCALATED

    @pytest.mark.asyncio
    async def test_verification_logs_activity(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        mock_llm.analyze.return_value = _make_llm_response("fixed and resolved")
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-V6", symptom="error", fix_applied="fix")
        state = _make_state(incident=inc)
        result = await builder._verification_node(state)
        types = [a.activity_type for a in result["incident"].activity_log]
        assert ActivityType.PHASE_START in types
        assert ActivityType.PHASE_COMPLETE in types


# ═══════════════════════════════════════════════════════════════
# ROUTING FUNCTION TESTS
# ═══════════════════════════════════════════════════════════════

class TestGraphRouting:
    def test_route_after_triage_investigate(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="R1", symptom="err", state=IncidentState.DIAGNOSIS)
        result = builder._route_after_triage({"incident": inc})
        assert result == "diagnosis"

    def test_route_after_triage_idle(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="R2", symptom="err", state=IncidentState.IDLE)
        result = builder._route_after_triage({"incident": inc})
        assert result == "end"

    def test_route_after_triage_escalated(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="R3", symptom="err", state=IncidentState.ESCALATED)
        result = builder._route_after_triage({"incident": inc})
        assert result == "end"

    def test_route_after_verification_resolved(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="R4", symptom="err", state=IncidentState.RESOLVED)
        result = builder._route_after_verification({"incident": inc})
        assert result == "end"

    def test_route_after_verification_escalated(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="R5", symptom="err", state=IncidentState.ESCALATED)
        result = builder._route_after_verification({"incident": inc})
        assert result == "end"

    def test_route_after_verification_retry(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="R6", symptom="err", state=IncidentState.DIAGNOSIS)
        result = builder._route_after_verification({"incident": inc})
        assert result == "diagnosis"

    def test_track_cost(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        builder = _make_builder(mock_llm, mock_tools, mock_memory, circuit_breaker)
        builder._track_cost({"input_tokens": 1000, "output_tokens": 500})
        assert circuit_breaker.current_cost > 0
