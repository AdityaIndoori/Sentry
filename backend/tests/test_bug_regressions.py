"""
Regression tests for documented bug fixes.

Each test targets the specific bug pattern that was originally found,
ensuring it doesn't recur. Tests use spec= mocks to enforce interface
contracts — the same technique that would have caught the ValidatorAgent
signature bug (Bug fix #1) before it shipped.

Bug fix index:
  #1  — ILLMClient.analyze() signature: (prompt, effort, tools)
  #2  — IToolExecutor.execute() takes a single ToolCall object
  #4  — Incident._phase_summary() handles terminal states
  #5  — Use timezone-aware datetime
  #9  — RateLimiter.is_allowed() auto-records on success
  #10 — AUDIT mode enforced centrally at executor level
  #14 — DISABLED mode blocks ALL tools
"""

import os
import tempfile

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.shared.interfaces import ILLMClient, IToolExecutor
from backend.shared.models import (
    Incident, IncidentState, IncidentSeverity, ToolCall, ToolResult,
)
from backend.shared.vault import LocalVault, AgentRole
from backend.shared.ai_gateway import AIGateway
from backend.shared.agent_throttle import AgentThrottle
from backend.shared.tool_registry import TrustedToolRegistry


# ═══════════════════════════════════════════════════════════════
# BUG FIX #1 — All agents must call llm.analyze(prompt=, effort=)
# ═══════════════════════════════════════════════════════════════

class TestBugFix1_AnalyzeSignature:
    """Regression: every agent must call analyze() with the correct ILLMClient signature."""

    def _make_spec_llm(self, response_text: str) -> AsyncMock:
        """Create a spec'd LLM mock that enforces the interface."""
        llm = AsyncMock(spec=ILLMClient)
        llm.analyze.return_value = {
            "text": response_text,
            "tool_calls": [],
            "thinking": "",
            "input_tokens": 10,
            "output_tokens": 10,
            "error": None,
        }
        return llm

    @pytest.mark.asyncio
    async def test_triage_agent_correct_signature(self):
        from backend.agents.triage_agent import TriageAgent
        vault = LocalVault()
        llm = self._make_spec_llm("SEVERITY: low\nVERDICT: INVESTIGATE\nSUMMARY: test")
        agent = TriageAgent(vault=vault, llm=llm, gateway=AIGateway())
        result = await agent.run(Incident(id="REG-T", symptom="test error"))
        assert result["severity"] == "low"
        llm.analyze.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_detective_agent_correct_signature(self):
        from backend.agents.detective_agent import DetectiveAgent
        vault = LocalVault()
        llm = self._make_spec_llm("ROOT CAUSE: test\nRECOMMENDED FIX: none")
        tools = AsyncMock(spec=IToolExecutor)
        tools.get_read_only_tool_definitions.return_value = []
        tools.get_tool_definitions.return_value = []
        registry = TrustedToolRegistry()
        registry.register("read_file", [AgentRole.DETECTIVE])
        agent = DetectiveAgent(
            vault=vault, llm=llm, tools=tools,
            registry=registry, gateway=AIGateway(), throttle=AgentThrottle(),
        )
        result = await agent.run(Incident(id="REG-D", symptom="error"))
        assert "root_cause" in result

    @pytest.mark.asyncio
    async def test_surgeon_agent_correct_signature(self):
        from backend.agents.surgeon_agent import SurgeonAgent
        vault = LocalVault()
        llm = self._make_spec_llm("FIX PROPOSED: restart service")
        tools = AsyncMock(spec=IToolExecutor)
        tools.get_tool_definitions.return_value = []
        registry = TrustedToolRegistry()
        registry.register("apply_patch", [AgentRole.SURGEON])
        config = MagicMock()
        config.security.mode.value = "AUDIT"
        agent = SurgeonAgent(
            vault=vault, llm=llm, tools=tools,
            registry=registry, gateway=AIGateway(), throttle=AgentThrottle(),
            config=config,
        )
        result = await agent.run(Incident(id="REG-S", symptom="err", root_cause="bad config"))
        assert "fix_description" in result

    @pytest.mark.asyncio
    async def test_validator_agent_correct_signature(self):
        """This test would have CAUGHT the original bug (wrong kwargs)."""
        from backend.agents.validator_agent import ValidatorAgent
        vault = LocalVault()
        llm = self._make_spec_llm("RESOLVED: true\nREASON: fixed")
        agent = ValidatorAgent(vault=vault, llm=llm, gateway=AIGateway())
        result = await agent.run(Incident(id="REG-V", symptom="err", fix_applied="restart"))
        assert result["resolved"] is True
        llm.analyze.assert_awaited_once()


# ═══════════════════════════════════════════════════════════════
# BUG FIX #9 — RateLimiter auto-records on success
# ═══════════════════════════════════════════════════════════════

class TestBugFix9_RateLimiterAutoRecord:
    """Regression: is_allowed() must auto-record to prevent unlimited retries."""

    def test_is_allowed_blocks_second_call_within_cooldown(self):
        from backend.shared.circuit_breaker import RateLimiter
        rl = RateLimiter()
        assert rl.is_allowed("service:restart", cooldown_seconds=60) is True
        # Second call should be blocked — auto-recorded by first is_allowed()
        assert rl.is_allowed("service:restart", cooldown_seconds=60) is False

    def test_is_allowed_allows_after_cooldown(self):
        import time
        from backend.shared.circuit_breaker import RateLimiter
        rl = RateLimiter()
        assert rl.is_allowed("key", cooldown_seconds=0) is True
        # Cooldown of 0 means it should be allowed again immediately
        time.sleep(0.01)
        assert rl.is_allowed("key", cooldown_seconds=0) is True


# ═══════════════════════════════════════════════════════════════
# BUG FIX #14 — DISABLED mode blocks ALL tools
# ═══════════════════════════════════════════════════════════════

class TestBugFix14_DisabledBlocksAll:
    """Regression: DISABLED mode must block ALL tools, not just active ones."""

    @pytest.mark.asyncio
    async def test_disabled_blocks_read_only_tool(self):
        from backend.shared.config import SecurityConfig, SentryMode
        from backend.shared.security import SecurityGuard
        from backend.mcp_tools.executor import MCPToolExecutor

        with tempfile.TemporaryDirectory() as tmp:
            config = SecurityConfig(mode=SentryMode.DISABLED, project_root=tmp)
            guard = SecurityGuard(config)
            executor = MCPToolExecutor(guard, tmp)
            result = await executor.execute(
                ToolCall(tool_name="read_file", arguments={"path": "test.txt"})
            )
            assert not result.success
            assert "DISABLED" in result.error

    @pytest.mark.asyncio
    async def test_disabled_blocks_active_tool(self):
        from backend.shared.config import SecurityConfig, SentryMode
        from backend.shared.security import SecurityGuard
        from backend.mcp_tools.executor import MCPToolExecutor

        with tempfile.TemporaryDirectory() as tmp:
            config = SecurityConfig(mode=SentryMode.DISABLED, project_root=tmp)
            guard = SecurityGuard(config)
            executor = MCPToolExecutor(guard, tmp)
            result = await executor.execute(
                ToolCall(tool_name="apply_patch", arguments={"file_path": "a.py", "diff": "x"})
            )
            assert not result.success
            assert "DISABLED" in result.error


# ═══════════════════════════════════════════════════════════════
# BUG FIX #4 — Phase summary handles terminal states
# ═══════════════════════════════════════════════════════════════

class TestBugFix4_PhaseSummaryTerminalStates:
    """Regression: resolved/escalated must mark all phases complete."""

    def test_resolved_marks_all_phases_complete(self):
        inc = Incident(id="PH-1", symptom="err", state=IncidentState.RESOLVED)
        summary = inc._phase_summary()
        assert summary["triage"] == "complete"
        assert summary["diagnosis"] == "complete"
        assert summary["remediation"] == "complete"
        assert summary["verification"] == "complete"
        assert summary["outcome"] == "resolved"

    def test_escalated_has_escalated_outcome(self):
        inc = Incident(id="PH-2", symptom="err", state=IncidentState.ESCALATED)
        summary = inc._phase_summary()
        assert summary["outcome"] == "escalated"

    def test_active_diagnosis_shows_active(self):
        inc = Incident(id="PH-3", symptom="err", state=IncidentState.DIAGNOSIS)
        summary = inc._phase_summary()
        assert summary["triage"] == "complete"
        assert summary["diagnosis"] == "active"
        assert summary["remediation"] == "pending"


# ═══════════════════════════════════════════════════════════════
# BUG FIX #10 — AUDIT mode enforced centrally at executor
# ═══════════════════════════════════════════════════════════════

class TestBugFix10_AuditModeEnforcedCentrally:
    """Regression: AUDIT mode must block active tools at executor level."""

    @pytest.mark.asyncio
    async def test_audit_blocks_apply_patch_at_executor(self):
        from backend.shared.config import SecurityConfig, SentryMode
        from backend.shared.security import SecurityGuard
        from backend.mcp_tools.executor import MCPToolExecutor

        with tempfile.TemporaryDirectory() as tmp:
            config = SecurityConfig(mode=SentryMode.AUDIT, project_root=tmp)
            guard = SecurityGuard(config)
            executor = MCPToolExecutor(guard, tmp)
            result = await executor.execute(
                ToolCall(tool_name="apply_patch", arguments={"file_path": "a.py", "diff": "x"})
            )
            assert result.audit_only is True
            assert "AUDIT" in result.output

    @pytest.mark.asyncio
    async def test_audit_allows_read_only_tools(self):
        from backend.shared.config import SecurityConfig, SentryMode
        from backend.shared.security import SecurityGuard
        from backend.mcp_tools.executor import MCPToolExecutor

        with tempfile.TemporaryDirectory() as tmp:
            # Create a file to read
            with open(os.path.join(tmp, "test.txt"), "w") as f:
                f.write("hello")
            config = SecurityConfig(mode=SentryMode.AUDIT, project_root=tmp)
            guard = SecurityGuard(config)
            executor = MCPToolExecutor(guard, tmp)
            result = await executor.execute(
                ToolCall(tool_name="read_file", arguments={"path": "test.txt"})
            )
            assert result.success is True
            assert "hello" in result.output
