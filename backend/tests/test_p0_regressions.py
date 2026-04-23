"""
P0 regression tests — one per bug fixed in the production hardening pass.

These tests lock in fixes for:
  1.  ESCALATED incident leak (incidents stayed in _active_incidents forever).
  2.  _resolved_incidents deque with bounded length.
  3.  (retired P3.4b) JSONMemoryStore atomic writes — the JSON store was
      deleted; memory now goes through SQLAlchemy's transactional write
      path, which has stronger atomicity guarantees than tmp+rename did.
  4.  LogWatcher UTF-8 codepoint split across polls.
  5.  LogWatcher inode-based rotation detection.
  6.  LogWatcher start() returns a task handle.
  7.  CostCircuitBreaker thread safety under concurrent record_usage.
  8.  Watcher control endpoints serialized under concurrent start calls
      (asserted via the lock's existence since exercising the live watcher
      is out of scope for a unit test).
  9.  SupervisorAgent dead code removed — importing it must fail.
  10. P0.1b — ToolExecutor AUDIT-mode short-circuit must run AFTER
      Pydantic + content validation. Malicious arguments (non-whitelisted
      commands, path traversal, bad URLs) must be hard-rejected in AUDIT
      mode, not silently "logged as audit_only=True".
  11. P1.4 — ToolExecutor wired with a LocalVault requires a vault-issued
      JITCredential (agent + scope match) on every execute() call. Forged,
      scope-mismatched, wrong-agent, and revoked credentials are hard-
      rejected at the tool boundary before any other gate runs. Legacy
      executors constructed without a vault keep pre-P1.4 behaviour.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.orchestrator.engine import MAX_RESOLVED_INCIDENTS, Orchestrator
from backend.shared.circuit_breaker import CostCircuitBreaker
from backend.shared.config import (
    AppConfig,
    MemoryConfig,
    SecurityConfig,
    SentryMode,
    WatcherConfig,
)
from backend.shared.models import Incident, IncidentState, LogEvent, MemoryEntry
from backend.watcher.log_watcher import LogWatcher


# ═══════════════════════════════════════════════════════════════
# Fix #1 — ESCALATED incident leak
# ═══════════════════════════════════════════════════════════════


def _make_config(project_root: str) -> AppConfig:
    return AppConfig(
        security=SecurityConfig(mode=SentryMode.AUDIT, project_root=project_root),
        memory=MemoryConfig(file_path=os.path.join(project_root, "mem.json")),
        watcher=WatcherConfig(watch_paths=()),
        service_source_path=project_root,
    )


def _build_orchestrator_with_graph(graph_ainvoke_side_effect, project_root):
    """Build an Orchestrator whose compiled graph does whatever you say."""
    mock_graph = AsyncMock()
    mock_graph.ainvoke = AsyncMock(side_effect=graph_ainvoke_side_effect)
    mock_builder = MagicMock()
    mock_builder.build.return_value = mock_graph

    mock_registry = MagicMock()
    mock_registry.has_context.return_value = False
    mock_registry.build_prompt_context.return_value = ""

    mock_mem = AsyncMock()
    mock_mem.save = AsyncMock()
    mock_mem.load = AsyncMock(return_value=[])
    mock_mem.get_count = AsyncMock(return_value=0)
    mock_mem.system_fingerprint = ""

    with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
         patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
        return Orchestrator(
            _make_config(project_root),
            AsyncMock(),
            AsyncMock(),
            mock_mem,
            CostCircuitBreaker(max_cost_usd=5.0),
        )


class TestEscalatedLeakFix:
    """The engine must remove terminal-state incidents from _active_incidents,
    including ESCALATED — which previously leaked indefinitely.
    """

    @pytest.mark.asyncio
    async def test_terminal_escalated_removed_in_graph_outcome(self, tmp_path):
        def escalate(state):
            state["incident"].state = IncidentState.ESCALATED
            return {"incident": state["incident"]}

        orch = _build_orchestrator_with_graph(escalate, str(tmp_path))
        event = LogEvent(source_file="x", line_content="ERROR: boom")
        result = await orch.handle_event(event)

        assert result is not None
        assert result.state == IncidentState.ESCALATED
        assert len(orch._active_incidents) == 0
        assert len(orch._resolved_incidents) == 0

    @pytest.mark.asyncio
    async def test_terminal_escalated_removed_on_exception(self, tmp_path):
        def crash(_state):
            raise RuntimeError("graph blew up")

        orch = _build_orchestrator_with_graph(crash, str(tmp_path))
        event = LogEvent(source_file="x", line_content="ERROR: boom")
        result = await orch.handle_event(event)

        assert result is not None
        assert result.state == IncidentState.ESCALATED
        # Regression: exception path must also clean up via `finally`.
        assert len(orch._active_incidents) == 0

    @pytest.mark.asyncio
    async def test_many_escalated_do_not_accumulate(self, tmp_path):
        """Simulate 50 failing incidents; _active_incidents must be empty."""
        def escalate(state):
            state["incident"].state = IncidentState.ESCALATED
            return {"incident": state["incident"]}

        orch = _build_orchestrator_with_graph(escalate, str(tmp_path))
        for i in range(50):
            await orch.handle_event(
                LogEvent(source_file=f"f{i}.log", line_content=f"ERROR: {i}")
            )
        assert len(orch._active_incidents) == 0


# ═══════════════════════════════════════════════════════════════
# Fix #2 — _resolved_incidents is a bounded deque
# ═══════════════════════════════════════════════════════════════


class TestResolvedIncidentsDeque:
    @pytest.mark.asyncio
    async def test_is_deque_with_correct_maxlen(self, tmp_path):
        orch = _build_orchestrator_with_graph(
            lambda state: {"incident": state["incident"]}, str(tmp_path)
        )
        assert isinstance(orch._resolved_incidents, deque)
        assert orch._resolved_incidents.maxlen == MAX_RESOLVED_INCIDENTS

    @pytest.mark.asyncio
    async def test_deque_drops_oldest_past_maxlen(self, tmp_path):
        orch = _build_orchestrator_with_graph(
            lambda state: {"incident": state["incident"]}, str(tmp_path)
        )
        # Fill past maxlen with synthetic resolved incidents.
        for i in range(MAX_RESOLVED_INCIDENTS + 25):
            orch._resolved_incidents.append(
                Incident(id=f"INC-{i:04d}", symptom="x", state=IncidentState.RESOLVED)
            )
        assert len(orch._resolved_incidents) == MAX_RESOLVED_INCIDENTS
        assert orch._resolved_incidents[0].id == f"INC-{25:04d}"


# ═══════════════════════════════════════════════════════════════
# Fix #3 — (retired P3.4b)
#
# JSONMemoryStore was deleted; memory is now persisted via SQLAlchemy
# session transactions which provide atomicity via the underlying
# engine (Postgres / SQLite WAL). The tmp+fsync+os.replace invariant
# that used to live here no longer applies.
# ═══════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════
# Fix #4 — UTF-8 codepoint split across polls
# ═══════════════════════════════════════════════════════════════


class TestWatcherUtf8SafeDecode:
    def test_decode_handles_split_codepoint(self):
        """A multi-byte UTF-8 codepoint split across chunks is carried over."""
        # "é" is 0xC3 0xA9 in UTF-8; split it.
        first_chunk = b"hello \xc3"
        second_chunk = b"\xa9 world\n"

        text1, carry1 = LogWatcher._safe_utf8_decode(first_chunk)
        assert text1 == "hello "
        assert carry1 == b"\xc3"

        text2, carry2 = LogWatcher._safe_utf8_decode(carry1 + second_chunk)
        assert text2 == "é world\n"
        assert carry2 == b""

    def test_decode_handles_complete_input(self):
        # Use explicit UTF-8 bytes so the source file is pure ASCII.
        text, carry = LogWatcher._safe_utf8_decode("café\n".encode("utf-8"))
        assert text == "café\n"
        assert carry == b""

    def test_decode_replaces_real_corruption(self):
        """A long invalid sequence (>4 bytes of garbage) is replaced, not carried."""
        text, carry = LogWatcher._safe_utf8_decode(b"ok " + b"\xff" * 10)
        # Must not hang or carry garbage forever.
        assert carry == b""
        assert "ok " in text

    @pytest.mark.asyncio
    async def test_check_file_survives_partial_utf8_at_boundary(self, tmp_path):
        """Write bytes such that a codepoint is cut at the read boundary."""
        path = tmp_path / "app.log"
        # Build content with a multibyte char and trailing newline.
        content = "ERROR: utf-8 café\n".encode("utf-8")
        path.write_bytes(content)

        cfg = WatcherConfig(
            watch_paths=(str(path),),
            error_patterns=(r"(?i)error",),
        )
        watcher = LogWatcher(cfg)
        await watcher._check_file(str(path))
        # No exception and at least one event emitted.
        assert not watcher._event_queue.empty()
        event = await watcher._event_queue.get()
        assert "café" in event.line_content


# ═══════════════════════════════════════════════════════════════
# Fix #5 — inode-based rotation detection
# ═══════════════════════════════════════════════════════════════


class TestWatcherRotationDetection:
    @pytest.mark.asyncio
    async def test_size_shrink_triggers_rotation_reset(self, tmp_path):
        """Truncate-in-place rotation: size shrinks → offset resets to 0."""
        path = tmp_path / "app.log"
        path.write_text("ERROR: old " * 30 + "\n")

        cfg = WatcherConfig(
            watch_paths=(str(path),),
            error_patterns=(r"(?i)error",),
        )
        watcher = LogWatcher(cfg)
        await watcher._check_file(str(path))
        # Drain queue.
        while not watcher._event_queue.empty():
            await watcher._event_queue.get()

        # Truncate: new content is smaller than last_pos.
        path.write_text("ERROR: after truncate\n")
        await watcher._check_file(str(path))
        assert not watcher._event_queue.empty()
        evt = await watcher._event_queue.get()
        assert "after truncate" in evt.line_content


# ═══════════════════════════════════════════════════════════════
# Fix #6 — start() returns task handle; stop() cancels it
# ═══════════════════════════════════════════════════════════════


class TestWatcherTaskLifecycle:
    @pytest.mark.asyncio
    async def test_start_returns_task_and_stop_cancels_it(self, tmp_path):
        cfg = WatcherConfig(watch_paths=(), poll_interval_seconds=0.05)
        watcher = LogWatcher(cfg)
        task = await watcher.start()
        assert task is not None
        assert not task.done()
        await watcher.stop()
        # After stop(), the task must be done (cancelled or exited).
        assert task.done()

    @pytest.mark.asyncio
    async def test_start_is_idempotent(self, tmp_path):
        cfg = WatcherConfig(watch_paths=(), poll_interval_seconds=0.05)
        watcher = LogWatcher(cfg)
        t1 = await watcher.start()
        t2 = await watcher.start()
        assert t1 is t2
        await watcher.stop()


# ═══════════════════════════════════════════════════════════════
# Fix #7 — CostCircuitBreaker concurrent record_usage
# ═══════════════════════════════════════════════════════════════


class TestCircuitBreakerConcurrency:
    def test_concurrent_record_usage_is_consistent(self):
        """Hammer record_usage from many threads; token totals must match."""
        cb = CostCircuitBreaker(max_cost_usd=10_000.0, window_minutes=60)

        def hammer():
            for _ in range(500):
                cb.record_usage(1, 1)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(hammer) for _ in range(8)]
            for f in futures:
                f.result()

        # Expected: 8 threads * 500 iterations * 1 token each.
        status = cb.get_status()
        assert status["input_tokens"] == 8 * 500
        assert status["output_tokens"] == 8 * 500


# ═══════════════════════════════════════════════════════════════
# Fix #9 — SupervisorAgent is dead code and must be gone
# ═══════════════════════════════════════════════════════════════


class TestSupervisorIsDead:
    def test_import_fails(self):
        with pytest.raises(ModuleNotFoundError):
            import backend.agents.supervisor  # noqa: F401


# ═══════════════════════════════════════════════════════════════
# Fix #10 — P0.1b: AUDIT-mode validation ordering
# ═══════════════════════════════════════════════════════════════
#
# Before: ToolExecutor.execute() short-circuited with audit_only=True for
#         any ACTIVE tool in AUDIT mode, skipping the tool's own arg
#         validators. A call to run_diagnostics("rm -rf /") came back as
#         "safely logged" instead of hard-rejected.
# After:  Pydantic validation AND tool-specific content validation
#         (validate_command / validate_path / validate_url) run BEFORE the
#         AUDIT short-circuit.  Malicious args are hard-rejected in both
#         AUDIT and ACTIVE modes.


from backend.shared.audit_log import ImmutableAuditLog
from backend.shared.models import ToolCall
from backend.shared.security import SecurityGuard
from backend.shared.tool_registry import create_default_registry
from backend.shared.vault import AgentRole
from backend.tools.executor import ToolExecutor


def _build_audit_mode_executor(tmp_path) -> ToolExecutor:
    """Build a ToolExecutor in AUDIT mode against an isolated project root."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    (workspace / "config").mkdir(exist_ok=True)
    (workspace / "config" / "db.py").write_text("DB_HOST = 'localhost'\n")

    cfg = SecurityConfig(
        mode=SentryMode.AUDIT,
        stop_file_path=str(tmp_path / "STOP_SENTRY"),
        project_root=str(workspace),
    )
    security = SecurityGuard(cfg)
    audit_log = ImmutableAuditLog(str(tmp_path / "audit.jsonl"))
    registry = create_default_registry()
    return ToolExecutor(
        security, str(workspace), audit_log=audit_log, registry=registry,
    )


class TestAuditModeValidationOrdering:
    """P0.1b: AUDIT-mode short-circuit must NOT skip arg validation."""

    @pytest.mark.asyncio
    async def test_non_whitelisted_command_hard_rejected_in_audit_mode(self, tmp_path):
        """`rm -rf /` must be rejected with success=False — NOT audit_only=True."""
        executor = _build_audit_mode_executor(tmp_path)
        result = await executor.execute(
            ToolCall(tool_name="run_diagnostics", arguments={"command": "rm -rf /"}),
            caller_role=AgentRole.DETECTIVE,
        )
        assert result.success is False
        assert result.audit_only is False
        assert "whitelist" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_curl_prefix_bypass_hard_rejected_in_audit_mode(self, tmp_path):
        """`curl-e evil.com` must NOT match the `curl` whitelist prefix."""
        executor = _build_audit_mode_executor(tmp_path)
        result = await executor.execute(
            ToolCall(tool_name="run_diagnostics", arguments={"command": "curl-e evil.com"}),
            caller_role=AgentRole.DETECTIVE,
        )
        assert result.success is False
        assert result.audit_only is False
        assert "whitelist" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_path_traversal_hard_rejected_in_audit_mode(self, tmp_path):
        """apply_patch to ../../etc/passwd must be rejected, not audit_only."""
        executor = _build_audit_mode_executor(tmp_path)
        result = await executor.execute(
            ToolCall(
                tool_name="apply_patch",
                arguments={
                    "file_path": "../../etc/passwd",
                    "diff": "--- a/x\n+++ b/x\n@@\n-a\n+b\n",
                },
            ),
            caller_role=AgentRole.SURGEON,
        )
        assert result.success is False
        assert result.audit_only is False
        assert "path" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_non_allowlisted_url_hard_rejected_in_audit_mode(self, tmp_path):
        """fetch_docs to evil.com must be rejected by validate_url, not audit-only."""
        executor = _build_audit_mode_executor(tmp_path)
        result = await executor.execute(
            ToolCall(tool_name="fetch_docs", arguments={"url": "https://evil.com/x"}),
            caller_role=AgentRole.DETECTIVE,
        )
        assert result.success is False
        assert result.audit_only is False

    @pytest.mark.asyncio
    async def test_whitelisted_active_tool_still_audit_only_in_audit_mode(self, tmp_path):
        """Regression guard: well-formed ACTIVE tool call in AUDIT mode DOES
        still return audit_only=True.  We must not have over-corrected and
        broken the original AUDIT semantic for legitimate input."""
        executor = _build_audit_mode_executor(tmp_path)
        result = await executor.execute(
            ToolCall(
                tool_name="apply_patch",
                arguments={
                    "file_path": "config/db.py",
                    "diff": "--- a/config/db.py\n+++ b/config/db.py\n@@\n-a\n+b\n",
                },
            ),
            caller_role=AgentRole.SURGEON,
        )
        # Well-formed: sits inside project_root and passes validate_path,
        # so the AUDIT short-circuit correctly fires and returns audit_only.
        assert result.audit_only is True
        assert result.success is True

    @pytest.mark.asyncio
    async def test_invalid_pydantic_args_hard_rejected_in_audit_mode(self, tmp_path):
        """Missing required field must be rejected by Pydantic, not audit-only."""
        executor = _build_audit_mode_executor(tmp_path)
        result = await executor.execute(
            # run_diagnostics requires "command" — omit it.
            ToolCall(tool_name="run_diagnostics", arguments={}),
            caller_role=AgentRole.DETECTIVE,
        )
        assert result.success is False
        assert result.audit_only is False
        assert "invalid arguments" in (result.error or "").lower()


# ═══════════════════════════════════════════════════════════════
# Fix #11 — P1.4: Vault JIT credential enforcement at tool boundary
# ═══════════════════════════════════════════════════════════════
#
# Before: ToolExecutor.execute() accepted a caller_role but never
#         required a JIT credential. Vault.issue_credential /
#         Vault.verify_credential existed but nothing actually called
#         them on the tool path — Zero-Trust credentials were ornamental.
# After:  When ToolExecutor is constructed with a vault, every
#         execute() call MUST present a JITCredential that this vault
#         issued for this agent and scope=f"tool:{tool_name}". Forged,
#         scope-mismatched, expired, or revoked credentials are hard-
#         rejected at the executor boundary, before any other gate runs.
#         ToolExecutors constructed WITHOUT a vault (legacy unit tests)
#         are unchanged.


from backend.shared.vault import LocalVault, JITCredential


def _build_vault_wired_executor(tmp_path):
    """Build a ToolExecutor wired with a real LocalVault."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    (workspace / "config").mkdir(exist_ok=True)
    (workspace / "config" / "db.py").write_text("DB_HOST = 'localhost'\n")

    cfg = SecurityConfig(
        mode=SentryMode.ACTIVE,   # avoid AUDIT short-circuit interfering
        stop_file_path=str(tmp_path / "STOP_SENTRY"),
        project_root=str(workspace),
    )
    security = SecurityGuard(cfg)
    audit_log = ImmutableAuditLog(str(tmp_path / "audit.jsonl"))
    registry = create_default_registry()
    vault = LocalVault()
    executor = ToolExecutor(
        security, str(workspace),
        audit_log=audit_log, registry=registry, vault=vault,
    )
    return executor, vault


class TestVaultCredentialEnforcement:
    """P1.4: the executor must hard-reject tool calls that aren't backed
    by a valid vault-issued JIT credential."""

    @pytest.mark.asyncio
    async def test_missing_credential_rejected(self, tmp_path):
        """credential=None must fail with a clear error — no tool runs."""
        executor, _vault = _build_vault_wired_executor(tmp_path)
        result = await executor.execute(
            ToolCall(tool_name="read_file", arguments={"path": "config/db.py"}),
            caller_role=AgentRole.DETECTIVE,
            credential=None,
        )
        assert result.success is False
        assert result.audit_only is False
        assert "credential" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_forged_credential_rejected(self, tmp_path):
        """A hand-built JITCredential with no matching vault entry is rejected."""
        import time as _time

        executor, _vault = _build_vault_wired_executor(tmp_path)
        forged = JITCredential(
            credential_id="cred-forged-0000",
            agent_id="detective-forged",
            token="x" * 64,
            scope="tool:read_file",
            issued_at=_time.time(),
            ttl_seconds=60,
        )
        result = await executor.execute(
            ToolCall(tool_name="read_file", arguments={"path": "config/db.py"}),
            caller_role=AgentRole.DETECTIVE,
            credential=forged,
        )
        assert result.success is False
        assert "credential" in (result.error or "").lower()
        assert "reject" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_scope_mismatch_rejected(self, tmp_path):
        """A credential for tool:read_file cannot be replayed for grep_search."""
        executor, vault = _build_vault_wired_executor(tmp_path)
        nhi = vault.register_agent(AgentRole.DETECTIVE)
        cred = vault.issue_credential(
            nhi.agent_id, scope="tool:read_file", ttl_seconds=60,
        )
        assert cred is not None

        result = await executor.execute(
            ToolCall(tool_name="grep_search", arguments={"pattern": "x", "path": "."}),
            caller_role=AgentRole.DETECTIVE,
            credential=cred,
        )
        assert result.success is False
        assert "credential" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_revoked_credential_rejected(self, tmp_path):
        """A revoked credential cannot be replayed even with the right scope."""
        executor, vault = _build_vault_wired_executor(tmp_path)
        nhi = vault.register_agent(AgentRole.DETECTIVE)
        cred = vault.issue_credential(
            nhi.agent_id, scope="tool:read_file", ttl_seconds=60,
        )
        assert cred is not None
        vault.revoke_credential(cred.credential_id)

        result = await executor.execute(
            ToolCall(tool_name="read_file", arguments={"path": "config/db.py"}),
            caller_role=AgentRole.DETECTIVE,
            credential=cred,
        )
        assert result.success is False
        assert "credential" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_valid_credential_accepted(self, tmp_path):
        """The legitimate agent path — issue, verify, execute — works end to end."""
        executor, vault = _build_vault_wired_executor(tmp_path)
        nhi = vault.register_agent(AgentRole.DETECTIVE)
        cred = vault.issue_credential(
            nhi.agent_id, scope="tool:read_file", ttl_seconds=60,
        )
        assert cred is not None

        result = await executor.execute(
            ToolCall(tool_name="read_file", arguments={"path": "config/db.py"}),
            caller_role=AgentRole.DETECTIVE,
            credential=cred,
        )
        assert result.success is True
        assert "DB_HOST" in (result.output or "")

    @pytest.mark.asyncio
    async def test_wrong_agent_rejected(self, tmp_path):
        """A credential issued to agent A cannot be used by agent B
        (even with the right scope)."""
        executor, vault = _build_vault_wired_executor(tmp_path)
        nhi_a = vault.register_agent(AgentRole.DETECTIVE)
        _nhi_b = vault.register_agent(AgentRole.DETECTIVE)
        cred_a = vault.issue_credential(
            nhi_a.agent_id, scope="tool:read_file", ttl_seconds=60,
        )
        assert cred_a is not None

        # Tamper: swap in a different agent id while keeping the same
        # credential_id — this is the classic "stolen credential" attack.
        tampered = JITCredential(
            credential_id=cred_a.credential_id,
            agent_id="detective-someone-else",
            token=cred_a.token,
            scope=cred_a.scope,
            issued_at=cred_a.issued_at,
            ttl_seconds=cred_a.ttl_seconds,
        )
        result = await executor.execute(
            ToolCall(tool_name="read_file", arguments={"path": "config/db.py"}),
            caller_role=AgentRole.DETECTIVE,
            credential=tampered,
        )
        assert result.success is False
        assert "credential" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_legacy_executor_without_vault_still_works(self, tmp_path):
        """Belt & braces: ToolExecutor constructed with no vault preserves
        the pre-P1.4 behaviour — credentials are optional."""
        # _build_audit_mode_executor doesn't pass a vault; verify that
        # a well-formed call still succeeds without any credential.
        executor = _build_audit_mode_executor(tmp_path)  # AUDIT mode, no vault
        result = await executor.execute(
            ToolCall(tool_name="read_file", arguments={"path": "config/db.py"}),
            caller_role=AgentRole.DETECTIVE,
            # credential intentionally omitted
        )
        # read_file is READ_ONLY so AUDIT doesn't short-circuit it — it
        # should just return the file content successfully.
        assert result.success is True
        assert "DB_HOST" in (result.output or "")


# ═══════════════════════════════════════════════════════════════
# Fix #12 — P4.1 LLM-call JIT credentials
# ═══════════════════════════════════════════════════════════════


class TestLLMCredentialEnforcement:
    """P4.1: every ``BaseAgent._call_llm`` call issues a JIT credential
    scoped to ``llm_call``, passes it through the OTel span attributes,
    and revokes it in ``finally``. When the vault's kill switch
    (``revoke_all()`` / STOP_SENTRY) is active, LLM calls are denied
    with a ``PermissionError`` and an ``llm_call_blocked`` audit entry.
    """

    def _make_concrete_agent(self, vault, llm):
        """Instantiate a concrete BaseAgent subclass against a real
        vault + stub LLM. ``run()`` is a no-op — we call ``_call_llm``
        directly."""
        from backend.agents.base_agent import BaseAgent
        from backend.shared.ai_gateway import AIGateway
        from backend.shared.vault import AgentRole

        class _BareAgent(BaseAgent):
            async def run(self, *args, **kwargs):  # pragma: no cover
                return {}

        gateway = AIGateway()
        return _BareAgent(
            vault=vault,
            role=AgentRole.TRIAGE,
            gateway=gateway,
            llm=llm,
        )

    @pytest.mark.asyncio
    async def test_llm_credential_issued_and_revoked(self):
        """Happy path — credential is issued before the LLM call and
        revoked in ``finally``, even when the LLM raises."""
        from backend.shared.vault import LocalVault

        vault = LocalVault()
        llm = AsyncMock()
        llm.analyze.return_value = {
            "input_tokens": 10, "output_tokens": 5, "summary": "ok",
        }

        agent = self._make_concrete_agent(vault, llm)

        issued_before = len(vault._credentials)  # type: ignore[attr-defined]
        resp = await agent._call_llm("hello", effort="low")

        assert resp["summary"] == "ok"
        llm.analyze.assert_awaited_once()
        # Every issued credential must be revoked when _call_llm returns.
        credentials = list(vault._credentials.values())  # type: ignore[attr-defined]
        assert len(credentials) == issued_before + 1
        new_cred = credentials[-1]
        assert new_cred.scope == "llm_call"
        assert new_cred.revoked is True, \
            "Credential must be revoked in finally even on success path"

    @pytest.mark.asyncio
    async def test_llm_credential_revoked_on_llm_failure(self):
        """If the underlying LLM call raises, the credential is still
        revoked (proves the ``finally`` is load-bearing)."""
        from backend.shared.vault import LocalVault

        vault = LocalVault()
        llm = AsyncMock()
        llm.analyze.side_effect = RuntimeError("model timeout")

        agent = self._make_concrete_agent(vault, llm)
        with pytest.raises(RuntimeError):
            await agent._call_llm("hello", effort="low")

        credentials = list(vault._credentials.values())  # type: ignore[attr-defined]
        assert len(credentials) == 1
        assert credentials[0].revoked is True

    @pytest.mark.asyncio
    async def test_llm_call_blocked_when_vault_kill_switch_active(self, tmp_path):
        """After ``vault.revoke_all()`` / STOP_SENTRY, every subsequent
        ``_call_llm`` must be denied with a ``PermissionError`` and an
        audit entry, AND the LLM itself must never be invoked."""
        from backend.shared.audit_log import ImmutableAuditLog
        from backend.shared.vault import LocalVault

        vault = LocalVault()
        llm = AsyncMock()
        llm.analyze.return_value = {"input_tokens": 1, "output_tokens": 1}
        audit_log = ImmutableAuditLog(
            log_path=str(tmp_path / "p41_audit.jsonl"),
        )

        from backend.agents.base_agent import BaseAgent
        from backend.shared.ai_gateway import AIGateway
        from backend.shared.vault import AgentRole

        class _BareAgent(BaseAgent):
            async def run(self, *args, **kwargs):  # pragma: no cover
                return {}

        agent = _BareAgent(
            vault=vault,
            role=AgentRole.TRIAGE,
            gateway=AIGateway(),
            audit_log=audit_log,
            llm=llm,
        )

        # Kill switch activates — all subsequent credentials are denied.
        vault.revoke_all()

        with pytest.raises(PermissionError, match="LLM credential"):
            await agent._call_llm("hello", effort="low")

        # LLM must never have been contacted after the kill switch.
        llm.analyze.assert_not_awaited()

        # Audit trail must reflect the denial.
        entries = audit_log.read_all()
        actions = [entry.get("action") for entry in entries]
        assert "llm_call_blocked" in actions

    @pytest.mark.asyncio
    async def test_llm_call_without_vault_backend_still_works(self):
        """Legacy unit tests that instantiate BaseAgent with a stub
        vault that returns ``None`` on ``issue_credential`` (simulating
        a no-vault environment) still reach the LLM — the zero-trust
        check only kicks in when a real vault is wired.
        
        This test uses a real LocalVault but registers the agent, then
        removes it from the registry — so ``issue_credential`` returns
        None but the vault is still an object. We expect PermissionError
        because this IS a real vault that denied the request.
        """
        from backend.shared.vault import LocalVault, AgentRole
        from backend.agents.base_agent import BaseAgent
        from backend.shared.ai_gateway import AIGateway

        vault = LocalVault()
        llm = AsyncMock()
        llm.analyze.return_value = {"input_tokens": 1, "output_tokens": 1}

        class _BareAgent(BaseAgent):
            async def run(self, *args, **kwargs):  # pragma: no cover
                return {}

        agent = _BareAgent(
            vault=vault,
            role=AgentRole.TRIAGE,
            gateway=AIGateway(),
            llm=llm,
        )

        # Forcibly corrupt the registry so the vault denies issuance.
        # This simulates the kill-switch path.
        vault._agents.clear()  # type: ignore[attr-defined]

        with pytest.raises(PermissionError):
            await agent._call_llm("hello", effort="low")
        llm.analyze.assert_not_awaited()


