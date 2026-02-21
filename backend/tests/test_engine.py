"""
Tests for the Orchestrator engine — full lifecycle, handle_event, memory, status.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from datetime import datetime, timezone

from backend.orchestrator.engine import Orchestrator, MAX_RESOLVED_INCIDENTS
from backend.shared.models import Incident, IncidentState, LogEvent, MemoryEntry
from backend.shared.config import (
    AppConfig, SecurityConfig, SentryMode, MemoryConfig, WatcherConfig,
)
from backend.shared.circuit_breaker import CostCircuitBreaker


# ═══════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════

def _make_config(project_root="/tmp/test"):
    return AppConfig(
        security=SecurityConfig(mode=SentryMode.AUDIT, project_root=project_root),
        memory=MemoryConfig(file_path="/tmp/test/mem.json", max_incidents_before_compaction=50),
        watcher=WatcherConfig(watch_paths=()),
        service_source_path=project_root,
    )


def _make_mock_graph(final_state=None):
    """Create a mock LangGraph compiled graph."""
    graph = AsyncMock()
    if final_state:
        graph.ainvoke = AsyncMock(return_value=final_state)
    return graph


@pytest.fixture
def mock_llm():
    return AsyncMock()


@pytest.fixture
def mock_tools():
    tools = AsyncMock()
    tools.get_tool_definitions = MagicMock(return_value=[])
    return tools


@pytest.fixture
def mock_memory():
    mem = AsyncMock()
    mem.save = AsyncMock()
    mem.load = AsyncMock(return_value=[])
    mem.get_count = AsyncMock(return_value=0)
    mem.get_fingerprint = AsyncMock(return_value="")
    mem.system_fingerprint = ""
    return mem


@pytest.fixture
def circuit_breaker():
    return CostCircuitBreaker(max_cost_usd=5.0, window_minutes=10)


@pytest.fixture
def log_event():
    return LogEvent(
        source_file="test.log",
        line_content="ERROR: Connection refused on port 5432",
        timestamp=datetime.now(timezone.utc),
        matched_pattern="(?i)error",
    )


# ═══════════════════════════════════════════════════════════════
# RESOLVED LIST CAP TESTS
# ═══════════════════════════════════════════════════════════════

class TestResolvedListCap:
    """Tests for production hardening #4: FIFO cap on resolved incidents list."""

    def test_max_resolved_constant(self):
        assert MAX_RESOLVED_INCIDENTS == 100

    def test_resolved_list_capped_at_max(self):
        resolved = []
        for i in range(MAX_RESOLVED_INCIDENTS + 20):
            incident = Incident(
                id=f"INC-{i:04d}",
                symptom=f"Test error {i}",
                state=IncidentState.RESOLVED,
            )
            resolved.append(incident)
            if len(resolved) > MAX_RESOLVED_INCIDENTS:
                resolved = resolved[-MAX_RESOLVED_INCIDENTS:]

        assert len(resolved) == MAX_RESOLVED_INCIDENTS
        assert resolved[0].id == "INC-0020"
        assert resolved[-1].id == "INC-0119"

    def test_under_cap_no_truncation(self):
        resolved = []
        for i in range(50):
            incident = Incident(
                id=f"INC-{i:04d}",
                symptom=f"Test error {i}",
                state=IncidentState.RESOLVED,
            )
            resolved.append(incident)
            if len(resolved) > MAX_RESOLVED_INCIDENTS:
                resolved = resolved[-MAX_RESOLVED_INCIDENTS:]

        assert len(resolved) == 50
        assert resolved[0].id == "INC-0000"

    def test_exactly_at_cap_no_truncation(self):
        resolved = []
        for i in range(MAX_RESOLVED_INCIDENTS):
            incident = Incident(
                id=f"INC-{i:04d}",
                symptom=f"Test error {i}",
                state=IncidentState.RESOLVED,
            )
            resolved.append(incident)
            if len(resolved) > MAX_RESOLVED_INCIDENTS:
                resolved = resolved[-MAX_RESOLVED_INCIDENTS:]

        assert len(resolved) == MAX_RESOLVED_INCIDENTS
        assert resolved[0].id == "INC-0000"


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR INIT TESTS
# ═══════════════════════════════════════════════════════════════

class TestOrchestratorInit:
    """Tests for Orchestrator.__init__."""

    def test_init_with_service_context(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        config = _make_config()
        mock_registry = MagicMock()
        mock_registry.has_context.return_value = True
        mock_registry.build_fingerprint.return_value = "test-fp"

        mock_builder = MagicMock()
        mock_builder.build.return_value = MagicMock()

        with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
             patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
            orch = Orchestrator(config, mock_llm, mock_tools, mock_memory, circuit_breaker)

        assert orch._config is config
        assert orch._active_incidents == {}
        assert orch._resolved_incidents == []
        mock_registry.build_fingerprint.assert_called_once()

    def test_init_without_service_context(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        config = _make_config()
        mock_registry = MagicMock()
        mock_registry.has_context.return_value = False

        mock_builder = MagicMock()
        mock_builder.build.return_value = MagicMock()

        with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
             patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
            orch = Orchestrator(config, mock_llm, mock_tools, mock_memory, circuit_breaker)

        mock_registry.build_fingerprint.assert_not_called()


# ═══════════════════════════════════════════════════════════════
# HANDLE_EVENT TESTS
# ═══════════════════════════════════════════════════════════════

class TestHandleEvent:
    """Tests for Orchestrator.handle_event."""

    def _make_orchestrator(self, mock_llm, mock_tools, mock_memory, circuit_breaker,
                           final_incident_state=IncidentState.RESOLVED):
        config = _make_config()
        mock_registry = MagicMock()
        mock_registry.has_context.return_value = False
        mock_registry.build_prompt_context.return_value = ""

        # Build a mock graph that returns the incident in the specified state
        def ainvoke_side_effect(state):
            incident = state["incident"]
            incident.state = final_incident_state
            incident.root_cause = "DB down"
            incident.fix_applied = "Restarted DB"
            return {"incident": incident}

        mock_graph = AsyncMock()
        mock_graph.ainvoke = AsyncMock(side_effect=ainvoke_side_effect)

        mock_builder = MagicMock()
        mock_builder.build.return_value = mock_graph

        with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
             patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
            return Orchestrator(config, mock_llm, mock_tools, mock_memory, circuit_breaker)

    @pytest.mark.asyncio
    async def test_circuit_breaker_tripped_skips(self, mock_llm, mock_tools, mock_memory, log_event):
        cb = CostCircuitBreaker(max_cost_usd=0.0, window_minutes=10)
        cb._is_tripped = True
        orch = self._make_orchestrator(mock_llm, mock_tools, mock_memory, cb)
        # Manually trip
        orch._cb._is_tripped = True
        # Need to mock is_tripped property
        with patch.object(type(orch._cb), 'is_tripped', new_callable=PropertyMock, return_value=True):
            result = await orch.handle_event(log_event)
        assert result is None

    @pytest.mark.asyncio
    async def test_resolved_incident_saved_to_memory(self, mock_llm, mock_tools, mock_memory, circuit_breaker, log_event):
        orch = self._make_orchestrator(
            mock_llm, mock_tools, mock_memory, circuit_breaker,
            final_incident_state=IncidentState.RESOLVED,
        )
        result = await orch.handle_event(log_event)

        assert result is not None
        assert result.state == IncidentState.RESOLVED
        mock_memory.save.assert_awaited_once()
        assert len(orch._resolved_incidents) == 1
        assert len(orch._active_incidents) == 0

    @pytest.mark.asyncio
    async def test_idle_incident_removed_from_active(self, mock_llm, mock_tools, mock_memory, circuit_breaker, log_event):
        orch = self._make_orchestrator(
            mock_llm, mock_tools, mock_memory, circuit_breaker,
            final_incident_state=IncidentState.IDLE,
        )
        result = await orch.handle_event(log_event)

        assert result is not None
        assert result.state == IncidentState.IDLE
        assert len(orch._active_incidents) == 0
        assert len(orch._resolved_incidents) == 0

    @pytest.mark.asyncio
    async def test_escalated_incident_stays_active(self, mock_llm, mock_tools, mock_memory, circuit_breaker, log_event):
        orch = self._make_orchestrator(
            mock_llm, mock_tools, mock_memory, circuit_breaker,
            final_incident_state=IncidentState.ESCALATED,
        )
        result = await orch.handle_event(log_event)

        assert result is not None
        assert result.state == IncidentState.ESCALATED
        # Escalated stays in active (not deleted unless RESOLVED or IDLE)
        assert len(orch._active_incidents) == 1

    @pytest.mark.asyncio
    async def test_exception_sets_escalated(self, mock_llm, mock_tools, mock_memory, circuit_breaker, log_event):
        config = _make_config()
        mock_registry = MagicMock()
        mock_registry.has_context.return_value = False
        mock_registry.build_prompt_context.return_value = ""

        mock_graph = AsyncMock()
        mock_graph.ainvoke = AsyncMock(side_effect=RuntimeError("Graph crashed"))

        mock_builder = MagicMock()
        mock_builder.build.return_value = mock_graph

        with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
             patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
            orch = Orchestrator(config, mock_llm, mock_tools, mock_memory, circuit_breaker)

        result = await orch.handle_event(log_event)
        assert result.state == IncidentState.ESCALATED

    @pytest.mark.asyncio
    async def test_fifo_cap_on_resolved(self, mock_llm, mock_tools, mock_memory, circuit_breaker, log_event):
        orch = self._make_orchestrator(
            mock_llm, mock_tools, mock_memory, circuit_breaker,
            final_incident_state=IncidentState.RESOLVED,
        )
        # Pre-fill with MAX incidents
        for i in range(MAX_RESOLVED_INCIDENTS):
            orch._resolved_incidents.append(
                Incident(id=f"OLD-{i}", symptom="old", state=IncidentState.RESOLVED)
            )

        result = await orch.handle_event(log_event)
        assert len(orch._resolved_incidents) == MAX_RESOLVED_INCIDENTS
        # The newest should be at the end
        assert orch._resolved_incidents[-1].id == result.id


# ═══════════════════════════════════════════════════════════════
# SAVE TO MEMORY TESTS
# ═══════════════════════════════════════════════════════════════

class TestSaveToMemory:
    """Tests for Orchestrator._save_to_memory."""

    @pytest.mark.asyncio
    async def test_save_creates_memory_entry(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        config = _make_config()
        mock_registry = MagicMock()
        mock_registry.has_context.return_value = False
        mock_builder = MagicMock()
        mock_builder.build.return_value = MagicMock()

        with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
             patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
            orch = Orchestrator(config, mock_llm, mock_tools, mock_memory, circuit_breaker)

        incident = Incident(
            id="INC-SAVE", symptom="test error",
            root_cause="Bad config", fix_applied="Fixed config",
            vectors=["config", "error"],
        )
        await orch._save_to_memory(incident)
        mock_memory.save.assert_awaited_once()
        saved_entry = mock_memory.save.call_args[0][0]
        assert saved_entry.id == "INC-SAVE"
        assert saved_entry.root_cause == "Bad config"

    @pytest.mark.asyncio
    async def test_save_with_compaction_threshold(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        config = AppConfig(
            security=SecurityConfig(mode=SentryMode.AUDIT, project_root="/tmp"),
            memory=MemoryConfig(file_path="/tmp/mem.json", max_incidents_before_compaction=5),
        )
        mock_memory.get_count = AsyncMock(return_value=10)  # Over threshold

        mock_registry = MagicMock()
        mock_registry.has_context.return_value = False
        mock_builder = MagicMock()
        mock_builder.build.return_value = MagicMock()

        with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
             patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
            orch = Orchestrator(config, mock_llm, mock_tools, mock_memory, circuit_breaker)

        incident = Incident(id="INC-CMP", symptom="err", root_cause="rc", fix_applied="fx")
        await orch._save_to_memory(incident)
        # Just verify it doesn't crash — compaction is logged but not yet implemented
        mock_memory.save.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_save_with_no_root_cause(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        config = _make_config()
        mock_registry = MagicMock()
        mock_registry.has_context.return_value = False
        mock_builder = MagicMock()
        mock_builder.build.return_value = MagicMock()

        with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
             patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
            orch = Orchestrator(config, mock_llm, mock_tools, mock_memory, circuit_breaker)

        incident = Incident(id="INC-NRC", symptom="test error")
        await orch._save_to_memory(incident)
        saved = mock_memory.save.call_args[0][0]
        assert saved.root_cause == "Unknown"
        assert saved.fix == "None"


# ═══════════════════════════════════════════════════════════════
# GET STATUS / GET ACTIVE INCIDENTS
# ═══════════════════════════════════════════════════════════════

class TestOrchestratorStatus:
    def _build_orch(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        config = _make_config()
        mock_registry = MagicMock()
        mock_registry.has_context.return_value = False
        mock_builder = MagicMock()
        mock_builder.build.return_value = MagicMock()

        with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
             patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
            return Orchestrator(config, mock_llm, mock_tools, mock_memory, circuit_breaker)

    @pytest.mark.asyncio
    async def test_get_active_incidents_empty(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        orch = self._build_orch(mock_llm, mock_tools, mock_memory, circuit_breaker)
        result = await orch.get_active_incidents()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_active_incidents_with_data(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        orch = self._build_orch(mock_llm, mock_tools, mock_memory, circuit_breaker)
        inc = Incident(id="INC-ACT", symptom="test")
        orch._active_incidents["INC-ACT"] = inc
        result = await orch.get_active_incidents()
        assert len(result) == 1
        assert result[0].id == "INC-ACT"

    @pytest.mark.asyncio
    async def test_get_status(self, mock_llm, mock_tools, mock_memory, circuit_breaker):
        orch = self._build_orch(mock_llm, mock_tools, mock_memory, circuit_breaker)
        orch._active_incidents["INC-1"] = Incident(id="INC-1", symptom="err")
        orch._resolved_incidents = [Incident(id="INC-0", symptom="old", state=IncidentState.RESOLVED)]

        status = await orch.get_status()
        assert status["active_incidents"] == 1
        assert status["resolved_total"] == 1
        assert "circuit_breaker" in status
        assert status["mode"] == "AUDIT"
