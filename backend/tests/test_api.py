"""
TDD tests for FastAPI endpoints.
Tests ALL API endpoints by mocking global state (_orchestrator, _watcher, _config).
"""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone

from backend.api.app import app
from backend.shared.models import Incident, IncidentState, MemoryEntry, LogEvent
from backend.shared.config import (
    AppConfig, SecurityConfig, SentryMode, WatcherConfig,
    MemoryConfig, AnthropicConfig, BedrockGatewayConfig, LLMProvider,
)


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _make_config(provider=LLMProvider.ANTHROPIC, mode=SentryMode.AUDIT):
    """Create a minimal AppConfig for tests."""
    return AppConfig(
        security=SecurityConfig(mode=mode, project_root="/tmp/test",
                                stop_file_path="/tmp/test/STOP_SENTRY"),
        anthropic=AnthropicConfig(model="claude-test"),
        bedrock_gateway=BedrockGatewayConfig(model="bedrock-test"),
        llm_provider=provider,
        watcher=WatcherConfig(watch_paths=("/tmp/logs/*.log",)),
        memory=MemoryConfig(file_path="/tmp/test/memory.json"),
        log_level="INFO",
        environment="test",
    )


def _make_orchestrator():
    """Create a mock orchestrator with realistic attributes."""
    orch = AsyncMock()
    orch._active_incidents = {}
    orch._resolved_incidents = []
    orch._memory = AsyncMock()
    orch._memory.load = AsyncMock(return_value=[])
    orch._memory.get_fingerprint = AsyncMock(return_value="fp-abc123")
    orch._tools = MagicMock()
    orch._tools.get_tool_definitions = MagicMock(return_value=[
        {"name": "read_file", "description": "Read a file", "input_schema": {"type": "object"}},
    ])
    orch._cb = MagicMock()
    orch._cb.get_status = MagicMock(return_value={"tripped": False, "cost_usd": 0.0})
    orch.get_status = AsyncMock(return_value={
        "active_incidents": 0,
        "resolved_total": 0,
        "circuit_breaker": {"tripped": False},
        "mode": "AUDIT",
    })
    orch.get_active_incidents = AsyncMock(return_value=[])
    return orch


def _make_watcher(running=False):
    """Create a mock watcher."""
    w = AsyncMock()
    w._running = running
    w.start = AsyncMock()
    w.stop = AsyncMock()
    return w


@pytest.mark.asyncio
class TestHealthEndpoint:
    async def test_health_returns_ok(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert "timestamp" in data


# ═══════════════════════════════════════════════════════════════
# STATUS ENDPOINT
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestStatusEndpoint:
    async def test_status_returns_503_when_no_orchestrator(self):
        with patch("backend.api.app._orchestrator", None), \
             patch("backend.api.app._watcher", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/status")
                assert resp.status_code == 503

    async def test_status_returns_ok(self):
        orch = _make_orchestrator()
        watcher = _make_watcher(running=True)
        with patch("backend.api.app._orchestrator", orch), \
             patch("backend.api.app._watcher", watcher):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/status")
                assert resp.status_code == 200
                data = resp.json()
                assert "active_incidents" in data
                assert data["watcher_running"] is True

    async def test_status_watcher_none(self):
        orch = _make_orchestrator()
        with patch("backend.api.app._orchestrator", orch), \
             patch("backend.api.app._watcher", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/status")
                assert resp.status_code == 200
                assert resp.json()["watcher_running"] is False


# ═══════════════════════════════════════════════════════════════
# INCIDENTS ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestIncidentsEndpoint:
    async def test_incidents_returns_503_when_not_ready(self):
        with patch("backend.api.app._orchestrator", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/incidents")
                assert resp.status_code == 503

    async def test_incidents_returns_active_and_resolved(self):
        orch = _make_orchestrator()
        inc = Incident(id="INC-001", symptom="test error", state=IncidentState.TRIAGE)
        orch.get_active_incidents = AsyncMock(return_value=[inc])
        resolved = Incident(id="INC-000", symptom="old error", state=IncidentState.RESOLVED)
        orch._resolved_incidents = [resolved]

        with patch("backend.api.app._orchestrator", orch):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/incidents")
                assert resp.status_code == 200
                data = resp.json()
                assert len(data["active"]) == 1
                assert data["active"][0]["id"] == "INC-001"
                assert len(data["resolved"]) == 1


@pytest.mark.asyncio
class TestIncidentDetailEndpoint:
    async def test_detail_returns_503_when_not_ready(self):
        with patch("backend.api.app._orchestrator", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/incidents/INC-001")
                assert resp.status_code == 503

    async def test_detail_returns_active_incident(self):
        orch = _make_orchestrator()
        inc = Incident(id="INC-001", symptom="test error")
        orch._active_incidents = {"INC-001": inc}

        with patch("backend.api.app._orchestrator", orch):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/incidents/INC-001")
                assert resp.status_code == 200
                assert resp.json()["id"] == "INC-001"

    async def test_detail_returns_resolved_incident(self):
        orch = _make_orchestrator()
        resolved = Incident(id="INC-002", symptom="old", state=IncidentState.RESOLVED)
        orch._resolved_incidents = [resolved]

        with patch("backend.api.app._orchestrator", orch):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/incidents/INC-002")
                assert resp.status_code == 200
                assert resp.json()["id"] == "INC-002"

    async def test_detail_returns_404_for_unknown(self):
        orch = _make_orchestrator()
        with patch("backend.api.app._orchestrator", orch):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/incidents/INC-MISSING")
                assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════
# TRIGGER ENDPOINT
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestTriggerEndpoint:
    async def test_trigger_returns_503_when_not_ready(self):
        with patch("backend.api.app._orchestrator", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/trigger", json={"message": "test"})
                assert resp.status_code == 503

    async def test_trigger_returns_incident(self):
        orch = _make_orchestrator()
        inc = Incident(id="INC-T01", symptom="triggered error")
        orch.handle_event = AsyncMock(return_value=inc)

        with patch("backend.api.app._orchestrator", orch):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/trigger", json={"message": "test error", "source": "manual"})
                assert resp.status_code == 200
                data = resp.json()
                assert data["incident"]["id"] == "INC-T01"

    async def test_trigger_returns_none_when_circuit_breaker(self):
        orch = _make_orchestrator()
        orch.handle_event = AsyncMock(return_value=None)

        with patch("backend.api.app._orchestrator", orch):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/trigger", json={"message": "test"})
                assert resp.status_code == 200
                data = resp.json()
                assert data["incident"] is None
                assert "Circuit breaker" in data["message"]


# ═══════════════════════════════════════════════════════════════
# MEMORY ENDPOINT
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestMemoryEndpoint:
    async def test_memory_returns_503_when_not_ready(self):
        with patch("backend.api.app._orchestrator", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/memory")
                assert resp.status_code == 503

    async def test_memory_returns_entries(self):
        orch = _make_orchestrator()
        entry = MemoryEntry(id="MEM-1", symptom="err", root_cause="rc", fix="f")
        orch._memory.load = AsyncMock(return_value=[entry])

        with patch("backend.api.app._orchestrator", orch):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/memory")
                assert resp.status_code == 200
                data = resp.json()
                assert data["count"] == 1
                assert data["fingerprint"] == "fp-abc123"


# ═══════════════════════════════════════════════════════════════
# TOOLS ENDPOINT
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestToolsEndpoint:
    async def test_tools_returns_503_when_not_ready(self):
        with patch("backend.api.app._orchestrator", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/tools")
                assert resp.status_code == 503

    async def test_tools_returns_definitions(self):
        orch = _make_orchestrator()
        with patch("backend.api.app._orchestrator", orch):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/tools")
                assert resp.status_code == 200
                data = resp.json()
                assert len(data["tools"]) == 1
                assert data["tools"][0]["name"] == "read_file"


# ═══════════════════════════════════════════════════════════════
# WATCHER START/STOP ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestWatcherEndpoints:
    async def test_watcher_start_returns_503_when_not_ready(self):
        with patch("backend.api.app._watcher", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/watcher/start")
                assert resp.status_code == 503

    async def test_watcher_start_already_running(self):
        watcher = _make_watcher(running=True)
        with patch("backend.api.app._watcher", watcher):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/watcher/start")
                assert resp.status_code == 200
                assert resp.json()["status"] == "already_running"

    async def test_watcher_start_success(self):
        watcher = _make_watcher(running=False)
        with patch("backend.api.app._watcher", watcher), \
             patch("backend.api.app._watcher_event_loop", new_callable=AsyncMock):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/watcher/start")
                assert resp.status_code == 200
                assert resp.json()["status"] == "started"
                watcher.start.assert_awaited_once()

    async def test_watcher_stop_returns_503_when_not_ready(self):
        with patch("backend.api.app._watcher", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/watcher/stop")
                assert resp.status_code == 503

    async def test_watcher_stop_success(self):
        watcher = _make_watcher(running=True)
        with patch("backend.api.app._watcher", watcher), \
             patch("backend.api.app._watcher_task", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/watcher/stop")
                assert resp.status_code == 200
                assert resp.json()["status"] == "stopped"
                watcher.stop.assert_awaited_once()

    async def test_watcher_stop_cancels_running_task(self):
        watcher = _make_watcher(running=True)
        mock_task = MagicMock()
        mock_task.done.return_value = False
        mock_task.cancel = MagicMock()

        with patch("backend.api.app._watcher", watcher), \
             patch("backend.api.app._watcher_task", mock_task):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/watcher/stop")
                assert resp.status_code == 200
                mock_task.cancel.assert_called_once()


# ═══════════════════════════════════════════════════════════════
# CONFIG ENDPOINT
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestConfigEndpoint:
    async def test_config_returns_503_when_not_ready(self):
        with patch("backend.api.app._config", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/config")
                assert resp.status_code == 503

    async def test_config_anthropic_provider(self):
        cfg = _make_config(provider=LLMProvider.ANTHROPIC)
        with patch("backend.api.app._config", cfg):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/config")
                assert resp.status_code == 200
                data = resp.json()
                assert data["llm_provider"] == "anthropic"
                assert data["model"] == "claude-test"
                assert data["mode"] == "AUDIT"
                assert data["log_level"] == "INFO"
                assert data["environment"] == "test"

    async def test_config_bedrock_provider(self):
        cfg = _make_config(provider=LLMProvider.BEDROCK_GATEWAY)
        with patch("backend.api.app._config", cfg):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/config")
                assert resp.status_code == 200
                data = resp.json()
                assert data["llm_provider"] == "bedrock_gateway"
                assert data["model"] == "bedrock-test"


# ═══════════════════════════════════════════════════════════════
# SECURITY ENDPOINT
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestSecurityEndpoint:
    async def test_security_returns_503_when_not_ready(self):
        with patch("backend.api.app._config", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/security")
                assert resp.status_code == 503

    async def test_security_returns_full_posture(self):
        cfg = _make_config()
        orch = _make_orchestrator()
        with patch("backend.api.app._config", cfg), \
             patch("backend.api.app._orchestrator", orch):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/security")
                assert resp.status_code == 200
                data = resp.json()
                assert "zero_trust" in data
                assert data["zero_trust"]["vault"] == "active"
                assert data["mode"] == "AUDIT"
                assert "agent_roles" in data
                assert "security_layers" in data
                assert len(data["security_layers"]) == 10
                assert "circuit_breaker" in data

    async def test_security_without_orchestrator(self):
        cfg = _make_config()
        with patch("backend.api.app._config", cfg), \
             patch("backend.api.app._orchestrator", None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/security")
                assert resp.status_code == 200
                data = resp.json()
                assert data["circuit_breaker"] == {}
