"""
Tests for shared/models.py — domain model serialization and behavior.
"""

import pytest
from datetime import datetime, timezone

from backend.shared.models import (
    LogEvent, ActivityEntry, ActivityType, Incident,
    IncidentState, IncidentSeverity, ToolCall, ToolCategory,
    ToolResult, MemoryEntry, CostTracker,
)


class TestLogEvent:
    def test_to_dict(self):
        evt = LogEvent(
            source_file="/var/log/app.log",
            line_content="ERROR: connection refused",
            matched_pattern=r"(?i)error",
            line_number=42,
        )
        d = evt.to_dict()
        assert d["source_file"] == "/var/log/app.log"
        assert d["line_content"] == "ERROR: connection refused"
        assert d["matched_pattern"] == r"(?i)error"
        assert d["line_number"] == 42
        assert "timestamp" in d

    def test_default_timestamp_is_utc(self):
        evt = LogEvent(source_file="test.log", line_content="error")
        assert evt.timestamp.tzinfo is not None


class TestActivityEntry:
    def test_to_dict(self):
        entry = ActivityEntry(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            activity_type=ActivityType.TOOL_CALL,
            phase="diagnosis",
            title="Called read_file",
            detail="Reading config/db.py",
            metadata={"tool": "read_file"},
        )
        d = entry.to_dict()
        assert d["activity_type"] == "tool_call"
        assert d["phase"] == "diagnosis"
        assert d["title"] == "Called read_file"
        assert d["metadata"]["tool"] == "read_file"

    def test_to_dict_truncates_detail(self):
        entry = ActivityEntry(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            activity_type=ActivityType.LLM_CALL,
            phase="triage",
            title="LLM analysis",
            detail="x" * 2000,
        )
        d = entry.to_dict()
        assert len(d["detail"]) == 1000


class TestIncident:
    def test_log_activity(self):
        inc = Incident(id="INC-001", symptom="502 error")
        inc.log_activity(ActivityType.PHASE_START, "triage", "Starting triage")
        assert len(inc.activity_log) == 1
        assert inc.activity_log[0].title == "Starting triage"

    def test_to_dict_basic(self):
        inc = Incident(id="INC-001", symptom="502 error")
        d = inc.to_dict()
        assert d["id"] == "INC-001"
        assert d["symptom"] == "502 error"
        assert d["state"] == "triage"
        assert d["severity"] == "medium"
        assert "phase_summary" in d

    def test_to_dict_with_log_event_dict(self):
        inc = Incident(
            id="INC-001", symptom="error",
            log_events=[{"source_file": "test.log", "line_content": "err"}],
        )
        d = inc.to_dict()
        assert d["log_events"][0]["source_file"] == "test.log"

    def test_to_dict_with_log_event_object(self):
        evt = LogEvent(source_file="test.log", line_content="error")
        inc = Incident(id="INC-001", symptom="error", log_events=[evt])
        d = inc.to_dict()
        assert d["log_events"][0]["source_file"] == "test.log"

    def test_to_dict_with_resolved_at(self):
        inc = Incident(
            id="INC-001", symptom="error",
            resolved_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        d = inc.to_dict()
        assert d["resolved_at"] is not None

    def test_phase_summary_triage(self):
        inc = Incident(id="INC-001", symptom="err", state=IncidentState.TRIAGE)
        d = inc.to_dict()
        assert d["phase_summary"]["triage"] == "active"
        assert d["phase_summary"]["diagnosis"] == "pending"

    def test_phase_summary_diagnosis(self):
        inc = Incident(id="INC-001", symptom="err", state=IncidentState.DIAGNOSIS)
        d = inc.to_dict()
        assert d["phase_summary"]["triage"] == "complete"
        assert d["phase_summary"]["diagnosis"] == "active"

    def test_phase_summary_resolved(self):
        inc = Incident(id="INC-001", symptom="err", state=IncidentState.RESOLVED)
        d = inc.to_dict()
        for phase in ["triage", "diagnosis", "remediation", "verification"]:
            assert d["phase_summary"][phase] == "complete"
        assert d["phase_summary"]["outcome"] == "resolved"

    def test_phase_summary_escalated(self):
        inc = Incident(id="INC-001", symptom="err", state=IncidentState.ESCALATED)
        d = inc.to_dict()
        assert d["phase_summary"]["outcome"] == "escalated"


class TestToolResult:
    def test_to_dict(self):
        tr = ToolResult(tool_name="read_file", success=True, output="file contents")
        d = tr.to_dict()
        assert d["tool_name"] == "read_file"
        assert d["success"] is True
        assert d["output"] == "file contents"

    def test_to_dict_truncates_output(self):
        tr = ToolResult(tool_name="read_file", success=True, output="x" * 1000)
        d = tr.to_dict()
        assert len(d["output"]) == 500


class TestMemoryEntry:
    def test_to_dict(self):
        me = MemoryEntry(
            id="INC-001", symptom="error", root_cause="OOM",
            fix="restart", vectors=["error", "oom"],
        )
        d = me.to_dict()
        assert d["id"] == "INC-001"
        assert d["root_cause"] == "OOM"

    def test_from_dict(self):
        data = {
            "id": "INC-001", "symptom": "error", "root_cause": "OOM",
            "fix": "restart", "vectors": ["error"], "timestamp": "2025-01-01",
        }
        me = MemoryEntry.from_dict(data)
        assert me.id == "INC-001"
        assert me.root_cause == "OOM"
        assert me.vectors == ["error"]

    def test_from_dict_missing_fields(self):
        me = MemoryEntry.from_dict({})
        assert me.id == ""
        assert me.symptom == ""


class TestCostTracker:
    def test_initial_cost_is_zero(self):
        ct = CostTracker()
        assert ct.estimated_cost_usd == 0.0

    def test_add_usage(self):
        ct = CostTracker()
        ct.add_usage(1000, 500)
        assert ct.total_input_tokens == 1000
        assert ct.total_output_tokens == 500
        assert ct.estimated_cost_usd > 0

    def test_estimated_cost_calculation(self):
        ct = CostTracker()
        ct.add_usage(10000, 10000)
        # 10k input * 0.015/1k = 0.15
        # 10k output * 0.075/1k = 0.75
        # Total = 0.90
        assert ct.estimated_cost_usd == 0.9

    def test_reset(self):
        ct = CostTracker()
        ct.add_usage(1000, 500)
        ct.reset()
        assert ct.total_input_tokens == 0
        assert ct.total_output_tokens == 0
        assert ct.estimated_cost_usd == 0.0
