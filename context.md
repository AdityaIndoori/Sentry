# Sentry — Full Project Context

> **Purpose of this file:** Provides complete architectural and implementation context so an LLM can understand, modify, debug, or extend any part of the Sentry codebase without reading individual source files.

---

## 1. Project Overview

**Sentry** is a Self-Healing Server Monitor — an autonomous AI service that:

1. **Watches** log files for error patterns (polling + regex)
2. **Triages** errors using Claude LLM with low-effort thinking
3. **Diagnoses** root causes using high-effort thinking + tool calls (read files, grep, run diagnostics)
4. **Fixes** issues by applying patches or restarting services (medium-effort thinking)
5. **Verifies** fixes with deterministic checks (thinking disabled)
6. **Remembers** past incidents in a JSON-based memory store for pattern matching

The system runs as two Docker containers (FastAPI backend + React/nginx frontend) and is governed by a **Zero Trust security architecture** with 15 defense-in-depth controls.

**Tech Stack:** Python 3.12, FastAPI, LangGraph, Anthropic Claude API (or AWS Bedrock Gateway), React 18, Vite, Docker Compose, nginx, pytest (442 tests, 97% coverage, 95% enforced at build time).

---

## 2. File Structure with Purpose

```
e:\Sentry\
├── .env.example              # Every env var with defaults and docs
├── .coveragerc               # Coverage config: source, omit, exclusions
├── .gitignore
├── docker-compose.yml        # 2 services: backend (:8000), frontend (:3000)
├── HighLevelDesignDoc.md     # Original design document
├── pytest.ini                # Test config + coverage flags (--cov-fail-under=95)
├── README.md                 # User-facing documentation
│
├── backend/
│   ├── __init__.py
│   ├── .dockerignore
│   ├── Dockerfile            # Python 3.12-slim, non-root sentry user
│   ├── requirements.txt      # All Python dependencies
│   │
│   ├── agents/               # Multi-agent architecture (standalone agent classes)
│   │   ├── __init__.py
│   │   ├── base_agent.py         # Abstract base: NHI registration + AI Gateway scanning
│   │   ├── supervisor.py         # Deterministic routing (no LLM, no tools)
│   │   ├── triage_agent.py       # Severity classifier (effort: low)
│   │   ├── detective_agent.py    # Root-cause investigator (effort: high, 4 tools)
│   │   ├── surgeon_agent.py      # Fix applier (effort: medium, 2 tools)
│   │   └── validator_agent.py    # Fix verifier (effort: disabled)
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   └── app.py                # FastAPI app with 11 REST endpoints + lifespan
│   │
│   ├── mcp_tools/            # Model Context Protocol tool implementations
│   │   ├── __init__.py
│   │   ├── executor.py           # MCPToolExecutor: routes calls, enforces security, retry + arg validation
│   │   ├── tool_schemas.py       # Pydantic models for tool args (single source of truth)
│   │   ├── read_only_tools.py    # read_file, grep_search, fetch_docs
│   │   ├── active_tools.py       # run_diagnostics
│   │   ├── patch_tool.py         # apply_patch (git apply --check + backup)
│   │   └── restart_tool.py       # restart_service (rate limited)
│   │
│   ├── memory/
│   │   ├── __init__.py
│   │   └── store.py              # JSONMemoryStore: file-based incident history
│   │
│   ├── orchestrator/         # Core AI pipeline
│   │   ├── __init__.py
│   │   ├── engine.py             # Orchestrator: incident lifecycle + memory + resolved list cap
│   │   ├── graph.py              # LangGraph StateGraph (4 nodes, conditional edges, empty response guards)
│   │   ├── llm_client.py         # OpusLLMClient + BedrockGatewayLLMClient + retry/timeout + factory
│   │   └── schemas.py            # Pydantic schemas: 3-tier parsing (JSON → regex fallback)
│   │
│   ├── services/             # Service Awareness Layer
│   │   ├── __init__.py
│   │   ├── models.py             # ServiceContext dataclass
│   │   └── registry.py           # ServiceRegistry: builds context from .env
│   │
│   ├── shared/               # Cross-cutting concerns
│   │   ├── __init__.py
│   │   ├── config.py             # All config dataclasses + load_config() from env
│   │   ├── interfaces.py         # ABC interfaces: ILLMClient, IMemoryStore, IToolExecutor, etc.
│   │   ├── models.py             # Domain models: Incident, LogEvent, ToolCall, ToolResult, etc.
│   │   ├── security.py           # SecurityGuard: path/command/URL validation, sanitization
│   │   ├── vault.py              # NHI Vault: agent identities, JIT credentials, kill switch
│   │   ├── ai_gateway.py         # AI Gateway: prompt injection + PII detection/redaction
│   │   ├── audit_log.py          # Immutable hash-chained audit log
│   │   ├── agent_throttle.py     # Per-agent sliding window rate limiter
│   │   ├── tool_registry.py      # Role-based tool access control
│   │   └── circuit_breaker.py    # Cost circuit breaker + restart rate limiter
│   │
│   └── tests/                # 442 tests (97% coverage, 95% enforced)
│       ├── __init__.py
│       ├── conftest.py               # Shared fixtures: security_guard, project_root, rate_limiter
│       ├── test_zero_trust.py        # 62 tests: vault, gateway, audit log, throttle, registry
│       ├── test_agents.py            # 59 tests: all 5 agent roles + supervisor routing
│       ├── test_tools.py             # 71 tests: read-only tools, active tools, executor hardening
│       ├── test_schemas.py           # 46 tests: parse_from_text, parse_safe, _try_extract_json
│       ├── test_llm_client.py        # 38 tests: effort, providers, factory, retry/backoff
│       ├── test_api.py               # 29 tests: all REST endpoints, config, watcher
│       ├── test_security.py          # 26 tests: path, command, URL, sanitization, stop file
│       ├── test_engine.py            # 18 tests: orchestrator lifecycle, circuit breaker, FIFO cap
│       ├── test_watcher.py           # 14 tests: log polling, file rotation, queue full
│       ├── test_config.py            # 14 tests: 12-factor config loading, defaults, env vars
│       ├── test_services.py          # 14 tests: service registry, context builder, fingerprint
│       ├── test_domain_models.py     # 22 tests: Pydantic domain models, serialization
│       ├── test_patch_tool.py        # 11 tests: apply_patch audit + active, git apply, backup
│       ├── test_circuit_breaker.py   # 10 tests: cost tracking, rate limiting
│       └── test_memory.py            # 6 tests: memory store CRUD, similarity, compaction
│
├── frontend/
│   ├── .dockerignore
│   ├── Dockerfile            # Multi-stage: node builder → nginx
│   ├── index.html
│   ├── nginx.conf            # Security headers + /api proxy to backend:8000
│   ├── package.json          # React 18 + Vite 5
│   ├── package-lock.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx              # React entry point
│       └── App.jsx               # Entire UI (~700 lines, single file)
│
├── watched/                  # Sample watched files (mounted in Docker)
│   ├── nginx-error.log
│   └── config/
│       ├── db.py
│       └── nginx.conf
│
└── docs/screenshots/         # Dashboard screenshots for README
```

---

## 3. End-to-End Data Flow

```
1. Log file changes → LogWatcher._poll_loop() detects via regex
2. LogWatcher emits LogEvent to async queue
3. _watcher_event_loop() reads queue → calls Orchestrator.handle_event()
4. Orchestrator creates Incident with UUID
5. ServiceRegistry.build_prompt_context() adds service paths to context
6. MemoryStore.get_relevant() finds similar past incidents by keyword overlap
7. LangGraph.ainvoke(initial_state) runs the 4-node state machine:
   a. _triage_node: LLM(effort=low) → TriageResult → severity + verdict
      - If FALSE_POSITIVE → state=IDLE → END
      - If INVESTIGATE → state=DIAGNOSIS → continue
   b. _diagnosis_node: LLM(effort=high, tools=all_defs) → tool loop (max 3 iterations)
      - LLM requests tool calls → MCPToolExecutor.execute() → results appended to prompt
      - After tools exhausted or LLM returns text → DiagnosisResult → root_cause
   c. _remediation_node: LLM(effort=medium, tools=all_defs in ACTIVE; no tools in AUDIT)
      - AUDIT mode: describes fix, doesn't execute
      - ACTIVE mode: calls apply_patch / restart_service
   d. _verification_node: LLM(effort=disabled) → VerificationResult → resolved/not
      - If resolved → state=RESOLVED → END
      - If not fixed & retries < max → state=DIAGNOSIS (retry loop)
      - If not fixed & retries >= max → state=ESCALATED → END
8. Resolved incidents → MemoryStore.save() for future pattern matching
9. Frontend polls /api/incidents every 3s → renders live state
```

---

## 4. Domain Models (`backend/shared/models.py`)

### Enums

```python
class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentState(Enum):
    IDLE = "idle"              # False positive, ignored
    TRIAGE = "triage"          # Being classified
    DIAGNOSIS = "diagnosis"    # Being investigated
    REMEDIATION = "remediation" # Fix being applied
    VERIFICATION = "verification" # Fix being verified
    RESOLVED = "resolved"      # Successfully fixed
    ESCALATED = "escalated"    # Failed, needs human

class ActivityType(Enum):
    PHASE_START = "phase_start"
    PHASE_COMPLETE = "phase_complete"
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    DECISION = "decision"
    ERROR = "error"
    INFO = "info"

class ToolCategory(Enum):
    READ_ONLY = "read_only"
    ACTIVE = "active"
```

### Core Dataclasses

```python
@dataclass
class LogEvent:
    source_file: str
    line_content: str
    timestamp: datetime        # timezone-aware UTC
    matched_pattern: str = ""
    line_number: int = 0

@dataclass
class Incident:
    id: str                    # "INC-20250101-120000-a1b2c3"
    symptom: str               # The error log line
    state: IncidentState = TRIAGE
    severity: IncidentSeverity = MEDIUM
    root_cause: Optional[str] = None
    fix_applied: Optional[str] = None
    triage_result: Optional[str] = None
    log_events: list = []
    activity_log: list = []    # list[ActivityEntry] — full timeline
    created_at: datetime       # UTC
    resolved_at: Optional[datetime] = None
    retry_count: int = 0
    cost_usd: float = 0.0
    vectors: list = []         # Keywords for memory matching
    current_agent_action: Optional[str] = None  # Live status text for UI

    # Methods:
    # log_activity(type, phase, title, detail, metadata) — appends ActivityEntry
    # to_dict() — full serialization including phase_summary
    # _phase_summary() — {"triage": "complete", "diagnosis": "active", ...}

@dataclass
class ActivityEntry:
    timestamp: datetime
    activity_type: ActivityType
    phase: str                 # "triage", "diagnosis", etc.
    title: str                 # Short summary
    detail: str = ""           # Longer detail (tool output, reasoning)
    metadata: dict = {}        # Extra info (tool args, tokens, etc.)

@dataclass
class ToolCall:
    tool_name: str
    arguments: dict = {}
    category: ToolCategory = READ_ONLY

@dataclass
class ToolResult:
    tool_name: str
    success: bool
    output: str = ""
    error: Optional[str] = None
    audit_only: bool = False   # True if blocked by AUDIT mode

@dataclass
class MemoryEntry:
    id: str
    symptom: str
    root_cause: str
    fix: str
    vectors: list = []         # Keywords for matching
    timestamp: str = ""
    # Methods: to_dict(), from_dict(data)

@dataclass
class CostTracker:
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    window_start: datetime     # UTC
    INPUT_COST_PER_1K: float = 0.015   # Claude pricing
    OUTPUT_COST_PER_1K: float = 0.075
    # Properties: estimated_cost_usd
    # Methods: add_usage(input, output), reset()
```

---

## 5. Interfaces (`backend/shared/interfaces.py`)

All abstractions that concrete classes implement (Dependency Inversion):

```python
class ILLMClient(ABC):
    async def analyze(self, prompt: str, effort: str = "low", tools: Optional[list] = None) -> dict:
        """Returns: {"text": str, "tool_calls": list[dict], "thinking": str,
                     "input_tokens": int, "output_tokens": int, "error": str|None}"""
    async def get_usage(self) -> dict:

class IToolExecutor(ABC):
    async def execute(self, tool_call: ToolCall) -> ToolResult:
    def get_tool_definitions(self) -> list:  # Anthropic tool format

class IMemoryStore(ABC):
    async def load(self) -> list[MemoryEntry]:
    async def save(self, entry: MemoryEntry) -> None:
    async def get_relevant(self, vectors: list[str]) -> list[MemoryEntry]:
    async def get_count(self) -> int:
    async def compact(self, summary_entries: list[MemoryEntry]) -> None:

class ILogWatcher(ABC):
    async def start(self) -> None:
    async def stop(self) -> None:
    async def events(self) -> AsyncIterator[LogEvent]:

class INotifier(ABC):  # NOT IMPLEMENTED — future work
    async def send_alert(self, incident: Incident, message: str) -> bool:
    async def send_resolution(self, incident: Incident) -> bool:

class IOrchestrator(ABC):
    async def handle_event(self, event: LogEvent) -> Optional[Incident]:
    async def get_active_incidents(self) -> list[Incident]:
    async def get_status(self) -> dict:
```

---

## 6. Configuration (`backend/shared/config.py`)

### Config Dataclasses (all frozen/immutable)

```python
class SentryMode(Enum):
    ACTIVE = "ACTIVE"      # Full autonomous operation
    AUDIT = "AUDIT"        # Log-only for active tools (default)
    DISABLED = "DISABLED"  # All operations blocked

class LLMProvider(Enum):
    ANTHROPIC = "anthropic"
    BEDROCK_GATEWAY = "bedrock_gateway"

@dataclass(frozen=True)
class SecurityConfig:
    mode: SentryMode = AUDIT
    stop_file_path: str = "/app/STOP_SENTRY"
    max_cost_per_10min_usd: float = 5.00
    max_retries: int = 3
    restart_cooldown_seconds: int = 600
    allowed_diagnostic_commands: FrozenSet[str]  # "ps aux", "netstat -tlnp", "curl", "tail", etc.
    allowed_fetch_domains: FrozenSet[str]        # "docs.python.org", "stackoverflow.com", etc.
    project_root: str = "/app/workspace"
    max_grep_results: int = 100
    max_file_size_bytes: int = 1_048_576  # 1MB

@dataclass(frozen=True)
class AnthropicConfig:
    api_key: str = ""
    model: str = "claude-opus-4-0-20250514"
    max_tokens: int = 16384

@dataclass(frozen=True)
class BedrockGatewayConfig:
    api_key: str = ""
    base_url: str = ""     # e.g. https://gateway.execute-api.us-east-1.amazonaws.com/api/v1
    model: str = "anthropic.claude-opus-4-0-20250514"
    max_tokens: int = 16384

@dataclass(frozen=True)
class WatcherConfig:
    watch_paths: tuple       # Glob patterns for log files
    poll_interval_seconds: float = 2.0
    error_patterns: tuple    # Regex patterns: error, critical, fatal, exception, etc.

@dataclass(frozen=True)
class MemoryConfig:
    file_path: str = "/app/data/sentry_memory.json"
    max_incidents_before_compaction: int = 50
    backup_on_write: bool = True

@dataclass(frozen=True)
class AppConfig:
    security: SecurityConfig
    anthropic: AnthropicConfig
    bedrock_gateway: BedrockGatewayConfig
    llm_provider: LLMProvider = ANTHROPIC
    watcher: WatcherConfig
    memory: MemoryConfig
    service_source_path: str = "/app/workspace"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"
    environment: str = "production"
```

### `load_config()` Function

Reads from environment variables (with `python-dotenv` for `.env` file support). Every variable has a secure default. Key env vars:

| Variable | Default | Required |
|----------|---------|----------|
| `LLM_PROVIDER` | `anthropic` | |
| `ANTHROPIC_API_KEY` | `""` | ✅ |
| `ANTHROPIC_MODEL` | `claude-opus-4-0-20250514` | |
| `SENTRY_MODE` | `AUDIT` | |
| `PROJECT_ROOT` | `/app/workspace` | |
| `WATCH_PATHS` | `/var/log/syslog,/var/log/app/*.log` | |
| `SERVICE_HOST_PATH` | (none) | ✅ for Docker |
| `SERVICE_SOURCE_PATH` | `/app/workspace` | |
| `MAX_COST_10MIN` | `5.00` | |
| `MAX_RETRIES` | `3` | |
| `RESTART_COOLDOWN` | `600` | |
| `POLL_INTERVAL` | `2` (or `5` in .env.example) | |
| `MEMORY_FILE_PATH` | `/app/data/sentry_memory.json` | |

---

## 7. Orchestrator Engine (`backend/orchestrator/engine.py`)

```python
class Orchestrator:
    def __init__(self, config, llm, tools, memory, circuit_breaker):
        # Loads ServiceRegistry from config
        # Builds system fingerprint into memory store
        # Builds LangGraph compiled graph via IncidentGraphBuilder

    async def handle_event(self, event: LogEvent) -> Optional[Incident]:
        # 1. Check circuit breaker
        # 2. Create Incident with unique ID: "INC-YYYYMMDD-HHMMSS-hexsuffix"
        # 3. Build service context from ServiceRegistry
        # 4. Create initial IncidentGraphState
        # 5. graph.ainvoke(initial_state) → final_state
        # 6. If resolved → save to memory, move to resolved list
        # 7. If idle → remove from active
        # 8. Return incident

    async def _save_to_memory(self, incident: Incident):
        # Creates MemoryEntry from incident
        # Checks compaction threshold

    # State tracking:
    _active_incidents: dict[str, Incident]   # incident_id → Incident
    _resolved_incidents: list[Incident]       # FIFO-capped at MAX_RESOLVED_INCIDENTS (100)

# Production hardening #4: Resolved list is capped at 100 entries (FIFO).
# When limit is exceeded, oldest entries are dropped to prevent unbounded memory growth.
MAX_RESOLVED_INCIDENTS = 100
```

---

## 8. LangGraph State Machine (`backend/orchestrator/graph.py`)

### Graph State

```python
class IncidentGraphState(TypedDict, total=False):
    incident: Incident         # The incident being processed
    service_context: str       # Service awareness prompt block
    triage: dict               # TriageResult as dict
    diagnosis: dict            # DiagnosisResult as dict
    remediation: dict          # RemediationResult as dict
    verification: dict         # VerificationResult as dict
    tool_results: list         # Accumulated tool call results
    tool_loop_count: int       # Diagnosis tool loops done
    error: str                 # Error message if any node fails
```

### Graph Topology

```
Entry → triage → [route_after_triage] → diagnosis → remediation → verification → [route_after_verification] → END
                        ↓                                                                    ↓
                       END (false positive)                                          diagnosis (retry)
                                                                                    or END (resolved/escalated)
```

### Node: `_triage_node` (Phase 1)

- Sets `incident.state = TRIAGE`
- Queries memory for similar past incidents (keyword overlap, top 3)
- Builds prompt with: error line + service context + memory hints
- Calls `llm.analyze(prompt, effort="low")`
- Parses response via `TriageResult.parse_from_text()`
- Sets severity (low/medium/high/critical) and verdict (INVESTIGATE/FALSE_POSITIVE)
- If FALSE_POSITIVE → `incident.state = IDLE`
- Logs all activities to incident.activity_log

**Triage Prompt Template:**
```
You are Sentry, an autonomous server monitoring AI.
Triage this production error log entry:

ERROR: {symptom}

--- SERVICE CONTEXT ---
{service_context}
--- END SERVICE CONTEXT ---

Similar past incidents:
- {past_incident_1}
- {past_incident_2}

Respond in this EXACT format:
SEVERITY: <low|medium|high|critical>
VERDICT: <INVESTIGATE|FALSE POSITIVE>
SUMMARY: <one-line description>
```

### Node: `_diagnosis_node` (Phase 2)

- Sets `incident.state = DIAGNOSIS`
- Gets all tool definitions via `tools.get_tool_definitions()`
- Loops up to `max_retries` times:
  - Calls `llm.analyze(prompt, effort="high", tools=tool_defs)`
  - If LLM returns `tool_calls`:
    - Execute each tool via `tools.execute(ToolCall(...))`
    - Append results to prompt (truncated to 2000 chars each)
    - Cap total prompt at 50K chars (truncate middle)
    - In AUDIT mode, force summary after 2 tool loops
  - If LLM returns text (no tool calls):
    - Parse via `DiagnosisResult.parse_from_text()` → root_cause
    - Break loop
- If loops exhausted: send summary prompt asking for best-effort diagnosis
- Checks circuit breaker on every loop iteration

**Diagnosis Prompt Template:**
```
You are diagnosing a server incident.
Symptom: {symptom}
Severity: {severity}

{service_context}

Start by reading the source code to understand how the service works.
Look at config files, entry points, error handlers, and dependencies.
Then investigate what went wrong.

Use the available tools to investigate. Find the root cause. Be specific.
```

### Node: `_remediation_node` (Phase 3)

- Sets `incident.state = REMEDIATION`
- **AUDIT mode:** Calls LLM without tools, asks for fix description only
  - Stores as `[AUDIT] {fix_description}`
- **ACTIVE mode:** Calls LLM with tool definitions
  - Executes tool calls (apply_patch, restart_service)
  - Stores actual results
- Parses via `RemediationResult.parse_from_text()`

### Node: `_verification_node` (Phase 4)

- Sets `incident.state = VERIFICATION`
- Calls `llm.analyze(prompt, effort="disabled")`
- Parses via `VerificationResult.parse_from_text()`
- If resolved → `incident.state = RESOLVED`, sets `resolved_at`
- If not resolved → increments `retry_count`
  - If `retry_count >= max_retries` → `ESCALATED`
  - Else → `DIAGNOSIS` (retry)

### Routing Functions

```python
def _route_after_triage(state) -> "diagnosis" | "end":
    # IDLE or ESCALATED → end, else → diagnosis

def _route_after_verification(state) -> "end" | "diagnosis":
    # RESOLVED or ESCALATED → end, else → diagnosis (retry)
```

### Cost Tracking

Every LLM response triggers `circuit_breaker.record_usage(input_tokens, output_tokens)`. If cost exceeds $5 in 10 minutes, the breaker trips and blocks further processing.

---

## 9. LLM Output Schemas (`backend/orchestrator/schemas.py`)

All schemas use a **provider-agnostic 3-tier validation strategy**:
- **Tier 1:** Tool/function calling (structured tool_call data — handled at graph level)
- **Tier 2:** JSON-in-text → Pydantic `model_validate()` (tried first in `parse_safe()`)
- **Tier 3:** Regex extraction via `parse_from_text()` (fallback)

Each schema has both `parse_safe()` (the entry point, tries JSON first) and `parse_from_text()` (regex fallback). Graph nodes call `parse_safe()`.

A shared `_try_extract_json(text)` helper handles: pure JSON, `\`\`\`json` code blocks, and embedded `{...}` objects.

### TriageResult

```python
class TriageResult(BaseModel):
    severity: str   # "low"|"medium"|"high"|"critical"
    verdict: str    # "INVESTIGATE"|"FALSE_POSITIVE"
    summary: str    # One-line description

    @classmethod
    def parse_safe(cls, text: str) -> "TriageResult":
        # Tier 2: _try_extract_json() → model_validate()
        # Tier 3: Falls back to parse_from_text()

    @classmethod
    def parse_from_text(cls, text: str) -> "TriageResult":
        # 1. Look for "SEVERITY: <value>" with regex
        # 2. Fallback: scan for standalone keywords
        # 3. Look for "VERDICT: FALSE POSITIVE" or "false_positive"
        # 4. Look for "SUMMARY: <text>" line
        # 5. Fallback: first non-severity/verdict line
```

### DiagnosisResult

```python
class DiagnosisResult(BaseModel):
    root_cause: str              # Clear root cause statement
    evidence: list[str] = []     # Key evidence found
    recommended_fix: str = ""    # Recommended remediation

    @classmethod
    def parse_safe(cls, text: str) -> "DiagnosisResult":
        # Tier 2: JSON → Tier 3: regex fallback

    @classmethod
    def parse_from_text(cls, text: str) -> "DiagnosisResult":
        # Parses "ROOT CAUSE:", "RECOMMENDED FIX:", "EVIDENCE:" sections
        # Handles content on same line as header or subsequent lines
        # Fallback: first substantive paragraph as root_cause
        # Strips markdown formatting (bold, italic, code, headers)
```

### RemediationResult

```python
class RemediationResult(BaseModel):
    fix_description: str         # What fix was applied/proposed
    tools_used: list[str] = []
    success: bool = False

    @classmethod
    def parse_safe(cls, text: str, tool_names: list[str] = None):
        # Tier 2: JSON → Tier 3: regex fallback
        # Injects tool_names into JSON obj if not present

    @classmethod
    def parse_from_text(cls, text: str, tool_names: list[str] = None):
        # Looks for "FIX PROPOSED:", "FIX APPLIED:", "FIX:" lines
        # Fallback: truncated full text
        # success = "success" or "applied" in text
```

### VerificationResult

```python
class VerificationResult(BaseModel):
    resolved: bool
    reason: str = ""

    @classmethod
    def parse_safe(cls, text: str):
        # Tier 2: JSON → Tier 3: regex fallback

    @classmethod
    def parse_from_text(cls, text: str):
        # Bug fix: Check negation phrases FIRST
        # "not fixed", "not resolved", "unsuccessful", "failed", "still broken"
        # Then check positive: "fixed", "resolved", "success"
        # resolved = has_positive AND NOT has_negation
```

---

## 10. LLM Clients (`backend/orchestrator/llm_client.py`)

### Effort → Budget Mapping

```python
def _effort_to_budget(effort: str) -> int:
    {"low": 2048, "medium": 8192, "high": 32768}
```

### OpusLLMClient (Direct Anthropic API)

```python
class OpusLLMClient(ILLMClient):
    def __init__(self, config: AnthropicConfig):
        self._client = anthropic.AsyncAnthropic(api_key=config.api_key)

    async def analyze(self, prompt, effort="low", tools=None) -> dict:
        # If no valid API key → return simulated escalation response
        # Build kwargs: model, max_tokens, messages=[{"role":"user","content":prompt}]
        # If effort != "disabled": add thinking={"type":"enabled","budget_tokens":budget}
        # If tools: add tools list
        # Call self._client.messages.create(**kwargs)
        # If TypeError (SDK doesn't support thinking): retry without thinking param
        # Parse response blocks: text, tool_use, thinking → standard dict
```

### BedrockGatewayLLMClient (OpenAI-compatible API)

```python
class BedrockGatewayLLMClient(ILLMClient):
    def __init__(self, config: BedrockGatewayConfig):
        from openai import AsyncOpenAI
        self._client = AsyncOpenAI(api_key=config.api_key, base_url=config.base_url)

    async def analyze(self, prompt, effort="low", tools=None) -> dict:
        # Adds system prompt with effort hint
        # Converts Anthropic tool format → OpenAI function-calling format:
        #   {"name","description","input_schema"} → {"type":"function","function":{"name","description","parameters"}}
        # Calls self._client.chat.completions.create(**kwargs)
        # Parses OpenAI-format response → standard dict
```

### Factory

```python
def create_llm_client(config: AppConfig) -> ILLMClient:
    # If BEDROCK_GATEWAY and base_url+api_key set → BedrockGatewayLLMClient
    # Else → OpusLLMClient (default)
```

### Standard Response Dict

All LLM clients return:
```python
{
    "text": str,              # Combined text blocks
    "tool_calls": [           # List of tool call requests
        {"id": str, "name": str, "arguments": dict}
    ],
    "thinking": str,          # Extended thinking content (Anthropic only)
    "input_tokens": int,
    "output_tokens": int,
    "error": str | None,
}
```

---

## 11. MCP Tools

### Tool Executor (`backend/mcp_tools/executor.py`)

```python
class MCPToolExecutor(IToolExecutor):
    def __init__(self, security: SecurityGuard, project_root: str):
        # Initializes all 6 tool instances
        # Maps tool_name → (tool_instance, ToolCategory)

    async def execute(self, tool_call: ToolCall) -> ToolResult:
        # 1. Check STOP_SENTRY file → block all
        # 2. Check DISABLED mode → block all
        # 3. Look up tool in map → "Unknown tool" if missing
        # 4. Check AUDIT mode for ACTIVE tools → return audit_only=True
        # 5. Call tool.execute(**tool_call.arguments)
        # 6. Wrap in ToolResult

    def get_tool_definitions(self) -> list:
        # Returns 6 Anthropic-format tool definitions
```

### read_file (`read_only_tools.py`)

```python
class ReadFileTool:
    async def execute(self, path: str) -> dict:
        # 1. security.validate_path(path) — within PROJECT_ROOT, no traversal
        # 2. Check os.path.isfile(full_path)
        # 3. Check file size <= max_file_size_bytes (1MB)
        # 4. Read with utf-8, errors="replace"
        # Returns: {"success": bool, "output": str, "error": str}

    @staticmethod
    def definition() -> dict:
        # name: "read_file"
        # input_schema: {"path": str (required)}
```

### grep_search (`read_only_tools.py`)

```python
class GrepSearchTool:
    async def execute(self, query: str, path: str = ".") -> dict:
        # 1. Validate path
        # 2. Compile regex (IGNORECASE)
        # 3. os.walk search directory, read each file
        # 4. Collect matches as "relative_path:line_num: content"
        # 5. Cap at max_grep_results (100)
        # Returns: {"success": bool, "output": str}

    @staticmethod
    def definition() -> dict:
        # name: "grep_search"
        # input_schema: {"query": str (required), "path": str (optional, default=".")}
```

### fetch_docs (`read_only_tools.py`)

```python
class FetchDocsTool:
    async def execute(self, url: str) -> dict:
        # 1. security.validate_url(url) — domain allow-list
        # 2. aiohttp GET with 10s timeout
        # 3. Truncate response to 10K chars
        # Returns: {"success": bool, "output": str}

    @staticmethod
    def definition() -> dict:
        # name: "fetch_docs"
        # input_schema: {"url": str (required)}
```

### run_diagnostics (`active_tools.py`)

```python
class RunDiagnosticsTool:
    async def execute(self, command: str) -> dict:
        # 1. security.sanitize_input(command) — strip dangerous chars
        # 2. security.validate_command(sanitized) — whitelist check
        # 3. If AUDIT mode → log only, return audit_only=True
        # 4. asyncio.create_subprocess_shell with 30s timeout
        # 5. Truncate output to 5000 chars
        # Returns: {"success": bool, "output": str, "audit_only": bool}

    @staticmethod
    def definition() -> dict:
        # name: "run_diagnostics"
        # input_schema: {"command": str (required)}
```

### apply_patch (`patch_tool.py`)

```python
class ApplyPatchTool:
    async def execute(self, file_path: str, diff: str) -> dict:
        # 1. Validate path
        # 2. Check file exists
        # 3. If AUDIT mode → log only
        # 4. Create .bak backup
        # 5. Write diff to temp file
        # 6. Run "git apply --check" (dry run)
        # 7. If check passes → "git apply" for real
        # 8. If apply fails → restore from backup
        # Returns: {"success": bool, "output": str}

    @staticmethod
    def definition() -> dict:
        # name: "apply_patch"
        # input_schema: {"file_path": str (required), "diff": str (required)}
```

### restart_service (`restart_tool.py`)

```python
class RestartServiceTool:
    async def execute(self, service_name: str) -> dict:
        # 1. Regex validate service name: ^[a-zA-Z0-9_\-\.]+$
        # 2. If AUDIT mode → log only
        # 3. Rate limiter check (1 restart per cooldown_seconds per service)
        # 4. "systemctl restart {service_name}" with 30s timeout
        # Returns: {"success": bool, "output": str}

    @staticmethod
    def definition() -> dict:
        # name: "restart_service"
        # input_schema: {"service_name": str (required)}
```

### Anthropic Tool Definition Format

Each tool's `definition()` returns:
```python
{
    "name": "tool_name",
    "description": "What it does",
    "input_schema": {
        "type": "object",
        "properties": { "param": {"type": "string", "description": "..."} },
        "required": ["param"]
    }
}
```

---

## 12. Zero Trust Security Architecture

### 12.1 NHI Vault (`backend/shared/vault.py`)

```python
class AgentRole(Enum):
    SUPERVISOR, TRIAGE, DETECTIVE, SURGEON, VALIDATOR

@dataclass(frozen=True)
class NonHumanIdentity:
    agent_id: str          # "triage-a1b2c3" (role-hexsuffix)
    role: AgentRole
    fingerprint: str       # SHA-256 of creation params (first 16 chars)
    created_at: datetime

@dataclass
class JITCredential:
    credential_id: str     # "cred-hexsuffix"
    agent_id: str
    token: str             # HMAC-SHA256 token
    scope: str             # "read_file", "llm_call", etc.
    issued_at: float       # time.time()
    ttl_seconds: int
    revoked: bool = False
    # Properties: is_expired, is_valid

class IVault(ABC):         # Interface for swapping to HashiCorp Vault
    register_agent(role) -> NonHumanIdentity
    issue_credential(agent_id, scope, ttl_seconds) -> Optional[JITCredential]
    verify_credential(credential_id, agent_id, scope) -> bool
    revoke_credential(credential_id) -> bool
    revoke_all() -> int    # KILL SWITCH
    get_agent(agent_id) -> Optional[NonHumanIdentity]

class LocalVault(IVault):
    # Thread-safe (Lock) in-process implementation
    # Master secret: random 32-byte hex
    # register_agent: creates unique ID + SHA-256 fingerprint
    # issue_credential: HMAC token with agent_id+scope+timestamp+random
    # verify_credential: checks valid + not expired + not revoked + agent match + scope match
    # revoke_all: sets _killed=True, revokes all credentials
    # cleanup_expired: removes dead credentials
```

### 12.2 AI Gateway (`backend/shared/ai_gateway.py`)

```python
class ScanResult:
    is_safe: bool
    threats: list[str]     # ["prompt_injection", "role_hijack", "pii_email", ...]
    details: str

class AIGateway:
    INJECTION_PATTERNS = [
        # 20+ patterns covering:
        # - System prompt override: "ignore previous instructions", "disregard prior"
        # - Role hijacking: "you are now in unrestricted mode", "enter god mode"
        # - Delimiter injection: "</system>", "<|im_start|>", "[INST]"
        # - Command injection: "execute any command", "run rm -rf"
    ]

    PII_PATTERNS = [
        # 10+ patterns covering:
        # - Email addresses
        # - API keys (sk-..., api_key=..., secret_key=...)
        # - Passwords (password=..., passwd=...)
        # - Internal IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
        # - SSH private keys
        # - AWS credentials (AKIA...)
        # - Credit card numbers
        # - Social Security Numbers
    ]

    def scan_input(self, text: str) -> ScanResult:
        # Checks all INJECTION_PATTERNS against text
        # Returns is_safe=False if any match

    def scan_output(self, text: str) -> ScanResult:
        # Checks all PII_PATTERNS against text
        # Returns is_safe=False if any match

    def redact_output(self, text: str) -> str:
        # Replaces PII matches with [REDACTED_TYPE] tags
```

### 12.3 Immutable Audit Log (`backend/shared/audit_log.py`)

```python
class ImmutableAuditLog:
    def __init__(self, log_path: str):
        # Creates JSONL file, recovers last hash on startup

    def log_action(self, agent_id, action, detail, result, chain_of_thought="", metadata=None) -> str:
        # Creates entry: {timestamp, agent_id, action, detail, result, chain_of_thought, metadata, prev_hash}
        # Computes SHA-256 of entry (without entry_hash field)
        # Appends entry + entry_hash to JSONL file
        # Returns entry_hash

    def verify_integrity(self) -> bool:
        # Reads all entries
        # For each entry: verify prev_hash matches previous entry's hash
        # For each entry: recompute hash and compare to stored hash
        # Returns False if any mismatch (tamper detected)

    def read_all(self) -> list[dict]
    def get_entry_count(self) -> int
```

### 12.4 Agent Throttle (`backend/shared/agent_throttle.py`)

```python
class AgentThrottle:
    def __init__(self, max_actions_per_minute: int = 5):
        # Per-agent sliding window counters

    def is_allowed(self, agent_id: str, action_type: str = "generic") -> bool:
        # Prune actions older than 60s
        # If count >= max_actions → return False (THROTTLED)
        # Else → record action, return True

    def get_remaining(self, agent_id: str) -> int
    def reset(self, agent_id: str)
    def reset_all()
```

### 12.5 Trusted Tool Registry (`backend/shared/tool_registry.py`)

```python
@dataclass
class ToolDefinition:
    name: str
    description: str
    allowed_roles: list[AgentRole]
    is_active: bool = False

class TrustedToolRegistry:
    def register(self, name, allowed_roles, description="", is_active=False)
    def is_allowed(self, tool_name: str, role: AgentRole) -> bool
    def get_tools_for_role(self, role: AgentRole) -> list[str]
    def get_tool(self, name: str) -> Optional[ToolDefinition]
    def get_all_tools(self) -> list[ToolDefinition]

def create_default_registry() -> TrustedToolRegistry:
    # Registers all 6 tools with role-based access:
    #
    # read_file:       [SUPERVISOR, TRIAGE, DETECTIVE, VALIDATOR] (read-only)
    # grep_search:     [SUPERVISOR, TRIAGE, DETECTIVE, VALIDATOR] (read-only)
    # fetch_docs:      [SUPERVISOR, TRIAGE, DETECTIVE]            (read-only)
    # run_diagnostics: [SUPERVISOR, DETECTIVE, VALIDATOR]          (active)
    # apply_patch:     [SUPERVISOR, SURGEON]                       (active)
    # restart_service: [SUPERVISOR, SURGEON]                       (active)
```

### 12.6 Security Guard (`backend/shared/security.py`)

```python
class SecurityGuard:
    def __init__(self, config: SecurityConfig)

    def is_stopped(self) -> bool:
        # os.path.exists(stop_file_path)

    def is_audit_mode(self) -> bool:
        # mode == AUDIT or is_stopped()

    def is_active_mode(self) -> bool:
        # mode == ACTIVE and not is_stopped()

    def validate_path(self, path: str) -> bool:
        # 1. os.path.normpath
        # 2. Reject ".." in path components
        # 3. os.path.realpath(project_root + path)
        # 4. Verify resolved path starts with project_root

    def validate_command(self, command: str) -> bool:
        # 1. Extract first token (base command)
        # 2. For each allowed command: match base AND full prefix
        # Prevents "curl evil.com" from matching "curl" in whitelist

    def validate_url(self, url: str) -> bool:
        # Parse hostname, check against allowed_fetch_domains
        # Supports subdomain matching (x.docs.python.org matches docs.python.org)

    def sanitize_input(self, text: str) -> str:
        # Strips: ; && || | ` $( >> <<
```

### 12.7 Circuit Breaker (`backend/shared/circuit_breaker.py`)

```python
class CostCircuitBreaker:
    def __init__(self, max_cost_usd=5.0, window_minutes=10):
        self._tracker = CostTracker()

    @property
    def is_tripped(self) -> bool:
        # Auto-resets if window has elapsed

    def record_usage(self, input_tokens, output_tokens):
        # Updates tracker, trips if cost >= max

    def get_status(self) -> dict:
        # {tripped, current_cost_usd, max_cost_usd, window_minutes, input_tokens, output_tokens}

class RateLimiter:
    def is_allowed(self, key: str, cooldown_seconds: int) -> bool:
        # Returns False if last call was within cooldown
        # Bug fix: automatically records on success (prevents retry abuse)

    def record(self, key: str)
    def get_remaining(self, key: str, cooldown_seconds: int) -> float
```

### Summary of All 15 Security Layers

| # | Layer | Enforcement Point |
|---|-------|-------------------|
| 1 | NHI Vault | Agent registration, credential issuance |
| 2 | AI Gateway (Input) | Prompt injection detection before LLM calls |
| 3 | AI Gateway (Output) | PII detection/redaction on LLM responses |
| 4 | Immutable Audit Log | Hash-chained logging of all actions |
| 5 | Agent Throttle | Per-agent rate limiting (actions/minute) |
| 6 | Tool Registry | Role-based tool access control |
| 7 | Human Switch | STOP_SENTRY file or SENTRY_MODE=AUDIT |
| 8 | Path Validation | All paths resolved against PROJECT_ROOT |
| 9 | Command Whitelist | Only approved diagnostic commands |
| 10 | URL Allow-List | Only approved domains for fetch_docs |
| 11 | Input Sanitization | Strips shell injection characters |
| 12 | Restart Rate Limiting | Max 1 restart per 10min per service |
| 13 | Cost Circuit Breaker | Auto-halt at $5/10min API spend |
| 14 | Diff Validation | git apply --check before patching |
| 15 | Non-Root Docker | Runs as sentry user with no-new-privileges |

---

## 13. Multi-Agent Architecture (`backend/agents/`)

> **Important note:** The agents in `backend/agents/` are defined as standalone classes with their own prompting and parsing logic. However, the production pipeline actually runs through `backend/orchestrator/graph.py` nodes, which implement overlapping but separate logic. The agent classes are primarily used for unit testing and as a design reference. This is a known architectural duplication.

### BaseAgent (`base_agent.py`)

```python
class BaseAgent(ABC):
    def __init__(self, vault: IVault, role: AgentRole, gateway: AIGateway):
        self._vault = vault
        self._gateway = gateway
        self._nhi = vault.register_agent(role)  # Gets unique NHI on creation

    @property
    def nhi(self) -> NonHumanIdentity
    @property
    def agent_id(self) -> str

    def _get_credential(self, scope: str, ttl: int = 60):
        # Issues JIT credential from vault
        # Raises PermissionError if denied

    def _scan_input(self, text: str) -> str:
        # Scans via ai_gateway.scan_input()
        # Raises ValueError if injection detected

    def _scan_and_redact_output(self, text: str) -> str:
        # Scans via ai_gateway.scan_output()
        # Redacts PII if detected
```

### SupervisorAgent (`supervisor.py`)

- Role: `SUPERVISOR`
- **No LLM access, no tool access** — pure deterministic routing
- `route(incident, phase_result, current_phase) → next_phase_name`
- Standalone routing functions: `route_after_triage(state)`, `route_after_verification(state)`

### TriageAgent (`triage_agent.py`)

- Role: `TRIAGE`, effort: `low`
- Has `TRIAGE_SYSTEM_PROMPT` constant
- `run(incident, memory_hints) → {"severity", "verdict", "summary", "raw_text"}`
- Gets JIT credential, scans input, calls LLM, revokes credential
- Parses response with regex for SEVERITY/VERDICT/SUMMARY

### DetectiveAgent (`detective_agent.py`)

- Role: `DETECTIVE`, effort: `high`, max 8 tool loops
- Has `DETECTIVE_SYSTEM_PROMPT` constant
- `run(incident) → {"root_cause", "recommended_fix", "tool_results"}`
- Uses: TrustedToolRegistry for access checks, AgentThrottle for rate limiting
- Tool loop: LLM requests tools → check registry → check throttle → execute → append to messages
- If loop exhausted → returns "Investigation inconclusive"

### SurgeonAgent (`surgeon_agent.py`)

- Role: `SURGEON`, effort: `medium`
- Has `SURGEON_SYSTEM_PROMPT` constant
- `run(incident) → {"fix_description", "fix_details", "fix_applied", "tool_results"}`
- Uses: TrustedToolRegistry, AgentThrottle
- Respects AUDIT mode via config

### ValidatorAgent (`validator_agent.py`)

- Role: `VALIDATOR`, effort: `disabled`
- Has `VALIDATOR_SYSTEM_PROMPT` constant
- `run(incident) → {"resolved", "reason", "raw_text"}`
- **Known bug:** Calls `self._llm.analyze(system_prompt=..., user_message=..., thinking=...)` but `ILLMClient.analyze()` signature is `(prompt, effort, tools)`. Would fail if called directly.

---

## 14. Service Awareness (`backend/services/`)

### ServiceContext (`models.py`)

```python
@dataclass
class ServiceContext:
    source_path: str = ""           # Path to service source code
    log_paths: list[str] = []      # Watched log file paths

    def build_prompt(self) -> str:
        # Returns:
        # === SERVICE CONTEXT ===
        # Source code path: /app/workspace
        # Log file paths: /app/watched/*.log, ...
        #
        # IMPORTANT: You have access to the service's source code via the read_file
        # and grep_search tools. Use them to understand how the service works...
        # === END SERVICE CONTEXT ===

    def has_context(self) -> bool:
        # True if source_path or log_paths are set

    def build_fingerprint(self) -> str:
        # "Monitored Service:\n  Source: ...\n  Logs: ..."
```

### ServiceRegistry (`registry.py`)

```python
class ServiceRegistry:
    def __init__(self, config: AppConfig):
        # Builds ServiceContext from config.service_source_path + config.watcher.watch_paths

    def has_context(self) -> bool
    def build_prompt_context(self) -> str    # Delegates to ServiceContext.build_prompt()
    def build_fingerprint(self) -> str       # Delegates to ServiceContext.build_fingerprint()
```

---

## 15. Memory Store (`backend/memory/store.py`)

### JSON File Structure

```json
{
    "system_fingerprint": "Monitored Service:\n  Source: /app/workspace\n  Logs: ...",
    "incident_history": [
        {
            "id": "INC-20250101-120000-a1b2c3",
            "symptom": "502 Bad Gateway on /api/login",
            "root_cause": "Postgres connection pool exhaustion",
            "fix": "Increased max_connections from 10 to 50",
            "vectors": ["postgres", "502", "pool"],
            "timestamp": "2025-01-01T12:05:00+00:00"
        }
    ]
}
```

### JSONMemoryStore

```python
class JSONMemoryStore(IMemoryStore):
    def __init__(self, config: MemoryConfig):
        # Creates file/directory if not exists
        # Uses asyncio.Lock for thread safety

    async def load(self) -> list[MemoryEntry]:
        # Read JSON, convert to MemoryEntry list

    async def save(self, entry: MemoryEntry):
        # Append to incident_history
        # Creates .bak backup before writing

    async def get_relevant(self, vectors: list[str]) -> list[MemoryEntry]:
        # Keyword overlap: set(entry.vectors) & set(input_vectors)
        # Sorted by overlap count (descending)

    async def get_count(self) -> int
    async def compact(self, summary_entries: list[MemoryEntry])
    async def set_fingerprint(self, fingerprint: str)
    async def get_fingerprint(self) -> str
```

---

## 16. Log Watcher (`backend/watcher/log_watcher.py`)

```python
class LogWatcher:
    def __init__(self, config: WatcherConfig):
        self._patterns = [re.compile(p) for p in config.error_patterns]
        # Error patterns: error, critical, fatal, exception, refused,
        #                 timeout, out of memory, disk full, 502, 503, connection reset
        self._event_queue = asyncio.Queue(maxsize=100)

    async def start(self):
        # Sets _running=True, creates background _poll_loop task

    async def stop(self):
        # Sets _running=False

    async def events(self) -> AsyncIterator[LogEvent]:
        # Yields events from queue with 1s timeout

    async def _poll_loop(self):
        # Every poll_interval_seconds:
        # 1. Resolve glob patterns → file list
        # 2. For each file: _check_file()

    async def _check_file(self, path: str):
        # Tracks file position (handles truncation/rotation)
        # Reads new lines from last position
        # Matches each line against error patterns
        # Creates LogEvent and puts in queue (drops if full)

    async def inject_event(self, event: LogEvent):
        # For testing/API manual triggers
```

---

## 17. API Endpoints (`backend/api/app.py`)

### Application Lifecycle

```python
@asynccontextmanager
async def lifespan(app):
    # Startup:
    #   load_config() → SecurityGuard → JSONMemoryStore → MCPToolExecutor
    #   → create_llm_client() → CostCircuitBreaker → Orchestrator → LogWatcher
    # Shutdown:
    #   watcher.stop()
```

### Endpoints

| Method | Path | Handler | Returns |
|--------|------|---------|---------|
| GET | `/api/health` | `health()` | `{"status": "ok", "timestamp": "..."}` |
| GET | `/api/status` | `get_status()` | `{"active_incidents": N, "resolved_total": N, "circuit_breaker": {...}, "mode": "AUDIT", "watcher_running": bool}` |
| GET | `/api/incidents` | `get_incidents()` | `{"active": [incident_dict...], "resolved": [last 20 incident_dicts...]}` |
| GET | `/api/incidents/{id}` | `get_incident_detail()` | Full incident dict with activity_log |
| POST | `/api/trigger` | `trigger_event(req)` | `{"incident": incident_dict}` or `{"incident": null, "message": "..."}` |
| GET | `/api/memory` | `get_memory()` | `{"count": N, "entries": [last 20...], "fingerprint": "..."}` |
| GET | `/api/tools` | `get_tools()` | `{"tools": [6 tool definitions]}` |
| GET | `/api/config` | `get_config()` | Safe config values (no API keys) |
| GET | `/api/security` | `get_security_status()` | Zero Trust posture: layers, agent roles, circuit breaker |
| POST | `/api/watcher/start` | `start_watcher()` | `{"status": "started"}` |
| POST | `/api/watcher/stop` | `stop_watcher()` | `{"status": "stopped"}` |

### Request Models

```python
class TriggerEventRequest(BaseModel):
    source: str = "manual"
    message: str
```

### CORS

```python
allow_origins=["http://localhost:3000", "http://localhost:5173"]
allow_methods=["GET", "POST"]
```

### Background Watcher Loop

```python
async def _watcher_event_loop():
    # Reads events from watcher.events() generator
    # Passes each to orchestrator.handle_event()
    # Started as asyncio.Task when /api/watcher/start is called
```

---

## 18. Frontend (`frontend/src/App.jsx`)

### Architecture

Single-file React app (~700 lines), no external UI libraries, all inline styles with a dark theme design system.

### Component Tree

```
App
├── GlobalStyles (injected CSS: animations, scrollbar, fonts)
├── Header (logo, mode badge, refresh button)
├── StatusRow (4 metric cards: active incidents, resolved, API cost, circuit breaker)
├── ConfigPanel (LLM provider, model, monitored service, mode, watch paths)
├── WatcherControl (start/stop toggle with status indicator)
├── TriggerPanel (manual error input form + result display)
├── SecurityPanel (10 security layers grid + 5 agent role cards with tool badges)
├── IncidentsPanel (active/resolved tabs)
│   └── IncidentCard (expandable, per incident)
│       ├── PhaseStepper (triage→diagnosis→remediation→verification progress)
│       ├── InfoBlock (triage result, root cause, fix applied, metrics, timeline)
│       └── ActivityFeed (chronological agent action log)
│           └── ActivityItem (individual action with expandable detail)
├── MemoryPanel (incident count, fingerprint, last 5 entries)
└── ToolsPanel (read-only vs active tool lists)
```

### Data Fetching

```javascript
function useApi(endpoint, interval = null) {
    // Custom hook: fetch + polling
    // Returns { data, error, loading, refresh }
}

// Polling intervals:
// /status     → 3000ms (3s)
// /incidents  → 3000ms (3s)
// /memory     → 10000ms (10s)
// /security   → 15000ms (15s)
// /tools      → once (no interval)
// /config     → once (no interval)
```

### Design Tokens

```javascript
const c = {
    bg: '#0b0d13',       surface: '#141721',    surfaceAlt: '#1a1e2e',
    border: '#232840',   borderLight: '#2e3452',
    text: '#e4e8f1',     textDim: '#8891a8',    textFaint: '#5c637a',
    accent: '#7c6aef',   // Purple
    green: '#34d399',    red: '#f87171',
    orange: '#fbbf24',   cyan: '#22d3ee',       pink: '#f472b6',
}
```

### Phase Metadata

```javascript
const PHASE_META = {
    triage:       { icon: '🔍', label: 'Triage',       color: orange, effort: 'Low' },
    diagnosis:    { icon: '🧠', label: 'Diagnosis',    color: cyan,   effort: 'High' },
    remediation:  { icon: '🔧', label: 'Remediation',  color: accent, effort: 'Medium' },
    verification: { icon: '✅', label: 'Verification', color: green,  effort: 'Disabled' },
}
```

---

## 19. Docker & Deployment

### docker-compose.yml

```yaml
services:
  backend:
    build: ./backend
    env_file: .env
    environment: PYTHONPATH=/app
    volumes:
      - sentry-data:/app/data              # Persistent memory store
      - ./watched:/app/watched              # Sample log files
      - ${SERVICE_HOST_PATH}:/app/workspace # User's service source code
    ports: ["8000:8000"]
    security_opt: [no-new-privileges:true]
    healthcheck: python urllib check on /api/health

  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    depends_on: backend (healthy)
    read_only: true
    tmpfs: [/tmp, /var/cache/nginx, /var/run]
    security_opt: [no-new-privileges:true]

volumes:
  sentry-data:
```

### Backend Dockerfile

```dockerfile
FROM python:3.12-slim
RUN groupadd -r sentry && useradd -r -g sentry sentry
COPY requirements.txt → pip install
COPY . /app/backend/
RUN mkdir /app/data /app/watched && chown sentry:sentry /app
USER sentry
CMD uvicorn backend.api.app:app --host 0.0.0.0 --port 8000
```

### Frontend Dockerfile

```dockerfile
# Stage 1: Build
FROM node:20-alpine
npm install → npm run build

# Stage 2: Serve
FROM nginx:alpine
COPY dist → /usr/share/nginx/html
COPY nginx.conf → /etc/nginx/conf.d/default.conf
```

### nginx.conf

```nginx
server {
    listen 3000;
    # Security headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, CSP, Referrer-Policy
    # CSP: default-src 'self'; style-src 'self' 'unsafe-inline' fonts.googleapis.com;
    #      font-src fonts.gstatic.com; connect-src 'self' http://backend:8000;

    location /api/ {
        proxy_pass http://backend:8000/api/;
        proxy_read_timeout 120s;
    }

    location / {
        try_files $uri $uri/ /index.html;  # SPA fallback
    }

    location ~* \.(js|css|png|...)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### Dependencies (`requirements.txt`)

```
fastapi==0.115.0, uvicorn==0.30.0, anthropic==0.39.0, openai>=1.30.0,
aiohttp==3.10.0, pydantic==2.9.0, python-dotenv==1.0.1, pyyaml>=6.0,
langgraph>=0.2.0, langchain-core>=0.3.0,
pytest==8.3.0, pytest-asyncio==0.24.0, pytest-cov==5.0.0, httpx==0.27.0
```

---

## 20. Testing

### Test Configuration (`pytest.ini`)

```ini
[pytest]
asyncio_mode = auto
testpaths = backend/tests
```

### Test Coverage Summary

**442 tests across 16 test files — 97% coverage** (enforced minimum: 95%)

| File | Count | Coverage Area |
|------|------:|---------------|
| `test_zero_trust.py` | 62 | NHI Vault (registration, credentials, kill switch, expiry), AI Gateway (injection detection, PII scanning, redaction), Audit Log (hash chain, integrity, tamper detection), Agent Throttle (rate limiting, reset), Tool Registry (role-based access) |
| `test_agents.py` | 59 | All 5 agent roles + Supervisor routing (9 paths), NHI registration per role, tool isolation, Gateway integration |
| `test_tools.py` | 71 | Read-only tools, active tools, executor hardening (arg validation, retry, empty output), DISABLED mode blocks all |
| `test_schemas.py` | 46 | TriageResult parsing (all severities, verdicts, fallbacks), DiagnosisResult, RemediationResult, VerificationResult (negation handling), parse_safe + _try_extract_json |
| `test_llm_client.py` | 38 | Effort budget mapping, OpusLLMClient, BedrockGatewayLLMClient (tool format conversion), create_llm_client factory, retry/backoff, transient errors |
| `test_api.py` | 29 | All REST endpoints via httpx TestClient: health, status, incidents, trigger, memory, tools, config, security, watcher start/stop |
| `test_security.py` | 26 | Path validation (traversal blocking), command whitelist, URL allow-list, input sanitization, STOP_SENTRY file, audit mode detection |
| `test_engine.py` | 18 | Orchestrator lifecycle, circuit breaker integration, memory save, resolved list FIFO cap |
| `test_watcher.py` | 14 | Log polling, file rotation, queue full, PermissionError handling |
| `test_config.py` | 14 | 12-factor config loading, defaults, env var parsing |
| `test_services.py` | 14 | Service registry, context builder, topology fingerprint |
| `test_domain_models.py` | 22 | Pydantic domain models, serialization, defaults |
| `test_patch_tool.py` | 11 | apply_patch audit + active mode, git apply --check, backup/restore |
| `test_circuit_breaker.py` | 10 | Cost tracking, trip threshold, auto-reset after window, manual reset, rate limiter cooldown |
| `test_memory.py` | 6 | Memory store CRUD, similarity search, compaction |

---

## 21. Known Bug Fixes (Documented in Code)

These are inline comments marking iterative improvements:

| # | Location | Fix |
|---|----------|-----|
| 1 | `triage_agent.py`, `detective_agent.py`, `surgeon_agent.py` | `ILLMClient.analyze()` takes `(prompt, effort, tools)` — combined system+user into single prompt string |
| 2 | `detective_agent.py`, `surgeon_agent.py` | `IToolExecutor.execute()` takes a single `ToolCall` object, not separate arguments |
| 4 | `models.py` `_phase_summary()` | resolved/escalated are terminal states, not phases; all 4 phases should show complete when resolved |
| 5 | `log_watcher.py` | Use `datetime.now(timezone.utc)` instead of deprecated `datetime.utcnow()` |
| 6 | `log_watcher.py` | Count lines correctly when reading from a non-zero position |
| 9 | `circuit_breaker.py` `RateLimiter.is_allowed()` | Auto-record action on success to prevent unlimited retries of failing operations |
| 10 | `executor.py` | Enforce AUDIT mode centrally at executor level for active tools (safety net) |
| 11 | `graph.py` `_diagnosis_node` | Truncate tool results to 2000 chars each; cap total prompt at 50K to prevent token explosion |
| 13 | `models.py` `Incident.to_dict()` | Handle log_events that may be LogEvent objects or dicts |
| 14 | `executor.py` | DISABLED mode blocks ALL tool execution (not just active tools) |

---

## 22. Key Design Patterns

### Factory Pattern
- `create_llm_client(config)` → `OpusLLMClient` or `BedrockGatewayLLMClient`
- `create_default_registry()` → pre-configured `TrustedToolRegistry`

### Strategy Pattern
- `ILLMClient` interface with two implementations (Anthropic direct, Bedrock Gateway)
- Effort levels ("low"/"medium"/"high"/"disabled") select thinking budget strategy

### State Machine
- LangGraph `StateGraph` with typed `IncidentGraphState` flowing through 4 nodes
- Conditional routing via `_route_after_triage` and `_route_after_verification`

### Decorator Pattern (Security)
- `BaseAgent` wraps all operations with: credential issuance → input scanning → execution → output scanning → credential revocation

### Chain of Responsibility
- Tool execution: MCPToolExecutor → STOP check → DISABLED check → AUDIT check → tool-level validation → execute

### Observer Pattern
- LogWatcher → async Queue → background task → Orchestrator event handler

### Template Method
- `BaseAgent` defines the security workflow skeleton; concrete agents implement `run()`

---

## 23. Architectural Notes & Known Gaps

1. **Dual implementation:** `agents/` classes and `graph.py` nodes implement overlapping logic. The graph is the production path; agents are for unit testing.

2. **ValidatorAgent bug:** `validator_agent.py` line 62 calls `self._llm.analyze(system_prompt=..., user_message=..., thinking=...)` which doesn't match the `ILLMClient.analyze(prompt, effort, tools)` signature.

3. **No authentication:** API has no auth middleware. Anyone on the network can trigger incidents, start/stop watcher.

4. **Unbounded resolved list:** `_resolved_incidents` in `Orchestrator` is an in-memory list with no eviction or pagination.

5. **No WebSocket:** Dashboard polls every 3s via HTTP instead of push.

6. **No INotifier implementation:** Slack/PagerDuty integration is defined as interface only.

7. **Memory is keyword-only:** No semantic/vector similarity — uses set intersection of keyword tags.

8. **Single-file frontend:** All ~700 lines in one `App.jsx`. Works but harder to maintain.

9. **pyyaml in requirements:** Listed but not used (leftover from when service config was YAML-based; now everything is .env).

---

## 24. How to Run

```bash
# Clone and configure
cp .env.example .env
# Edit .env: set ANTHROPIC_API_KEY and SERVICE_HOST_PATH

# Docker (production)
docker compose up --build
# Dashboard: http://localhost:3000
# API: http://localhost:8000/api/health

# Tests
cd backend && pip install -r requirements.txt && cd ..
python -m pytest -v   # 442 tests, 97% coverage
```

---

## 25. Quick Reference: Where to Find Things

| If you need to... | Look at... |
|-------------------|-----------|
| Add a new MCP tool | `mcp_tools/` (create class) + `executor.py` (register) + `tool_registry.py` (add to roles) |
| Add a new agent | `agents/` (extend BaseAgent) + `vault.py` (add AgentRole) + `tool_registry.py` (define permissions) |
| Change LLM prompts | `orchestrator/graph.py` (production) or `agents/*.py` (standalone) |
| Add new LLM provider | `orchestrator/llm_client.py` (implement ILLMClient + add to factory) |
| Add API endpoint | `api/app.py` |
| Modify security rules | `shared/security.py` (validation) or `shared/config.py` (defaults) |
| Change UI | `frontend/src/App.jsx` |
| Add prompt injection pattern | `shared/ai_gateway.py` INJECTION_PATTERNS |
| Add PII detection pattern | `shared/ai_gateway.py` PII_PATTERNS |
| Add error log pattern | `shared/config.py` WatcherConfig.error_patterns |
| Add allowed domain | `shared/config.py` SecurityConfig.allowed_fetch_domains |
| Add allowed command | `shared/config.py` SecurityConfig.allowed_diagnostic_commands |
