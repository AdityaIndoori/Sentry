# Manual Testing Guide

> How to verify every improvement made to the Sentry codebase.

---

## Prerequisites

```bash
cd e:\Sentry
pip install -r backend/requirements.txt
```

---

## 1. Run the Full Test Suite (Quick Verification)

This single command verifies everything at once:

```bash
python -m pytest backend/tests/ -v --no-cov
```

**Expected:** `518 passed` (was 442 before improvements)

To also check coverage:

```bash
python -m pytest backend/tests/ -v
```

**Expected:** Coverage report prints. `graph.py` is now included (was excluded before).

---

## 2. Verify Each Improvement Individually

### 2.1 ValidatorAgent Signature Fix

**What changed:** `backend/agents/validator_agent.py` — `analyze()` now called with `(prompt=, effort=)` instead of wrong kwargs.

**How to test:**

```bash
python -m pytest backend/tests/test_bug_regressions.py::TestBugFix1_AnalyzeSignature::test_validator_agent_correct_signature -v --no-cov
```

**Expected:** `PASSED`. This test uses `spec=ILLMClient` — if the old wrong signature were still there, it would fail with `TypeError`.

**Bonus — prove the old code would have failed:**

```python
# In a Python shell:
from unittest.mock import AsyncMock
from backend.shared.interfaces import ILLMClient

llm = AsyncMock(spec=ILLMClient)
# This would have been the OLD call — it will raise TypeError:
import asyncio
try:
    asyncio.run(llm.analyze(system_prompt="test", user_message="test", thinking={"type": "disabled"}))
except TypeError as e:
    print(f"CAUGHT: {e}")
# Output: CAUGHT: analyze() got an unexpected keyword argument 'system_prompt'
```

---

### 2.2 pyyaml Removed

**How to test:**

```bash
# Check it's gone from requirements.txt:
findstr "pyyaml" backend\requirements.txt
```

**Expected:** No output (not found).

```bash
# Verify no code imports it:
findstr /s /i "import yaml" backend\*.py
```

**Expected:** No output.

---

### 2.3 Interface Inheritance (Orchestrator, LogWatcher)

**How to test:**

```python
# In a Python shell:
from backend.orchestrator.engine import Orchestrator
from backend.shared.interfaces import IOrchestrator
print(issubclass(Orchestrator, IOrchestrator))  # True

from backend.watcher.log_watcher import LogWatcher
from backend.shared.interfaces import ILogWatcher
print(issubclass(LogWatcher, ILogWatcher))  # True
```

**Expected:** Both print `True`.

---

### 2.4 Duplicate _sanitize() Removed

**How to test:**

```bash
# Check the old function is gone:
findstr "_DANGEROUS_CHARS" backend\agents\base_agent.py
```

**Expected:** No output (removed).

```bash
# Check SecurityGuard is now accepted:
findstr "security" backend\agents\base_agent.py
```

**Expected:** Shows `security: Optional[SecurityGuard] = None` in `__init__`.

---

### 2.5 Dummy-Service Bug Comments Updated

**How to test:**

```bash
findstr "FIXED" dummy-service\routes\checkout.py
findstr "FIXED" dummy-service\routes\products.py
findstr "FIXED" dummy-service\config\settings.py
findstr "ACTIVE" dummy-service\config\db.py
```

**Expected:** Shows `(FIXED)` for bugs #2, #3, #4 and `(ACTIVE)` for bug #1.

---

### 2.6 Spec'd Mock Fixtures in conftest.py

**How to test:**

```bash
python -m pytest backend/tests/test_bug_regressions.py -v --no-cov
```

**Expected:** All 13 tests pass. These use `spec=ILLMClient` which enforces the real interface.

**Manual proof that spec= works:**

```python
from unittest.mock import AsyncMock
from backend.shared.interfaces import ILLMClient

# WITHOUT spec — accepts any garbage:
bad_mock = AsyncMock()
import asyncio
asyncio.run(bad_mock.analyze(foo=1, bar=2))  # No error!

# WITH spec — enforces interface:
good_mock = AsyncMock(spec=ILLMClient)
try:
    asyncio.run(good_mock.analyze(foo=1, bar=2))
except TypeError as e:
    print(f"CAUGHT: {e}")  # TypeError raised!
```

---

### 2.7 Regression Tests

**How to test:**

```bash
python -m pytest backend/tests/test_bug_regressions.py -v --no-cov
```

**Expected:** 13 tests covering bug fixes #1, #4, #9, #10, #14 — all pass.

---

### 2.8 Graph.py Coverage + Prompt Builder Tests

**How to test:**

```bash
# Verify graph.py is no longer excluded:
findstr "graph.py" .coveragerc
```

**Expected:** No output (removed from omit list).

```bash
# Run the new graph helper tests:
python -m pytest backend/tests/test_graph_helpers.py -v --no-cov
```

**Expected:** 25 tests pass — covering all 5 prompt builder functions.

---

### 2.9 Shared Prompts Module

**How to test:**

```bash
# Verify agents import from shared prompts:
findstr "from backend.shared.prompts import" backend\agents\*.py
```

**Expected:** All 4 agents show imports from `backend.shared.prompts`.

```bash
# Verify no agent defines its own SYSTEM_PROMPT constant:
findstr /c:"SYSTEM_PROMPT = " backend\agents\triage_agent.py
findstr /c:"SYSTEM_PROMPT = " backend\agents\detective_agent.py
findstr /c:"SYSTEM_PROMPT = " backend\agents\surgeon_agent.py
findstr /c:"SYSTEM_PROMPT = " backend\agents\validator_agent.py
```

**Expected:** No output (prompts are imported, not defined inline).

---

### 2.10 Schema Parsers in Agents

**How to test:**

```bash
# Verify agents use _parse_using_schema instead of _parse_response:
findstr "_parse_using_schema" backend\agents\triage_agent.py
findstr "_parse_using_schema" backend\agents\detective_agent.py
findstr "_parse_using_schema" backend\agents\validator_agent.py
```

**Expected:** Each file shows the method.

```bash
# Run agent tests to verify parsing still works:
python -m pytest backend/tests/test_agents.py -v --no-cov -k "parse"
```

**Expected:** Parse-related tests pass.

---

### 2.11 Named Constants Module

**How to test:**

```bash
python -c "from backend.shared.constants import *; print(MAX_EVENT_QUEUE_SIZE, MAX_PROMPT_SIZE, MAX_RESOLVED_INCIDENTS)"
```

**Expected:** `100 50000 100`

---

### 2.12 __all__ Exports

**How to test:**

```bash
python -c "import backend.shared; print(backend.shared.__all__)"
python -c "import backend.agents; print(backend.agents.__all__)"
python -c "import backend.orchestrator; print(backend.orchestrator.__all__)"
```

**Expected:** Each prints a list of module names.

---

## 3. Run the Full Suite with Coverage

```bash
python -m pytest backend/tests/ -v --tb=short
```

**Expected:**
- `518 passed`
- Coverage report shows `graph.py` is now measured
- No test failures

---

## 4. Visual Diff of All Changes

To see exactly what changed:

```bash
git log --oneline bfb7950..HEAD
```

Shows 12 commits. To see the full diff:

```bash
git diff bfb7950..HEAD --stat
```

To inspect a specific commit:

```bash
git show 0c39c68   # ValidatorAgent fix
git show 9b734bd   # shared prompts.py
git show f82ac37   # graph.py coverage + tests
```

---

## 5. Docker Build Test (Optional)

If you want to verify the Docker build still works (includes test stage):

```bash
docker compose build backend
```

**Expected:** Build succeeds — the Dockerfile test stage runs all tests and will fail the build if any test fails.

---

## Quick Checklist

| # | What to Verify | Command | Expected |
|---|---------------|---------|----------|
| 1 | All tests pass | `python -m pytest backend/tests/ --no-cov -q` | `518 passed` |
| 2 | ValidatorAgent fix | `python -m pytest -k test_validator_agent_correct_signature --no-cov` | `1 passed` |
| 3 | pyyaml removed | `findstr "pyyaml" backend\requirements.txt` | No output |
| 4 | Interfaces wired | `python -c "from backend.orchestrator.engine import Orchestrator; from backend.shared.interfaces import IOrchestrator; print(issubclass(Orchestrator, IOrchestrator))"` | `True` |
| 5 | Graph.py in coverage | `findstr "graph.py" .coveragerc` | No output |
| 6 | Shared prompts exist | `python -c "from backend.shared.prompts import TRIAGE_SYSTEM_PROMPT; print('OK')"` | `OK` |
| 7 | Constants exist | `python -c "from backend.shared.constants import MAX_PROMPT_SIZE; print(MAX_PROMPT_SIZE)"` | `50000` |
| 8 | New test files | `dir backend\tests\test_bug_regressions.py backend\tests\test_graph_helpers.py` | Both exist |
