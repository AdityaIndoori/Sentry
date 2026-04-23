"""
Deterministic fake LLM client for E2E tests.

Implements the full `ILLMClient` contract (`analyze`, `get_usage`) so it
is a drop-in replacement for `OpusLLMClient` / `BedrockGatewayLLMClient`
inside the orchestrator. Real Anthropic / Bedrock APIs are NEVER hit
from the test suite.

Scripted responses are matched against a rule list. Each rule has:

  - a predicate taking (prompt, effort, tools) and returning True/False
  - a response dict matching ILLMClient.analyze()'s return contract

Rules are tried in order; the first match wins. A default rule is
required.

Typical use:

    llm = FakeLLMClient([
        Rule.when_prompt_contains("Triage", response={"text": "SEVERITY: low\\nVERDICT: FALSE_POSITIVE\\nSUMMARY: bot"}),
        Rule.when_prompt_contains("Detective", response={"text": "ROOT CAUSE: disk full\\nRECOMMENDED FIX: clear /tmp"}),
        Rule.when_prompt_contains("Surgeon", response={"text": "FIX PROPOSED: cleared /tmp\\nFIX DETAILS: ok"}),
        Rule.when_prompt_contains("Validator", response={"text": "RESOLVED: true\\nREASON: disk free"}),
        Rule.default(response={"text": "ROOT CAUSE: Unknown"}),
    ])
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from backend.shared.interfaces import ILLMClient

RulePredicate = Callable[[str, str, list | None], bool]


@dataclass
class Rule:
    predicate: RulePredicate
    response: dict
    # Optional async side-effect (e.g. sleep to simulate latency, raise
    # to simulate timeouts). If returns a value, that value becomes the
    # response (overriding `response`). If raises, the exception bubbles
    # up.
    side_effect: Callable[..., Awaitable[Any]] | None = None
    name: str = "rule"

    @classmethod
    def when_prompt_contains(cls, needle: str, response: dict, name: str = "") -> Rule:
        """Match any LLM call whose prompt contains `needle`."""
        return cls(
            predicate=lambda prompt, effort, tools: needle in (prompt or ""),
            response=response,
            name=name or f"prompt~{needle[:32]}",
        )

    @classmethod
    def when_prompt_contains_any(cls, needles: list[str], response: dict, name: str = "") -> Rule:
        """Match any LLM call whose prompt contains any of `needles`."""
        return cls(
            predicate=lambda prompt, effort, tools: any(n in (prompt or "") for n in needles),
            response=response,
            name=name or f"prompt~any({','.join(n[:16] for n in needles)})",
        )

    @classmethod
    def when_effort_is(cls, effort: str, response: dict, name: str = "") -> Rule:
        return cls(
            predicate=lambda prompt, eff, tools: eff == effort,
            response=response,
            name=name or f"effort={effort}",
        )

    @classmethod
    def always(cls, response: dict, name: str = "always") -> Rule:
        return cls(predicate=lambda *a, **kw: True, response=response, name=name)

    @classmethod
    def default(cls, response: dict) -> Rule:
        return cls.always(response, name="default")

    @classmethod
    def raising(cls, predicate: RulePredicate, exc: BaseException, name: str = "raise") -> Rule:
        async def _raise(*_a, **_kw):
            raise exc
        return cls(predicate=predicate, response={}, side_effect=_raise, name=name)


DEFAULT_TRIAGE = {
    "text": "SEVERITY: medium\nVERDICT: INVESTIGATE\nSUMMARY: unknown error",
    "thinking": "",
    "tool_calls": [],
    "input_tokens": 50,
    "output_tokens": 20,
    "error": None,
}

DEFAULT_DETECTIVE = {
    "text": "ROOT CAUSE: unknown\nRECOMMENDED FIX: investigate further",
    "thinking": "",
    "tool_calls": [],
    "input_tokens": 100,
    "output_tokens": 40,
    "error": None,
}

DEFAULT_SURGEON = {
    "text": "FIX PROPOSED: none\nFIX DETAILS: dry-run",
    "thinking": "",
    "tool_calls": [],
    "input_tokens": 80,
    "output_tokens": 30,
    "error": None,
}

DEFAULT_VALIDATOR_RESOLVED = {
    "text": "RESOLVED: true\nREASON: looks good",
    "thinking": "",
    "tool_calls": [],
    "input_tokens": 50,
    "output_tokens": 20,
    "error": None,
}

DEFAULT_VALIDATOR_UNRESOLVED = {
    # IMPORTANT: must exercise the negation branch of
    # VerificationResult.parse_safe() which inspects for phrases like
    # "unresolved" / "not resolved" / "failed". A bare "RESOLVED: false"
    # is actually parsed as resolved=True because the string "resolved"
    # appears as a positive keyword with no negation phrase. This text
    # is crafted to match the parser's negation logic.
    "text": "RESOLVED: false\nREASON: fix failed, incident still unresolved — error remains",
    "thinking": "",
    "tool_calls": [],
    "input_tokens": 50,
    "output_tokens": 20,
    "error": None,
}


class FakeLLMClient(ILLMClient):
    """A deterministic scripted LLM client."""

    def __init__(self, rules: list[Rule]):
        if not rules:
            raise ValueError("FakeLLMClient requires at least one rule (and a default)")
        self._rules = rules
        self._total_input = 0
        self._total_output = 0
        self._call_log: list[dict] = []

    async def analyze(
        self, prompt: str, effort: str, tools: list | None = None
    ) -> dict:
        # Record every call for observability tests
        call = {
            "prompt": prompt,
            "effort": effort,
            "tools": [t.get("name") for t in (tools or [])],
        }
        self._call_log.append(call)

        # Find the first matching rule
        for rule in self._rules:
            try:
                if rule.predicate(prompt, effort, tools):
                    if rule.side_effect is not None:
                        result = await rule.side_effect(prompt, effort, tools)
                        if result is not None:
                            return self._record(result)
                    return self._record(rule.response)
            except Exception:  # pragma: no cover  (buggy predicate should not crash the test)
                continue

        # Shouldn't happen if a default rule exists
        raise AssertionError(
            f"FakeLLMClient: no rule matched prompt={prompt[:100]!r} "
            f"effort={effort!r} — always include Rule.default() as the last rule."
        )

    def _record(self, response: dict) -> dict:
        self._total_input += int(response.get("input_tokens", 0))
        self._total_output += int(response.get("output_tokens", 0))
        return response

    def get_usage(self) -> dict:
        return {
            "total_input_tokens": self._total_input,
            "total_output_tokens": self._total_output,
        }

    # ── test introspection ────────────────────────────────────────────

    @property
    def call_log(self) -> list[dict]:
        return list(self._call_log)

    def calls_with_effort(self, effort: str) -> list[dict]:
        return [c for c in self._call_log if c["effort"] == effort]

    def prompts(self) -> list[str]:
        return [c["prompt"] for c in self._call_log]


# ──────────────────────────────────────────────────────────────────────
# Convenience scripted clients for common E2E scenarios
# ──────────────────────────────────────────────────────────────────────


# Unique markers from backend/shared/prompts.py to identify which agent is calling.
# Checked in order validator → surgeon → detective → triage so substrings don't
# collide (for example the Detective prompt mentions "fix" in passing).
_TRIAGE_MARKER = "Triage this production error"
_DETECTIVE_MARKER = "You are diagnosing a server incident"
_SURGEON_MARKER = "Apply a fix using the available tools"
_VALIDATOR_MARKER = "Validator Agent for Sentry"


def resolving_llm() -> FakeLLMClient:
    """Triage INVESTIGATE → Detective finds cause → Surgeon proposes fix → Validator RESOLVED."""
    return FakeLLMClient([
        Rule.when_prompt_contains(_VALIDATOR_MARKER, response=DEFAULT_VALIDATOR_RESOLVED),
        Rule.when_prompt_contains(_SURGEON_MARKER, response={
            **DEFAULT_SURGEON,
            "text": "FIX PROPOSED: increased max_connections\nFIX DETAILS: 10 -> 50",
        }),
        Rule.when_prompt_contains(_DETECTIVE_MARKER, response={
            **DEFAULT_DETECTIVE,
            "text": "ROOT CAUSE: postgres conn pool exhausted\nRECOMMENDED FIX: increase max_connections",
        }),
        Rule.when_prompt_contains(_TRIAGE_MARKER, response={
            **DEFAULT_TRIAGE,
            "text": "SEVERITY: high\nVERDICT: INVESTIGATE\nSUMMARY: likely db outage",
        }),
        Rule.default(response=DEFAULT_DETECTIVE),
    ])


def false_positive_llm() -> FakeLLMClient:
    """Triage immediately returns FALSE_POSITIVE; no further phases."""
    return FakeLLMClient([
        Rule.when_prompt_contains(_VALIDATOR_MARKER, response=DEFAULT_VALIDATOR_RESOLVED),
        Rule.when_prompt_contains(_SURGEON_MARKER, response=DEFAULT_SURGEON),
        Rule.when_prompt_contains(_DETECTIVE_MARKER, response=DEFAULT_DETECTIVE),
        Rule.when_prompt_contains(_TRIAGE_MARKER, response={
            **DEFAULT_TRIAGE,
            "text": "SEVERITY: low\nVERDICT: FALSE POSITIVE\nSUMMARY: bot scan, ignore",
        }),
        Rule.default(response=DEFAULT_DETECTIVE),
    ])


def never_resolves_llm() -> FakeLLMClient:
    """Validator always says RESOLVED: false — used to force ESCALATED via retries."""
    return FakeLLMClient([
        Rule.when_prompt_contains(_VALIDATOR_MARKER, response=DEFAULT_VALIDATOR_UNRESOLVED),
        Rule.when_prompt_contains(_SURGEON_MARKER, response={
            **DEFAULT_SURGEON,
            "text": "FIX PROPOSED: attempted restart\nFIX DETAILS: no-op",
        }),
        Rule.when_prompt_contains(_DETECTIVE_MARKER, response={
            **DEFAULT_DETECTIVE,
            "text": "ROOT CAUSE: unresolvable\nRECOMMENDED FIX: none known",
        }),
        Rule.when_prompt_contains(_TRIAGE_MARKER, response={
            **DEFAULT_TRIAGE,
            "text": "SEVERITY: high\nVERDICT: INVESTIGATE\nSUMMARY: persistent error",
        }),
        Rule.default(response=DEFAULT_DETECTIVE),
    ])
