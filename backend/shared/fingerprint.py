"""
Canonical log-event fingerprinting + keyword extraction.

Why this module exists
----------------------
Before this module, the dedup fingerprint was computed in TWO places
(``backend.orchestrator.engine._compute_event_fingerprint`` and
``backend.persistence.repositories.incident_repo.compute_fingerprint``)
as ``sha256(source_file|matched_pattern|raw_line)``. Hashing the *raw*
line meant that real-world log storms — where every line embeds a
timestamp, PID, request id, port, or hex address — produced a distinct
fingerprint per line. The result: N "identical" errors → N incidents →
N-fold LLM spend, defeating the dedup window entirely.

This module is the single source of truth for:

* :func:`normalize_log_line` — collapse the variable parts of a log
  line (timestamps, UUIDs, hex addresses, IPs, bare numbers, runs of
  whitespace) into stable placeholders so that two occurrences of the
  *same* error fingerprint identically. This mirrors how production
  alerting systems (Sentry.io event grouping, Datadog log clustering)
  group events.
* :func:`compute_fingerprint` — ``sha256(source|pattern|normalized_line)``.
  Used by both the orchestrator's in-memory dedup cache and the
  persistence layer's DB-backed dedup, guaranteeing they always agree.
* :func:`extract_keywords` — distinctive-token extraction used for
  memory storage/retrieval vectors. Replaces the naive
  ``symptom.lower().split()[:5]`` which kept stop-words ("the", "on")
  and noise tokens ("error:") while dropping the distinctive ones that
  appear later in the line.

Dependency-free by design: importable from the orchestrator without
pulling in SQLAlchemy, and from the persistence layer without pulling
in LangGraph.
"""

from __future__ import annotations

import hashlib
import re

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

# Order matters: longer/more-specific patterns first so e.g. a UUID isn't
# first shredded by the bare-number pass.
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_ISO_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_CLOCK_RE = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b")
_HEX_RE = re.compile(r"\b0[xX][0-9a-fA-F]+\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{12,}\b")  # request ids, hashes
_NUM_RE = re.compile(r"\d+")
_WS_RE = re.compile(r"\s+")


def normalize_log_line(line: str) -> str:
    """Collapse the variable parts of a log line into placeholders.

    Two log lines that describe the *same* error but differ only in
    timestamps, PIDs, ports, request ids, IPs, or memory addresses
    normalize to the same string — which is exactly what the dedup
    fingerprint wants.

    >>> normalize_log_line("ERROR [2026-01-02T10:11:12] worker 4123 died")
    'error [<ts>] worker <n> died'
    """
    text = (line or "").strip()
    if not text:
        return ""
    text = _UUID_RE.sub("<uuid>", text)
    text = _ISO_TS_RE.sub("<ts>", text)
    text = _CLOCK_RE.sub("<ts>", text)
    text = _HEX_RE.sub("<hex>", text)
    text = _IPV4_RE.sub("<ip>", text)
    text = _LONG_HEX_RE.sub("<hex>", text)
    text = _NUM_RE.sub("<n>", text)
    text = _WS_RE.sub(" ", text)
    return text.lower()


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def compute_fingerprint(
    source_file: str, matched_pattern: str, line_content: str
) -> str:
    """Deterministic dedup key for a log event.

    Format: ``sha256(source_file|matched_pattern|normalized_line)``.

    * The source file is kept verbatim so errors from *different*
      services/files stay distinct.
    * The line content is normalized (see :func:`normalize_log_line`)
      so a 1000-line log storm of the same error — each line carrying a
      fresh timestamp/PID — collapses to ONE fingerprint.
    """
    src = source_file or ""
    pat = matched_pattern or ""
    line = normalize_log_line(line_content or "")
    material = f"{src}|{pat}|{line}".encode("utf-8", errors="replace")
    return hashlib.sha256(material).hexdigest()


# ---------------------------------------------------------------------------
# Keyword extraction (memory retrieval vectors)
# ---------------------------------------------------------------------------

# Common English glue + log-level noise words that carry zero retrieval
# signal — virtually every log line contains "error", so matching on it
# makes every memory entry "relevant" to every incident.
_STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "been", "but", "by",
    "for", "from", "had", "has", "have", "in", "into", "is", "it",
    "its", "of", "on", "or", "that", "the", "this", "to", "was",
    "were", "while", "with", "will", "not", "no", "after", "before",
    # log noise
    "error", "errors", "err", "warn", "warning", "critical", "fatal",
    "exception", "failed", "failure", "fail", "info", "debug", "trace",
    "log", "message",
})

# Tokens: words of length >= 3 made of letters/digits/underscore/dot/dash.
# Digits-only tokens of length >= 3 (ports, HTTP status codes) ARE kept —
# "502" and "5432" are among the most distinctive tokens in a log line.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]{2,}")


def extract_keywords(text: str, k: int = 8) -> list[str]:
    """Extract up to ``k`` distinctive lowercase keywords from ``text``.

    Replaces the old ``text.lower().split()[:5]`` heuristic which kept
    stop-words and clipped distinctive tokens appearing after position 5.

    Properties:
    * order-preserving and deduplicated;
    * stop-words and 1-2 char fragments dropped;
    * numeric tokens (ports, status codes) kept;
    * trailing punctuation inside tokens trimmed (``"refused."`` → ``"refused"``).
    """
    if not text:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in _TOKEN_RE.findall(text):
        token = raw.strip(".-_").lower()
        if len(token) < 3:
            continue
        if token in _STOPWORDS:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
        if len(out) >= k:
            break
    return out


__all__ = ["compute_fingerprint", "extract_keywords", "normalize_log_line"]
