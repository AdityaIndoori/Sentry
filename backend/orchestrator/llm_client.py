"""
LLM client implementations for Sentry.
Supports both direct Anthropic API and AWS Bedrock Access Gateway (OpenAI-compatible).
Implements ILLMClient with adaptive thinking support.

Production hardening:
- All LLM calls wrapped in asyncio.wait_for() with configurable timeout
- Exponential backoff retry (3 attempts) on transient failures
- Clear error categorization: transient vs permanent failures
"""

import asyncio
import json
import logging
from typing import Optional, Union

import anthropic

from backend.shared.config import (
    AnthropicConfig,
    AppConfig,
    BedrockGatewayConfig,
    LLMProvider,
)
from backend.shared.interfaces import ILLMClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Retry / timeout constants
# ---------------------------------------------------------------------------

LLM_CALL_TIMEOUT_SECONDS = 120      # Max time for a single LLM API call
LLM_MAX_RETRIES = 3                  # Total attempts (1 initial + 2 retries)
LLM_BACKOFF_BASE_SECONDS = 2.0      # Exponential backoff base: 2s, 4s, 8s

# Errors that are worth retrying (transient)
_TRANSIENT_ERROR_KEYWORDS = (
    "timeout", "timed out", "rate_limit", "rate limit",
    "overloaded", "capacity", "529", "503", "502",
    "connection", "reset", "eof", "broken pipe",
)


def _is_transient_error(error: Exception) -> bool:
    """Determine if an error is transient and worth retrying."""
    error_str = str(error).lower()
    return any(keyword in error_str for keyword in _TRANSIENT_ERROR_KEYWORDS)


async def _retry_with_backoff(coro_factory, operation_name: str) -> dict:
    """
    Execute an async operation with timeout + exponential backoff retry.

    Args:
        coro_factory: A callable that returns a new coroutine on each call.
                      (Must be a factory because coroutines can't be re-awaited.)
        operation_name: For logging (e.g., "Anthropic API call").

    Returns:
        The result dict from the coroutine, or an error dict on final failure.
    """
    last_error = None
    for attempt in range(1, LLM_MAX_RETRIES + 1):
        try:
            result = await asyncio.wait_for(
                coro_factory(),
                timeout=LLM_CALL_TIMEOUT_SECONDS,
            )
            return result
        except asyncio.TimeoutError:
            last_error = TimeoutError(
                f"{operation_name} timed out after {LLM_CALL_TIMEOUT_SECONDS}s"
            )
            logger.warning(
                f"{operation_name} timeout (attempt {attempt}/{LLM_MAX_RETRIES})"
            )
        except Exception as e:
            last_error = e
            if not _is_transient_error(e):
                # Permanent error — don't retry
                logger.error(f"{operation_name} permanent error: {e}")
                return {
                    "text": "", "tool_calls": [], "thinking": "",
                    "error": str(e), "input_tokens": 0, "output_tokens": 0,
                }
            logger.warning(
                f"{operation_name} transient error (attempt {attempt}/{LLM_MAX_RETRIES}): {e}"
            )

        # Backoff before retry (except after final attempt)
        if attempt < LLM_MAX_RETRIES:
            backoff = LLM_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
            logger.info(f"{operation_name} retrying in {backoff:.1f}s...")
            await asyncio.sleep(backoff)

    # All retries exhausted
    logger.error(
        f"{operation_name} failed after {LLM_MAX_RETRIES} attempts: {last_error}"
    )
    return {
        "text": "", "tool_calls": [], "thinking": "",
        "error": f"All {LLM_MAX_RETRIES} attempts failed: {last_error}",
        "input_tokens": 0, "output_tokens": 0,
    }

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _effort_to_budget(effort: str) -> int:
    """Map effort level to thinking token budget."""
    budgets = {"low": 2048, "medium": 8192, "high": 32768}
    return budgets.get(effort, 2048)


def _no_api_key_response() -> dict:
    """Standard response when no API key is configured."""
    return {
        "text": (
            "No API key configured. Escalating to human. "
            "This is a critical issue that needs investigation."
        ),
        "tool_calls": [],
        "thinking": "",
        "error": "no_api_key",
        "input_tokens": 0,
        "output_tokens": 0,
    }


# ---------------------------------------------------------------------------
# Direct Anthropic API client
# ---------------------------------------------------------------------------

class OpusLLMClient(ILLMClient):
    """Claude API client via direct Anthropic SDK."""

    def __init__(self, config: AnthropicConfig):
        self._config = config
        self._client = anthropic.AsyncAnthropic(api_key=config.api_key)
        self._total_input = 0
        self._total_output = 0

    async def analyze(
        self,
        prompt: str,
        effort: str = "low",
        tools: Optional[list] = None,
    ) -> dict:
        if not self._config.api_key or self._config.api_key.startswith("sk-ant-your"):
            logger.warning("No valid API key - returning simulated escalation response")
            return _no_api_key_response()

        kwargs = {
            "model": self._config.model,
            "max_tokens": self._config.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

        if effort != "disabled":
            budget = _effort_to_budget(effort)
            try:
                kwargs["thinking"] = {"type": "enabled", "budget_tokens": budget}
            except Exception:
                logger.debug("Thinking parameter not supported, proceeding without it")

        if tools:
            kwargs["tools"] = tools

        return await _retry_with_backoff(
            lambda: self._raw_call(kwargs),
            "Anthropic API call",
        )

    async def _raw_call(self, kwargs: dict) -> dict:
        """Single Anthropic API call attempt (used by retry wrapper)."""
        try:
            response = await self._client.messages.create(**kwargs)
        except TypeError as e:
            # Thinking parameter not supported by this SDK version — retry without it
            logger.warning(f"SDK parameter error, retrying without thinking: {e}")
            kwargs_fallback = {k: v for k, v in kwargs.items() if k != "thinking"}
            response = await self._client.messages.create(**kwargs_fallback)

        usage = response.usage
        self._total_input += usage.input_tokens
        self._total_output += usage.output_tokens
        return self._parse_response(response, usage)

    def _parse_response(self, response, usage) -> dict:
        text_parts = []
        tool_calls = []
        thinking = ""
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append({"id": block.id, "name": block.name, "arguments": block.input})
            elif block.type == "thinking":
                thinking = block.thinking
        return {
            "text": "\n".join(text_parts),
            "tool_calls": tool_calls,
            "thinking": thinking,
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "error": None,
        }

    async def get_usage(self) -> dict:
        return {"total_input_tokens": self._total_input, "total_output_tokens": self._total_output}


# ---------------------------------------------------------------------------
# AWS Bedrock Access Gateway client (OpenAI-compatible API)
# ---------------------------------------------------------------------------

class BedrockGatewayLLMClient(ILLMClient):
    """
    Claude via AWS Bedrock Access Gateway.

    The gateway (https://github.com/aws-samples/bedrock-access-gateway)
    exposes an OpenAI-compatible /v1/chat/completions endpoint.
    We use the ``openai`` Python SDK pointed at the gateway URL.
    """

    def __init__(self, config: BedrockGatewayConfig):
        self._config = config
        self._client = None  # Created lazily on first API call
        self._total_input = 0
        self._total_output = 0

    def _get_client(self):
        """Lazy-create the AsyncOpenAI client on first use.

        This avoids creating async resources that trigger
        'coroutine was never awaited' warnings when the client
        is instantiated but never used (e.g. early-return on missing config).
        """
        if self._client is None:
            try:
                from openai import AsyncOpenAI
            except ImportError as exc:
                raise ImportError(
                    "The 'openai' package is required for Bedrock Gateway support. "
                    "Install it with: pip install openai>=1.30.0"
                ) from exc
            self._client = AsyncOpenAI(
                api_key=self._config.api_key,
                base_url=self._config.base_url,
            )
        return self._client

    async def analyze(
        self,
        prompt: str,
        effort: str = "low",
        tools: Optional[list] = None,
    ) -> dict:
        if not self._config.api_key or not self._config.base_url:
            logger.warning("Bedrock Gateway not configured - returning simulated escalation")
            return _no_api_key_response()

        messages = [{"role": "user", "content": prompt}]

        # Build system prompt with effort hint so the model adapts depth
        system_prompt = (
            f"You are Sentry, an autonomous server monitoring agent. "
            f"Analysis effort level: {effort}. "
            f"If effort is 'low', be concise. If 'high', think deeply and explore all angles."
        )

        kwargs: dict = {
            "model": self._config.model,
            "max_tokens": self._config.max_tokens,
            "messages": [{"role": "system", "content": system_prompt}] + messages,
        }

        # Convert Anthropic-style tool definitions to OpenAI function-calling format
        if tools:
            kwargs["tools"] = self._convert_tools(tools)

        return await _retry_with_backoff(
            lambda: self._raw_call(kwargs),
            "Bedrock Gateway API call",
        )

    async def _raw_call(self, kwargs: dict) -> dict:
        """Single Bedrock Gateway API call attempt (used by retry wrapper)."""
        client = self._get_client()
        response = await client.chat.completions.create(**kwargs)
        return self._parse_response(response)

    def _convert_tools(self, anthropic_tools: list) -> list:
        """
        Convert Anthropic tool definitions to OpenAI function-calling format.

        Anthropic format:
            {"name": "...", "description": "...", "input_schema": {...}}
        OpenAI format:
            {"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}
        """
        openai_tools = []
        for tool in anthropic_tools:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {}),
                },
            })
        return openai_tools

    def _parse_response(self, response) -> dict:
        """Parse OpenAI-format response into our standard dict."""
        choice = response.choices[0] if response.choices else None
        if not choice:
            return {"text": "", "tool_calls": [], "error": "empty_response", "input_tokens": 0, "output_tokens": 0}

        message = choice.message
        text = message.content or ""

        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except json.JSONDecodeError:
                    args = {"raw": tc.function.arguments}
                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": args,
                })

        # Token usage
        usage = response.usage
        input_tokens = usage.prompt_tokens if usage else 0
        output_tokens = usage.completion_tokens if usage else 0
        self._total_input += input_tokens
        self._total_output += output_tokens

        return {
            "text": text,
            "tool_calls": tool_calls,
            "thinking": "",  # Gateway doesn't expose thinking blocks
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "error": None,
        }

    async def get_usage(self) -> dict:
        return {"total_input_tokens": self._total_input, "total_output_tokens": self._total_output}


# ---------------------------------------------------------------------------
# Factory function (Open/Closed Principle - extend without modifying callers)
# ---------------------------------------------------------------------------

def create_llm_client(config: AppConfig) -> ILLMClient:
    """
    Factory: create the appropriate LLM client based on configuration.

    Supports:
      - LLM_PROVIDER=anthropic  → Direct Anthropic API (OpusLLMClient)
      - LLM_PROVIDER=bedrock_gateway → AWS Bedrock Access Gateway (BedrockGatewayLLMClient)
    """
    provider = config.llm_provider

    if provider == LLMProvider.BEDROCK_GATEWAY:
        gw = config.bedrock_gateway
        if gw.base_url and gw.api_key:
            logger.info(
                f"Using Bedrock Access Gateway at {gw.base_url} "
                f"(model: {gw.model})"
            )
            return BedrockGatewayLLMClient(gw)
        else:
            logger.warning(
                "LLM_PROVIDER=bedrock_gateway but BEDROCK_GATEWAY_BASE_URL or "
                "BEDROCK_GATEWAY_API_KEY is not set. Falling back to Anthropic."
            )

    # Default: direct Anthropic
    logger.info(f"Using direct Anthropic API (model: {config.anthropic.model})")
    return OpusLLMClient(config.anthropic)
