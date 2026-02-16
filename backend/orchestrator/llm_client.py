"""
LLM client implementations for Claude Sentry.
Supports both direct Anthropic API and AWS Bedrock Access Gateway (OpenAI-compatible).
Implements ILLMClient with adaptive thinking support.
"""

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
    """Claude Opus 4.6 API client via direct Anthropic SDK."""

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

        try:
            response = await self._client.messages.create(**kwargs)
            usage = response.usage
            self._total_input += usage.input_tokens
            self._total_output += usage.output_tokens
            return self._parse_response(response, usage)
        except TypeError as e:
            logger.warning(f"SDK parameter error, retrying without thinking: {e}")
            kwargs.pop("thinking", None)
            try:
                response = await self._client.messages.create(**kwargs)
                usage = response.usage
                self._total_input += usage.input_tokens
                self._total_output += usage.output_tokens
                return self._parse_response(response, usage)
            except Exception as e2:
                logger.error(f"Anthropic API error (retry): {e2}")
                return {"text": "", "tool_calls": [], "error": str(e2), "input_tokens": 0, "output_tokens": 0}
        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            return {"text": "", "tool_calls": [], "error": str(e), "input_tokens": 0, "output_tokens": 0}

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
        # Lazy import so the openai package is only required when this provider is used
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for Bedrock Gateway support. "
                "Install it with: pip install openai>=1.30.0"
            ) from exc

        self._client = AsyncOpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
        )
        self._total_input = 0
        self._total_output = 0

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
            f"You are Claude Sentry, an autonomous server monitoring agent. "
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

        try:
            response = await self._client.chat.completions.create(**kwargs)
            return self._parse_response(response)
        except Exception as e:
            logger.error(f"Bedrock Gateway API error: {e}")
            return {"text": "", "tool_calls": [], "error": str(e), "input_tokens": 0, "output_tokens": 0}

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
