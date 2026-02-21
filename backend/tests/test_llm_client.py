"""
Tests for LLM client implementations and factory function.
Covers OpusLLMClient, BedrockGatewayLLMClient, create_llm_client factory,
and production hardening: retry/timeout, transient error detection, backoff.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.shared.config import (
    AnthropicConfig,
    AppConfig,
    BedrockGatewayConfig,
    LLMProvider,
    SecurityConfig,
)
from backend.orchestrator.llm_client import (
    BedrockGatewayLLMClient,
    OpusLLMClient,
    _effort_to_budget,
    _is_transient_error,
    _no_api_key_response,
    _retry_with_backoff,
    create_llm_client,
    LLM_CALL_TIMEOUT_SECONDS,
    LLM_MAX_RETRIES,
    LLM_BACKOFF_BASE_SECONDS,
)


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def _make_app_config(
    provider: LLMProvider = LLMProvider.ANTHROPIC,
    anthropic_key: str = "sk-ant-test-key",
    gw_key: str = "",
    gw_url: str = "",
) -> AppConfig:
    return AppConfig(
        security=SecurityConfig(),
        anthropic=AnthropicConfig(api_key=anthropic_key),
        bedrock_gateway=BedrockGatewayConfig(api_key=gw_key, base_url=gw_url),
        llm_provider=provider,
    )


# ---------------------------------------------------------------------------
# Unit tests: helpers
# ---------------------------------------------------------------------------

class TestEffortBudget:
    def test_low(self):
        assert _effort_to_budget("low") == 2048

    def test_medium(self):
        assert _effort_to_budget("medium") == 8192

    def test_high(self):
        assert _effort_to_budget("high") == 32768

    def test_unknown_defaults_low(self):
        assert _effort_to_budget("ultra") == 2048


class TestNoApiKeyResponse:
    def test_returns_escalation_dict(self):
        resp = _no_api_key_response()
        assert resp["error"] == "no_api_key"
        assert "Escalating" in resp["text"]
        assert resp["tool_calls"] == []
        assert resp["input_tokens"] == 0


# ---------------------------------------------------------------------------
# Unit tests: OpusLLMClient
# ---------------------------------------------------------------------------

class TestOpusLLMClientNoKey:
    @pytest.mark.asyncio
    @patch("backend.orchestrator.llm_client.anthropic.AsyncAnthropic")
    async def test_no_key_returns_escalation(self, mock_anthropic):
        client = OpusLLMClient(AnthropicConfig(api_key=""))
        result = await client.analyze("test prompt")
        assert result["error"] == "no_api_key"

    @pytest.mark.asyncio
    @patch("backend.orchestrator.llm_client.anthropic.AsyncAnthropic")
    async def test_placeholder_key_returns_escalation(self, mock_anthropic):
        client = OpusLLMClient(AnthropicConfig(api_key="sk-ant-your-key-here"))
        result = await client.analyze("test prompt")
        assert result["error"] == "no_api_key"

    @pytest.mark.asyncio
    @patch("backend.orchestrator.llm_client.anthropic.AsyncAnthropic")
    async def test_usage_starts_at_zero(self, mock_anthropic):
        client = OpusLLMClient(AnthropicConfig(api_key=""))
        usage = await client.get_usage()
        assert usage["total_input_tokens"] == 0
        assert usage["total_output_tokens"] == 0


# ---------------------------------------------------------------------------
# Unit tests: BedrockGatewayLLMClient
# ---------------------------------------------------------------------------

class TestBedrockGatewayLLMClientNoConfig:
    @pytest.mark.asyncio
    async def test_no_key_returns_escalation(self):
        config = BedrockGatewayConfig(api_key="", base_url="https://gw.example.com/v1")
        client = BedrockGatewayLLMClient(config)
        result = await client.analyze("test prompt")
        assert result["error"] == "no_api_key"

    @pytest.mark.asyncio
    async def test_no_url_returns_escalation(self):
        config = BedrockGatewayConfig(api_key="test-key", base_url="")
        client = BedrockGatewayLLMClient(config)
        result = await client.analyze("test prompt")
        assert result["error"] == "no_api_key"

    @pytest.mark.asyncio
    async def test_usage_starts_at_zero(self):
        config = BedrockGatewayConfig(api_key="k", base_url="https://gw.example.com/v1")
        client = BedrockGatewayLLMClient(config)
        usage = await client.get_usage()
        assert usage["total_input_tokens"] == 0


class TestBedrockGatewayToolConversion:
    def test_converts_anthropic_to_openai_format(self):
        config = BedrockGatewayConfig(api_key="k", base_url="https://gw.example.com/v1")
        client = BedrockGatewayLLMClient(config)

        anthropic_tools = [
            {
                "name": "read_file",
                "description": "Read a file",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            }
        ]

        result = client._convert_tools(anthropic_tools)
        assert len(result) == 1
        assert result[0]["type"] == "function"
        assert result[0]["function"]["name"] == "read_file"
        assert result[0]["function"]["description"] == "Read a file"
        assert result[0]["function"]["parameters"]["type"] == "object"


class TestBedrockGatewayParseResponse:
    def test_parses_text_response(self):
        config = BedrockGatewayConfig(api_key="k", base_url="https://gw.example.com/v1")
        client = BedrockGatewayLLMClient(config)

        # Mock OpenAI response structure
        mock_usage = MagicMock()
        mock_usage.prompt_tokens = 10
        mock_usage.completion_tokens = 20

        mock_message = MagicMock()
        mock_message.content = "This is a test response"
        mock_message.tool_calls = None

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = mock_usage

        result = client._parse_response(mock_response)
        assert result["text"] == "This is a test response"
        assert result["tool_calls"] == []
        assert result["input_tokens"] == 10
        assert result["output_tokens"] == 20
        assert result["error"] is None

    def test_parses_tool_call_response(self):
        config = BedrockGatewayConfig(api_key="k", base_url="https://gw.example.com/v1")
        client = BedrockGatewayLLMClient(config)

        mock_usage = MagicMock()
        mock_usage.prompt_tokens = 15
        mock_usage.completion_tokens = 25

        mock_function = MagicMock()
        mock_function.name = "read_file"
        mock_function.arguments = json.dumps({"path": "/etc/hosts"})

        mock_tool_call = MagicMock()
        mock_tool_call.id = "call_123"
        mock_tool_call.function = mock_function

        mock_message = MagicMock()
        mock_message.content = ""
        mock_message.tool_calls = [mock_tool_call]

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = mock_usage

        result = client._parse_response(mock_response)
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["name"] == "read_file"
        assert result["tool_calls"][0]["arguments"]["path"] == "/etc/hosts"

    def test_handles_empty_choices(self):
        config = BedrockGatewayConfig(api_key="k", base_url="https://gw.example.com/v1")
        client = BedrockGatewayLLMClient(config)

        mock_response = MagicMock()
        mock_response.choices = []

        result = client._parse_response(mock_response)
        assert result["error"] == "empty_response"


# ---------------------------------------------------------------------------
# Unit tests: Factory function
# ---------------------------------------------------------------------------

class TestCreateLLMClient:
    @patch("backend.orchestrator.llm_client.anthropic.AsyncAnthropic")
    def test_default_creates_opus_client(self, mock_anthropic):
        config = _make_app_config(LLMProvider.ANTHROPIC)
        client = create_llm_client(config)
        assert isinstance(client, OpusLLMClient)

    def test_bedrock_gateway_with_valid_config(self):
        config = _make_app_config(
            LLMProvider.BEDROCK_GATEWAY,
            gw_key="test-key",
            gw_url="https://gw.example.com/v1",
        )
        client = create_llm_client(config)
        assert isinstance(client, BedrockGatewayLLMClient)

    @patch("backend.orchestrator.llm_client.anthropic.AsyncAnthropic")
    def test_bedrock_gateway_missing_url_falls_back(self, mock_anthropic):
        config = _make_app_config(
            LLMProvider.BEDROCK_GATEWAY,
            gw_key="test-key",
            gw_url="",  # missing
        )
        client = create_llm_client(config)
        assert isinstance(client, OpusLLMClient)

    @patch("backend.orchestrator.llm_client.anthropic.AsyncAnthropic")
    def test_bedrock_gateway_missing_key_falls_back(self, mock_anthropic):
        config = _make_app_config(
            LLMProvider.BEDROCK_GATEWAY,
            gw_key="",  # missing
            gw_url="https://gw.example.com/v1",
        )
        client = create_llm_client(config)
        assert isinstance(client, OpusLLMClient)


# ===========================================================================
# Hardening tests: _is_transient_error()
# ===========================================================================

class TestIsTransientError:
    """Tests for transient vs permanent error classification."""

    def test_timeout_is_transient(self):
        assert _is_transient_error(Exception("Request timed out")) is True

    def test_rate_limit_is_transient(self):
        assert _is_transient_error(Exception("rate_limit_error: too many requests")) is True

    def test_overloaded_is_transient(self):
        assert _is_transient_error(Exception("Server overloaded, try again")) is True

    def test_503_is_transient(self):
        assert _is_transient_error(Exception("HTTP 503 Service Unavailable")) is True

    def test_502_is_transient(self):
        assert _is_transient_error(Exception("502 Bad Gateway")) is True

    def test_connection_error_is_transient(self):
        assert _is_transient_error(Exception("Connection reset by peer")) is True

    def test_capacity_is_transient(self):
        assert _is_transient_error(Exception("Insufficient capacity")) is True

    def test_invalid_api_key_is_permanent(self):
        assert _is_transient_error(Exception("Invalid API key provided")) is False

    def test_permission_denied_is_permanent(self):
        assert _is_transient_error(Exception("Permission denied for this resource")) is False

    def test_model_not_found_is_permanent(self):
        assert _is_transient_error(Exception("Model not found: claude-invalid")) is False

    def test_empty_error_is_permanent(self):
        assert _is_transient_error(Exception("")) is False


# ===========================================================================
# Hardening tests: _retry_with_backoff()
# ===========================================================================

class TestRetryWithBackoff:
    """Tests for the retry/timeout wrapper around LLM calls."""

    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self):
        """Coroutine succeeds immediately — no retries needed."""
        expected = {"text": "hello", "error": None}

        async def _coro():
            return expected

        result = await _retry_with_backoff(lambda: _coro(), "test op")
        assert result == expected

    @pytest.mark.asyncio
    async def test_retries_on_transient_error(self):
        """Transient error on first call, success on second."""
        call_count = 0

        async def _coro():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Connection reset by peer")
            return {"text": "recovered", "error": None}

        with patch("backend.orchestrator.llm_client.asyncio.sleep", new_callable=AsyncMock):
            result = await _retry_with_backoff(lambda: _coro(), "test op")

        assert result["text"] == "recovered"
        assert result["error"] is None
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_permanent_error_no_retry(self):
        """Permanent error should fail immediately without retrying."""
        call_count = 0

        async def _coro():
            nonlocal call_count
            call_count += 1
            raise Exception("Invalid API key provided")

        result = await _retry_with_backoff(lambda: _coro(), "test op")
        assert call_count == 1  # Only one attempt
        assert result["error"] == "Invalid API key provided"
        assert result["text"] == ""

    @pytest.mark.asyncio
    async def test_all_retries_exhausted(self):
        """All retries fail with transient errors → returns error dict."""
        call_count = 0

        async def _coro():
            nonlocal call_count
            call_count += 1
            raise Exception("Connection timeout")

        with patch("backend.orchestrator.llm_client.asyncio.sleep", new_callable=AsyncMock):
            result = await _retry_with_backoff(lambda: _coro(), "test op")

        assert call_count == LLM_MAX_RETRIES
        assert "failed" in result["error"].lower()
        assert result["input_tokens"] == 0

    @pytest.mark.asyncio
    async def test_timeout_triggers_retry(self):
        """asyncio.TimeoutError should trigger retry, not immediate failure."""
        call_count = 0

        async def _coro():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise asyncio.TimeoutError()
            return {"text": "ok after timeout", "error": None}

        with patch("backend.orchestrator.llm_client.asyncio.sleep", new_callable=AsyncMock):
            # Also patch wait_for to just call the coro directly (we raise TimeoutError manually)
            result = await _retry_with_backoff(lambda: _coro(), "test op")

        assert call_count == 2
        assert result["text"] == "ok after timeout"

    @pytest.mark.asyncio
    async def test_backoff_timing(self):
        """Verify exponential backoff sleep is called with correct values."""
        sleep_calls = []

        async def _mock_sleep(seconds):
            sleep_calls.append(seconds)

        async def _coro():
            raise Exception("overloaded server 529")

        with patch("backend.orchestrator.llm_client.asyncio.sleep", side_effect=_mock_sleep):
            await _retry_with_backoff(lambda: _coro(), "test op")

        # With 3 retries: sleep after attempt 1 and 2, not after attempt 3
        assert len(sleep_calls) == LLM_MAX_RETRIES - 1
        # First backoff: base * 2^0 = 2.0, second: base * 2^1 = 4.0
        assert sleep_calls[0] == LLM_BACKOFF_BASE_SECONDS * 1
        assert sleep_calls[1] == LLM_BACKOFF_BASE_SECONDS * 2


# ===========================================================================
# Hardening tests: OpusLLMClient._raw_call() TypeError handling
# ===========================================================================

class TestOpusRawCallTypeError:
    """Tests for the SDK compatibility fallback when 'thinking' param fails."""

    @pytest.mark.asyncio
    @patch("backend.orchestrator.llm_client.anthropic.AsyncAnthropic")
    async def test_raw_call_retries_without_thinking_on_type_error(self, mock_cls):
        """If create() raises TypeError for 'thinking', retry without it."""
        mock_usage = MagicMock()
        mock_usage.input_tokens = 5
        mock_usage.output_tokens = 10

        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "Fallback response"

        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.usage = mock_usage

        # First call with 'thinking' raises TypeError, second without succeeds
        mock_create = AsyncMock(side_effect=[
            TypeError("unexpected keyword argument 'thinking'"),
            mock_response,
        ])
        mock_instance = MagicMock()
        mock_instance.messages.create = mock_create
        mock_cls.return_value = mock_instance

        client = OpusLLMClient(AnthropicConfig(api_key="sk-ant-real-key"))
        kwargs = {
            "model": "claude-opus-4-0-20250514",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "test"}],
            "thinking": {"type": "enabled", "budget_tokens": 2048},
        }
        result = await client._raw_call(kwargs)
        assert result["text"] == "Fallback response"
        assert result["input_tokens"] == 5
        # Verify create was called twice: once with thinking, once without
        assert mock_create.call_count == 2
        # Second call should NOT have 'thinking' key
        second_call_kwargs = mock_create.call_args_list[1][1]
        assert "thinking" not in second_call_kwargs


# ===========================================================================
# Hardening tests: OpusLLMClient.analyze() full path with retry
# ===========================================================================

class TestOpusAnalyzeWithRetry:
    """Integration test: analyze() → _retry_with_backoff() → _raw_call()."""

    @pytest.mark.asyncio
    @patch("backend.orchestrator.llm_client.anthropic.AsyncAnthropic")
    async def test_analyze_with_disabled_effort_skips_thinking(self, mock_cls):
        """effort='disabled' should not add thinking parameter."""
        mock_usage = MagicMock()
        mock_usage.input_tokens = 10
        mock_usage.output_tokens = 20

        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "Analysis complete"

        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.usage = mock_usage

        mock_create = AsyncMock(return_value=mock_response)
        mock_instance = MagicMock()
        mock_instance.messages.create = mock_create
        mock_cls.return_value = mock_instance

        client = OpusLLMClient(AnthropicConfig(api_key="sk-ant-real-key"))
        result = await client.analyze("test prompt", effort="disabled")

        assert result["text"] == "Analysis complete"
        assert result["error"] is None
        # Verify 'thinking' was NOT in the call kwargs
        call_kwargs = mock_create.call_args[1]
        assert "thinking" not in call_kwargs
