"""
Tests for LLM client implementations and factory function.
Covers OpusLLMClient, BedrockGatewayLLMClient, and create_llm_client factory.
"""

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
    _no_api_key_response,
    create_llm_client,
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
