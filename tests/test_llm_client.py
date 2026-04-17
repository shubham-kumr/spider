"""
Tests for spider.llm.client — LLM JSON parsing and fallbacks.
Uses mocking to avoid real API calls.
"""

import json
import pytest
from unittest.mock import patch, MagicMock


class TestCallQwenJson:
    def _mock_response(self, content: str):
        """Create a mock OpenAI-style response."""
        msg = MagicMock()
        msg.content = content
        choice = MagicMock()
        choice.message = msg
        response = MagicMock()
        response.choices = [choice]
        return response

    @patch("spider.llm.client._get_client")
    def test_clean_json_object(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = self._mock_response(
            '{"next": "recon", "reason": "No ports found"}'
        )
        mock_get_client.return_value = mock_client

        from spider.llm.client import call_qwen_json
        result = call_qwen_json("system", "user")
        assert result == {"next": "recon", "reason": "No ports found"}

    @patch("spider.llm.client._get_client")
    def test_json_array_response(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = self._mock_response(
            '[{"title": "Test", "severity": "high"}]'
        )
        mock_get_client.return_value = mock_client

        from spider.llm.client import call_qwen_json
        result = call_qwen_json("system", "user")
        assert isinstance(result, list)
        assert result[0]["title"] == "Test"

    @patch("spider.llm.client._get_client")
    def test_json_in_markdown_code_fence(self, mock_get_client):
        mock_client = MagicMock()
        content = '```json\n{"next": "enumerate", "reason": "ports found"}\n```'
        mock_client.chat.completions.create.return_value = self._mock_response(content)
        mock_get_client.return_value = mock_client

        from spider.llm.client import call_qwen_json
        result = call_qwen_json("system", "user")
        assert result["next"] == "enumerate"

    @patch("spider.llm.client._get_client")
    def test_json_embedded_in_prose(self, mock_get_client):
        mock_client = MagicMock()
        content = 'Sure, here is my answer: {"next": "report", "reason": "All done"} — hope that helps!'
        mock_client.chat.completions.create.return_value = self._mock_response(content)
        mock_get_client.return_value = mock_client

        from spider.llm.client import call_qwen_json
        result = call_qwen_json("system", "user")
        assert result["next"] == "report"

    @patch("spider.llm.client._get_client")
    def test_invalid_json_raises_value_error(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = self._mock_response(
            "This is plain text with no JSON at all."
        )
        mock_get_client.return_value = mock_client

        from spider.llm.client import call_qwen_json
        with pytest.raises(ValueError, match="non-JSON"):
            call_qwen_json("system", "user")

    @patch("spider.llm.client._get_client")
    def test_rate_limit_retry(self, mock_get_client):
        """Should retry on RateLimitError and eventually succeed."""
        from openai import RateLimitError as OpenAIRateLimitError
        mock_client = MagicMock()

        # First call raises rate limit, second succeeds
        call_count = 0
        def side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OpenAIRateLimitError(
                    message="rate limit",
                    response=MagicMock(status_code=429),
                    body={},
                )
            return self._mock_response('{"next": "recon", "reason": "retry worked"}')

        mock_client.chat.completions.create.side_effect = side_effect
        mock_get_client.return_value = mock_client

        from spider.llm.client import call_qwen_json

        with patch("spider.llm.client.time.sleep"):  # Don't actually sleep
            result = call_qwen_json("system", "user")
        assert result["next"] == "recon"
        assert call_count == 2
