"""
PhishGuard AI — Tests: Ollama Service
Tests the Ollama integration using mocked HTTP calls.
Covers: offline Ollama, timeout, invalid JSON, valid responses,
JSON in markdown fences, and edge cases.
"""
import pytest
import json
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.ollama_service import (
    check_ollama_status,
    analyze_with_ollama,
    _parse_ai_response,
    _validate_ai_data,
)


# ================================================================
# Constants
# ================================================================
BASE_URL = 'http://localhost:11434'
MODEL    = 'llama3.2:3b'
SAMPLE_EMAIL = {
    'sender': 'phisher@evil.com',
    'subject': 'Verify your account',
    'body': 'Click here to verify your password immediately.',
}

# A valid AI response JSON
VALID_AI_JSON = {
    'verdict': 'Suspicious',
    'reasons': ['Contains urgent language', 'Requests credentials'],
    'evidence': ['verify your password immediately'],
    'confidence': 85,
    'uncertainty': 'Could be a legitimate security alert',
    'recommended_actions': ['Do not click any links'],
}


# ================================================================
# check_ollama_status() tests
# ================================================================

class TestCheckOllamaStatus:

    @patch('app.services.ollama_service.requests.get')
    def test_ollama_online(self, mock_get):
        """Returns running=True when Ollama responds with HTTP 200."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'models': [{'name': 'llama3.2:3b'}, {'name': 'llama3.1:8b'}]
        }
        mock_get.return_value = mock_resp

        result = check_ollama_status(BASE_URL)
        assert result['running'] is True
        assert 'llama3.2:3b' in result['models']

    @patch('app.services.ollama_service.requests.get')
    def test_ollama_offline_connection_error(self, mock_get):
        """Returns running=False on ConnectionError."""
        import requests as req_module
        mock_get.side_effect = req_module.exceptions.ConnectionError('Connection refused')

        result = check_ollama_status(BASE_URL)
        assert result['running'] is False
        assert 'connect' in result['message'].lower()

    @patch('app.services.ollama_service.requests.get')
    def test_ollama_timeout(self, mock_get):
        """Returns running=False on Timeout."""
        import requests as req_module
        mock_get.side_effect = req_module.exceptions.Timeout('Timed out')

        result = check_ollama_status(BASE_URL)
        assert result['running'] is False
        assert 'timed out' in result['message'].lower() or 'timeout' in result['message'].lower()

    @patch('app.services.ollama_service.requests.get')
    def test_ollama_non_200_status(self, mock_get):
        """Returns running=False on non-200 status code."""
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_get.return_value = mock_resp

        result = check_ollama_status(BASE_URL)
        assert result['running'] is False
        assert '503' in result['message']


# ================================================================
# analyze_with_ollama() tests
# ================================================================

class TestAnalyzeWithOllama:

    @patch('app.services.ollama_service.requests.post')
    def test_successful_analysis(self, mock_post):
        """Returns success=True with valid AI data."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'response': json.dumps(VALID_AI_JSON)
        }
        mock_post.return_value = mock_resp

        result = analyze_with_ollama(
            sender=SAMPLE_EMAIL['sender'],
            subject=SAMPLE_EMAIL['subject'],
            body=SAMPLE_EMAIL['body'],
            base_url=BASE_URL,
            model=MODEL,
        )
        assert result['success'] is True
        assert result['data']['verdict'] in ('Safe', 'Suspicious', 'Malicious')
        assert isinstance(result['data']['confidence'], int)
        assert 0 <= result['data']['confidence'] <= 100

    @patch('app.services.ollama_service.requests.post')
    def test_ollama_offline_during_analysis(self, mock_post):
        """Returns success=False with helpful error when Ollama is offline."""
        import requests as req_module
        mock_post.side_effect = req_module.exceptions.ConnectionError('Connection refused')

        result = analyze_with_ollama(**SAMPLE_EMAIL, base_url=BASE_URL, model=MODEL)
        assert result['success'] is False
        assert result['data'] is None
        assert result['error'] is not None
        assert 'connect' in result['error'].lower() or 'ollama' in result['error'].lower()

    @patch('app.services.ollama_service.requests.post')
    def test_timeout_during_analysis(self, mock_post):
        """Returns success=False with timeout error message."""
        import requests as req_module
        mock_post.side_effect = req_module.exceptions.Timeout('Request timed out')

        result = analyze_with_ollama(**SAMPLE_EMAIL, base_url=BASE_URL, model=MODEL, timeout=10)
        assert result['success'] is False
        assert 'timeout' in result['error'].lower() or 'timed out' in result['error'].lower()

    @patch('app.services.ollama_service.requests.post')
    def test_model_not_pulled(self, mock_post):
        """Returns success=False when model returns HTTP 404."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_post.return_value = mock_resp

        result = analyze_with_ollama(**SAMPLE_EMAIL, base_url=BASE_URL, model='nonexistent-model')
        assert result['success'] is False
        assert result['error'] is not None

    @patch('app.services.ollama_service.requests.post')
    def test_invalid_json_response(self, mock_post):
        """Returns success=False when AI returns non-JSON text."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'response': 'Sure, I think this email looks suspicious! It has many red flags.'
        }
        mock_post.return_value = mock_resp

        result = analyze_with_ollama(**SAMPLE_EMAIL, base_url=BASE_URL, model=MODEL)
        assert result['success'] is False
        assert 'parsed' in result['error'].lower() or 'json' in result['error'].lower()

    @patch('app.services.ollama_service.requests.post')
    def test_json_in_markdown_fence(self, mock_post):
        """AI response with JSON wrapped in markdown fences is parsed correctly."""
        fenced = f"```json\n{json.dumps(VALID_AI_JSON)}\n```"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'response': fenced}
        mock_post.return_value = mock_resp

        result = analyze_with_ollama(**SAMPLE_EMAIL, base_url=BASE_URL, model=MODEL)
        assert result['success'] is True
        assert result['data']['verdict'] in ('Safe', 'Suspicious', 'Malicious')

    @patch('app.services.ollama_service.requests.post')
    def test_body_truncation(self, mock_post):
        """Very long email body is truncated before sending to Ollama."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'response': json.dumps(VALID_AI_JSON)}
        mock_post.return_value = mock_resp

        long_body = 'word ' * 20000  # ~100 KB
        result = analyze_with_ollama(
            sender='test@test.com',
            subject='Test',
            body=long_body,
            base_url=BASE_URL,
            model=MODEL,
        )
        # Should succeed regardless of body length
        assert result['success'] is True

        # Check the actual prompt sent had truncated body
        call_args = mock_post.call_args
        prompt = call_args.kwargs.get('json', {}).get('prompt', '') or \
                 call_args.args[1].get('prompt', '') if call_args.args else ''
        if prompt:
            assert len(prompt) < len(long_body)


# ================================================================
# _parse_ai_response() Unit Tests
# ================================================================

class TestParseAiResponse:

    def test_parse_valid_json(self):
        """Clean JSON string is parsed correctly."""
        text = json.dumps(VALID_AI_JSON)
        result = _parse_ai_response(text)
        assert result is not None
        assert result['verdict'] == 'Suspicious'

    def test_parse_empty_string(self):
        """Empty string returns None."""
        assert _parse_ai_response('') is None

    def test_parse_none(self):
        """None input returns None."""
        assert _parse_ai_response(None) is None

    def test_parse_plain_text_no_json(self):
        """Plain text with no JSON structure returns None."""
        assert _parse_ai_response('This email is definitely phishing.') is None

    def test_parse_json_with_surrounding_text(self):
        """JSON embedded in surrounding text is extracted."""
        text = f"Here is my analysis:\n{json.dumps(VALID_AI_JSON)}\nPlease review."
        result = _parse_ai_response(text)
        assert result is not None

    def test_parse_malformed_json(self):
        """Malformed JSON returns None without exception."""
        assert _parse_ai_response('{"verdict": "Suspicious", "confidence": }') is None


# ================================================================
# _validate_ai_data() Unit Tests
# ================================================================

class TestValidateAiData:

    def test_valid_data_passes(self):
        """Valid AI data passes validation unchanged."""
        data = dict(VALID_AI_JSON)
        result = _validate_ai_data(data)
        assert result is not None
        assert result['verdict'] == 'Suspicious'
        assert result['confidence'] == 85

    def test_invalid_verdict_coerced(self):
        """Non-standard verdict strings are coerced to valid ones."""
        data = {**VALID_AI_JSON, 'verdict': 'Definitely Phishing!!'}
        result = _validate_ai_data(data)
        assert result['verdict'] in ('Safe', 'Suspicious', 'Malicious')

    def test_confidence_clamped(self):
        """Confidence values outside 0-100 are clamped."""
        data = {**VALID_AI_JSON, 'confidence': 150}
        result = _validate_ai_data(data)
        assert result['confidence'] == 100

        data2 = {**VALID_AI_JSON, 'confidence': -5}
        result2 = _validate_ai_data(data2)
        assert result2['confidence'] == 0

    def test_non_list_fields_defaulted(self):
        """Fields that should be lists but aren't are reset to empty lists."""
        data = {**VALID_AI_JSON, 'reasons': 'Some reason', 'evidence': None}
        result = _validate_ai_data(data)
        assert isinstance(result['reasons'], list)
        assert isinstance(result['evidence'], list)

    def test_non_dict_input_returns_none(self):
        """Non-dict input returns None."""
        assert _validate_ai_data([]) is None
        assert _validate_ai_data("string") is None
        assert _validate_ai_data(42) is None
