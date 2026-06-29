"""Tests for the AI reviewer. The HTTP call is always mocked — never hit a real API.

Findings are plain dicts matching gitleaks_runner's keys (source, rule, severity, file,
start_line, end_line, description) plus optional AI extras (secret/category/suggestion),
present only when the model supplied them.
"""

import json
from unittest.mock import patch

import pytest
import requests

from commitgate import ai_reviewer
from commitgate.ai_reviewer import build_prompt, call_llm, parse_findings, review

STAGED = ["app/config.py", "app/db.py"]


class FakeResponse:
    def __init__(self, content, ok=True, status_code=200):
        self._content = content
        self.ok = ok
        self.status_code = status_code
        self.text = content if isinstance(content, str) else json.dumps(content)

    def iter_lines(self):
        chunk = json.dumps({"choices": [{"delta": {"content": self._content}, "index": 0}]})
        yield f"data: {chunk}"
        yield "data: [DONE]"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _llm_returning(content):
    """Patch requests.post so call_llm yields `content` as the model message."""
    return patch.object(ai_reviewer.requests, "post", return_value=FakeResponse(content))


# --- happy path ---------------------------------------------------------------

def test_review_happy_path_parses_findings():
    content = json.dumps([
        {
            "rule": "hardcoded-internal-url",
            "severity": "HIGH",
            "file": "app/config.py",
            "start_line": 12,
            "secret": "http://internal.corp.local",
            "description": "Hardcoded internal hostname",
        }
    ])
    with _llm_returning(content):
        findings, ok = review("some diff", STAGED, api_key="k")

    assert ok is True
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, dict)
    assert f["source"] == "AI Review (DeepSeek)"   # provider auto-resolved from config
    assert f["severity"] == "high"          # normalized to lowercase
    assert f["file"] == "app/config.py"
    assert f["start_line"] == 12


def test_source_includes_provider_label():
    raw = '[{"file": "app/db.py", "severity": "low", "rule": "r", "description": "m"}]'
    findings, _ = parse_findings(raw, STAGED, provider_label="DeepSeek")
    assert findings[0]["source"] == "AI Review (DeepSeek)"


# --- parsing robustness -------------------------------------------------------

def test_parse_strips_code_fences():
    raw = '```json\n[{"file": "app/db.py", "severity": "low", "rule": "r", "description": "m"}]\n```'
    findings, ok = parse_findings(raw, STAGED)
    assert ok is True
    assert len(findings) == 1
    assert findings[0]["file"] == "app/db.py"


def test_parse_malformed_json_is_not_ok():
    # garbage in -> empty findings AND parse_ok False (the caller should warn, not relax)
    findings, ok = parse_findings("the model rambled, no json here", STAGED)
    assert findings == []
    assert ok is False


def test_parse_clean_empty_array_is_ok():
    # a genuine clean review -> empty findings but parse_ok True (do NOT warn)
    findings, ok = parse_findings("[]", STAGED)
    assert findings == []
    assert ok is True


def test_parse_drops_non_staged_file():
    # JSON parsed fine; the finding was just hallucinated -> dropped, but still parse_ok True
    raw = json.dumps([{"file": "not/staged.py", "severity": "high", "rule": "r", "description": "m"}])
    findings, ok = parse_findings(raw, STAGED)
    assert findings == []
    assert ok is True


def test_parse_normalizes_bad_severity_and_line():
    raw = json.dumps([
        {"file": "app/db.py", "severity": "spicy", "start_line": "x", "rule": "r", "description": "m"}
    ])
    findings, _ = parse_findings(raw, STAGED)
    assert findings[0]["severity"] == "medium"   # unknown severity -> medium
    assert findings[0]["start_line"] is None      # non-numeric line -> None


def test_parse_extracts_rich_fields():
    raw = json.dumps([{
        "rule": "command-injection",
        "category": "injection",
        "severity": "critical",
        "file": "app/db.py",
        "start_line": 4,
        "end_line": 6,
        "description": "os.system on user input",
        "suggestion": "Use subprocess with a list of args.",
    }])
    findings, _ = parse_findings(raw, STAGED)
    f = findings[0]
    assert f["category"] == "Injection"        # normalized to sentence case
    assert f["end_line"] == 6
    assert f["suggestion"].startswith("Use subprocess")


def test_parse_salvages_truncated_array():
    # Response cut off mid-array (e.g. hit max_tokens): two complete findings, then a
    # third object truncated with no closing "]". We should recover the two.
    raw = (
        '[{"file": "app/db.py", "severity": "high", "rule": "r1", "description": "m1"}, '
        '{"file": "app/config.py", "severity": "low", "rule": "r2", "description": "m2"}, '
        '{"file": "app/db.py", "severity": "crit'
    )
    findings, ok = parse_findings(raw, STAGED)
    assert ok is True                              # salvaged the complete objects
    assert [f["rule"] for f in findings] == ["r1", "r2"]


def test_parse_normalizes_category_to_sentence_case():
    raw = json.dumps([
        {"file": "app/db.py", "severity": "high", "rule": "r", "description": "m", "category": "secret-leak"},
        {"file": "app/config.py", "severity": "high", "rule": "r", "description": "m", "category": "Hardcoded-URL"},
    ])
    findings, _ = parse_findings(raw, STAGED)
    assert findings[0]["category"] == "Secret leak"
    assert findings[1]["category"] == "Hardcoded url"


def test_parse_omits_absent_optional_fields():
    # a minimal finding carries only the core keys, no empty optionals
    raw = json.dumps([{"file": "app/db.py", "severity": "low", "rule": "r", "description": "m"}])
    findings, _ = parse_findings(raw, STAGED)
    f = findings[0]
    assert set(f) == {"source", "rule", "severity", "file", "start_line", "end_line", "description"}


def test_parse_accepts_object_with_findings_key():
    raw = json.dumps({"findings": [
        {"file": "app/db.py", "severity": "critical", "rule": "r", "description": "m"}
    ]})
    findings, ok = parse_findings(raw, STAGED)
    assert ok is True
    assert len(findings) == 1 and findings[0]["severity"] == "critical"


# --- fail-safe ----------------------------------------------------------------

def test_review_fail_safe_on_timeout(capsys):
    with patch.object(ai_reviewer.requests, "post", side_effect=requests.exceptions.Timeout):
        findings, ok = review("some diff", STAGED, api_key="k")
    assert findings == []                      # never raises
    assert ok is False                         # a dead call is NOT a clean pass
    assert "AI review skipped" in capsys.readouterr().err

def test_review_fail_safe_on_http_error():
    with patch.object(ai_reviewer.requests, "post",
                      return_value=FakeResponse("nope", ok=False, status_code=500)):
        findings, ok = review("some diff", STAGED, api_key="k")
    assert findings == []
    assert ok is False


def test_review_empty_diff_skips_llm():
    with patch.object(ai_reviewer.requests, "post") as post:
        findings, ok = review("   ", STAGED, api_key="k")
        assert findings == []
        assert ok is True                      # nothing to review is not a failure
        post.assert_not_called()


# --- client wiring (OpenAI-compatible endpoint) -------------------------------

def test_review_targets_v4_flash_with_thinking_disabled():
    captured = {}

    def fake_post(url, headers=None, json=None, **kwargs):
        captured["json"] = json
        return FakeResponse("[]")

    with patch.object(ai_reviewer.requests, "post", side_effect=fake_post):
        review("some diff", STAGED, api_key="k")

    assert captured["json"]["model"] == "deepseek-v4-flash"
    assert captured["json"]["thinking"] == {"type": "disabled"}
    assert captured["json"]["stream"] is True


def test_review_self_wires_provider_and_key_when_omitted():
    # The pre-push case: caller hands over a diff but no api_key/provider. review() must
    # resolve the provider from commitgate.yaml and pull the key from env (no 401).
    captured = {}

    def fake_post(url, headers=None, json=None, **kwargs):
        captured["url"] = url
        captured["headers"] = headers
        return FakeResponse('[{"file": "app/db.py", "severity": "low", "rule": "r", "description": "m"}]')

    with patch.object(ai_reviewer, "ai_api_key", return_value="env-key"), \
         patch.object(ai_reviewer.requests, "post", side_effect=fake_post):
        findings, ok = review("some diff", STAGED)   # no api_key, no provider

    assert ok is True
    assert captured["url"] == "https://api.deepseek.com/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer env-key"
    assert findings[0]["source"] == "AI Review (DeepSeek)"


def test_call_llm_hits_chat_completions_with_bearer():
    captured = {}

    def fake_post(url, headers=None, json=None, **kwargs):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return FakeResponse("[]")

    with patch.object(ai_reviewer.requests, "post", side_effect=fake_post):
        out = call_llm("https://api.deepseek.com", "deepseek-chat", "secret-key",
                       build_prompt("d"), timeout=5)

    assert out == "[]"
    assert captured["url"] == "https://api.deepseek.com/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer secret-key"
    assert captured["json"]["model"] == "deepseek-chat"
