"""Tests for the AI reviewer. The HTTP call is always mocked — never hit a real API.

Findings are plain dicts matching gitleaks_runner's keys (source, rule, severity, file,
start_line, end_line, description) plus optional AI extras (secret/category/suggestion),
present only when the model supplied them.
"""

import json
from unittest.mock import patch

import pytest
import requests

from commitgate.ai_review import build_prompt, call_llm, parse_findings, review
from commitgate.ai_review import reviewer as ai_reviewer
from commitgate.report_generator import remove_dup

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
        findings, ok = review("some diff", STAGED, api_key="k", provider="deepseek")

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


# --- deterministic secret location normalization -----------------------------

SECRET_DIFF = """diff --git a/app/config.py b/app/config.py
new file mode 100644
--- /dev/null
+++ b/app/config.py
@@ -0,0 +1,4 @@
+import os
+
+# release credential
+TOKEN = "unit-test-secret-12345"
"""


def _secret_raw(*, line=5, secret="unit-test-secret-12345"):
    item = {
        "file": "app/config.py",
        "severity": "critical",
        "rule": "hardcoded-token",
        "start_line": line,
        "end_line": line,
        "description": "Credential in source",
    }
    if secret is not None:
        item["secret"] = secret
    return json.dumps([item])


def test_parse_corrects_secret_line_then_exact_dedup_collapses():
    ai, ok = parse_findings(_secret_raw(line=5), STAGED, diff=SECRET_DIFF)
    assert ok is True
    assert ai[0]["start_line"] == 4
    assert ai[0]["end_line"] == 4

    gitleaks = {
        "source": "gitleaks", "rule": "generic-api-key", "severity": "critical",
        "file": "app/config.py", "start_line": 4, "end_line": 4,
    }
    merged = remove_dup([gitleaks, *ai])
    assert len(merged) == 1
    assert merged[0]["source"] == "gitleaks"


def test_parse_corrects_quoted_secret_evidence():
    findings, _ = parse_findings(
        _secret_raw(line=99, secret='"unit-test-secret-12345"'),
        STAGED,
        diff=SECRET_DIFF,
    )
    assert findings[0]["start_line"] == 4


def test_parse_keeps_location_when_secret_match_is_ambiguous():
    diff = SECRET_DIFF.replace(
        '+TOKEN = "unit-test-secret-12345"',
        '+TOKEN = "unit-test-secret-12345"\n+BACKUP = "unit-test-secret-12345"',
    )
    findings, _ = parse_findings(_secret_raw(line=77), STAGED, diff=diff)
    assert findings[0]["start_line"] == 77


@pytest.mark.parametrize("secret", [None, "REDACTED", "short"])
def test_parse_keeps_location_without_usable_secret_evidence(secret):
    findings, _ = parse_findings(_secret_raw(line=33, secret=secret), STAGED, diff=SECRET_DIFF)
    assert findings[0]["start_line"] == 33


def test_diff_parser_tracks_hunks_files_context_and_deletions():
    diff = """diff --git a/app/config.py b/app/config.py
--- a/app/config.py
+++ b/app/config.py
@@ -8,3 +8,3 @@
 context
-old value
+new unit-test-secret-12345
 context
diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -20,0 +20,1 @@
+DATABASE_URL = "db-test-secret-67890"
"""
    assert ai_reviewer._added_lines_by_file(diff) == {
        "app/config.py": [(9, "new unit-test-secret-12345")],
        "app/db.py": [(20, 'DATABASE_URL = "db-test-secret-67890"')],
    }


def test_parse_does_not_match_secret_only_in_removed_or_context_lines():
    diff = """diff --git a/app/config.py b/app/config.py
--- a/app/config.py
+++ b/app/config.py
@@ -3,2 +3,2 @@
-TOKEN = "unit-test-secret-12345"
+TOKEN = load_from_env()
 context mentions unit-test-secret-12345
"""
    findings, _ = parse_findings(_secret_raw(line=41), STAGED, diff=diff)
    assert findings[0]["start_line"] == 41


# --- fail-safe ----------------------------------------------------------------

def test_review_fail_safe_on_timeout(capsys):
    with patch.object(ai_reviewer.requests, "post", side_effect=requests.exceptions.Timeout):
        findings, ok = review("some diff", STAGED, api_key="k", provider="deepseek")
    assert findings == []                      # never raises
    assert ok is False                         # a dead call is NOT a clean pass
    assert "AI review skipped" in capsys.readouterr().err

def test_review_fail_safe_on_http_error():
    with patch.object(ai_reviewer.requests, "post",
                      return_value=FakeResponse("nope", ok=False, status_code=500)):
        findings, ok = review("some diff", STAGED, api_key="k", provider="deepseek")
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
        review("some diff", STAGED, api_key="k", provider="deepseek")

    assert captured["json"]["model"] == "deepseek-v4-flash"
    assert captured["json"]["thinking"] == {"type": "disabled"}
    assert captured["json"]["stream"] is True


def test_review_targets_kimi_with_current_endpoint_and_token_key():
    captured = {}

    def fake_post(url, headers=None, json=None, **kwargs):
        captured["url"] = url
        captured["json"] = json
        return FakeResponse('[{"file": "app/db.py", "severity": "low", "rule": "r", "description": "m"}]')

    with patch.object(ai_reviewer.requests, "post", side_effect=fake_post):
        findings, ok = review("some diff", STAGED, api_key="k", provider="kimi")

    assert ok is True
    assert captured["url"] == "https://api.moonshot.ai/v1/chat/completions"
    assert captured["json"]["model"] == "kimi-k2.7-code-highspeed"
    assert captured["json"]["temperature"] == 1
    assert "max_tokens" not in captured["json"]
    assert captured["json"]["max_completion_tokens"] == ai_reviewer.DEFAULT_MAX_TOKENS
    assert findings[0]["source"] == "AI Review (Kimi)"

def test_review_self_wires_provider_and_key_when_omitted():
    # The pre-push case: caller hands over a diff but no api_key/provider. review() must
    # resolve the provider from config and pull the key from env (no 401). Config is
    # mocked so the test doesn't depend on the repo's live commitgate.yaml.
    captured = {}

    def fake_post(url, headers=None, json=None, **kwargs):
        captured["url"] = url
        captured["headers"] = headers
        return FakeResponse('[{"file": "app/db.py", "severity": "low", "rule": "r", "description": "m"}]')

    with patch("commitgate.config.load_config", return_value={"ai": {"provider": "deepseek"}}), \
         patch.object(ai_reviewer, "ai_api_key", return_value="env-key"), \
         patch.object(ai_reviewer.requests, "post", side_effect=fake_post):
        findings, ok = review("some diff", STAGED)   # no api_key, no provider

    assert ok is True
    assert captured["url"] == "https://api.deepseek.com/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer env-key"
    assert findings[0]["source"] == "AI Review (DeepSeek)"


# --- CLI transport (claude-cli, no API key) -----------------------------------

class FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_review_cli_provider_parses_envelope():
    # claude-cli returns its JSON envelope; the model's findings live in "result".
    inner = json.dumps([{"file": "app/db.py", "severity": "high", "rule": "r", "description": "m"}])
    envelope = json.dumps({"is_error": False, "result": inner})
    with patch.object(ai_reviewer.shutil, "which", return_value="/usr/bin/claude"), \
         patch.object(ai_reviewer.subprocess, "run", return_value=FakeProc(stdout=envelope)) as run:
        findings, ok = review("some diff", STAGED, provider="claude-cli")

    assert ok is True
    assert findings[0]["source"] == "AI Review (Claude Code)"
    assert findings[0]["severity"] == "high"
    _, kwargs = run.call_args
    assert kwargs["input"]                      # prompt piped on stdin, not argv


def test_review_cli_needs_no_api_key():
    # No AI_KEY in the environment, yet the CLI path still works (subscription auth).
    with patch.object(ai_reviewer, "ai_api_key", return_value=None), \
         patch.object(ai_reviewer.shutil, "which", return_value="/usr/bin/claude"), \
         patch.object(ai_reviewer.subprocess, "run",
                      return_value=FakeProc(stdout=json.dumps({"result": "[]"}))):
        findings, ok = review("some diff", STAGED, provider="claude-cli")
    assert ok is True
    assert findings == []


def test_review_cli_missing_binary_warns_and_fails_safe(capsys):
    # User selected claude-cli but doesn't have it installed -> clear message, no crash,
    # ok=False so the deterministic gate still governs.
    with patch.object(ai_reviewer.shutil, "which", return_value=None):
        findings, ok = review("some diff", STAGED, provider="claude-cli")
    assert findings == []
    assert ok is False
    err = capsys.readouterr().err
    assert "AI review skipped" in err
    assert "claude" in err


def test_review_resolves_cli_provider_from_config():
    # provider omitted; config says claude-cli -> CLI transport, HTTP path untouched.
    with patch("commitgate.config.load_config", return_value={"ai": {"provider": "claude-cli"}}), \
         patch.object(ai_reviewer.shutil, "which", return_value="/usr/bin/claude"), \
         patch.object(ai_reviewer.subprocess, "run",
                      return_value=FakeProc(stdout=json.dumps({"result": "[]"}))) as run, \
         patch.object(ai_reviewer.requests, "post") as post:
        findings, ok = review("some diff", STAGED)   # no provider, no api_key

    assert ok is True
    run.assert_called_once()
    post.assert_not_called()


def test_review_cli_disables_thinking_via_env():
    # Extended thinking dominates CLI latency (~60s -> ~12s when off); the claude-cli
    # provider must pass MAX_THINKING_TOKENS=0 into the subprocess environment.
    with patch.object(ai_reviewer.shutil, "which", return_value="/usr/bin/claude"), \
         patch.object(ai_reviewer.subprocess, "run",
                      return_value=FakeProc(stdout=json.dumps({"result": "[]"}))) as run:
        review("some diff", STAGED, provider="claude-cli")
    _, kwargs = run.call_args
    assert kwargs["env"]["MAX_THINKING_TOKENS"] == "0"


# --- Codex CLI (JSONL event stream) -------------------------------------------

def _codex_stream(agent_text, *, extra_agent=None):
    """Build a realistic `codex exec --json` JSONL stream ending in an agent_message."""
    lines = [
        json.dumps({"type": "thread.started", "thread_id": "t1"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "item.completed", "item": {"id": "i0", "type": "reasoning", "text": "thinking"}}),
    ]
    if extra_agent:   # an earlier agent_message that must be superseded by the final one
        lines.append(json.dumps({"type": "item.completed",
                                 "item": {"id": "i1", "type": "agent_message", "text": extra_agent}}))
    lines += [
        json.dumps({"type": "item.completed", "item": {"id": "i2", "type": "agent_message", "text": agent_text}}),
        json.dumps({"type": "turn.completed", "usage": {"input_tokens": 10, "output_tokens": 5}}),
    ]
    return "\n".join(lines)


def test_unwrap_codex_jsonl_extracts_last_agent_message():
    stream = "not-json progress noise\n" + _codex_stream("FINAL", extra_agent="earlier")
    assert ai_reviewer._unwrap_codex_jsonl(stream) == "FINAL"   # last agent_message, noise skipped


def test_unwrap_codex_jsonl_empty_when_no_agent_message():
    stream = json.dumps({"type": "turn.failed", "error": "boom"})
    assert ai_reviewer._unwrap_codex_jsonl(stream) == ""       # -> parse_findings returns ([], False)


def test_review_codex_parses_jsonl_stream():
    findings_json = json.dumps([{"file": "app/db.py", "severity": "high", "rule": "r", "description": "m"}])
    with patch.object(ai_reviewer.shutil, "which", return_value="/usr/bin/codex"), \
         patch.object(ai_reviewer.subprocess, "run",
                      return_value=FakeProc(stdout=_codex_stream(findings_json))) as run:
        findings, ok = review("some diff", STAGED, provider="codex-cli")

    assert ok is True
    assert findings[0]["source"] == "AI Review (Codex)"
    assert findings[0]["severity"] == "high"
    # routed to the codex command, non-interactive, prompt on stdin
    argv = run.call_args.args[0]
    assert "codex" in argv[0]
    assert "exec" in argv and "--json" in argv and argv[-1] == "-"
    assert run.call_args.kwargs["input"]


def test_review_codex_missing_binary_fails_safe(capsys):
    with patch.object(ai_reviewer.shutil, "which", return_value=None):
        findings, ok = review("some diff", STAGED, provider="codex-cli")
    assert findings == [] and ok is False
    assert "codex" in capsys.readouterr().err


# --- Antigravity CLI (plain output, prompt in argv) ---------------------------

def test_review_antigravity_parses_plain_output_and_uses_safe_flags():
    raw = json.dumps([{
        "file": "app/db.py", "severity": "high", "rule": "r", "description": "m"
    }])
    with patch.object(ai_reviewer.shutil, "which", return_value="C:/agy/agy.exe"), \
         patch.object(ai_reviewer.subprocess, "run", return_value=FakeProc(stdout=raw)) as run:
        findings, ok = review("some diff", STAGED, provider="agy-cli")

    assert ok is True
    assert findings[0]["source"] == "AI Review (Antigravity)"
    argv = run.call_args.args[0]
    assert argv[argv.index("--model") + 1] == "Gemini 3.5 Flash (Low)"
    assert "--sandbox" in argv
    assert argv[argv.index("--mode") + 1] == "plan"
    assert argv[-2] == "--print"
    assert "some diff" in argv[-1]
    assert run.call_args.kwargs["input"] is None


def test_review_antigravity_missing_binary_fails_safe(capsys):
    with patch.object(ai_reviewer.shutil, "which", return_value=None):
        findings, ok = review("some diff", STAGED, provider="agy-cli")
    assert findings == [] and ok is False
    assert "agy" in capsys.readouterr().err


def test_antigravity_oversized_windows_prompt_fails_before_launch():
    with patch.object(ai_reviewer.shutil, "which", return_value="C:/agy/agy.exe"), \
         patch.object(ai_reviewer.os, "name", "nt"), \
         patch.object(ai_reviewer.subprocess, "run") as run:
        with pytest.raises(RuntimeError, match="too large for the Windows command line"):
            ai_reviewer.call_cli(
                "agy", ["--print"], "x" * ai_reviewer.WINDOWS_ARGV_SAFE_LIMIT,
                output_mode="plain", prompt_mode="argv",
            )
    run.assert_not_called()


def test_review_cli_floors_short_timeout():
    # scan passes the HTTP-tuned 20s; the CLI path must floor it (agent boot alone can
    # exceed 20s) so the review isn't spuriously skipped.
    captured = {}

    def fake_call_cli(command, args, prompt, timeout, result_key="result", env=None,
                      output_mode="envelope", prompt_mode="stdin"):
        captured["timeout"] = timeout
        return "[]"

    with patch.object(ai_reviewer, "call_cli", side_effect=fake_call_cli):
        findings, ok = review("some diff", STAGED, provider="claude-cli", timeout=20)
    assert ok is True
    assert captured["timeout"] >= ai_reviewer.CLI_MIN_TIMEOUT


def test_review_cli_nonzero_exit_fails_safe():
    with patch.object(ai_reviewer.shutil, "which", return_value="/usr/bin/claude"), \
         patch.object(ai_reviewer.subprocess, "run",
                      return_value=FakeProc(stderr="not logged in", returncode=1)):
        findings, ok = review("some diff", STAGED, provider="claude-cli")
    assert findings == []
    assert ok is False


def test_review_cli_timeout_fails_safe():
    with patch.object(ai_reviewer.shutil, "which", return_value="/usr/bin/claude"), \
         patch.object(ai_reviewer.subprocess, "run",
                      side_effect=ai_reviewer.subprocess.TimeoutExpired(cmd="claude", timeout=1)):
        findings, ok = review("some diff", STAGED, provider="claude-cli")
    assert findings == []
    assert ok is False


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


# --- prompt shaping from reporting.fields (output-token / latency win) ---------

def test_system_prompt_keeps_evidence_rules():
    # Anti-inflation/anti-false-positive rules added deliberately in the structured
    # rewrite - pin them so a future prompt edit doesn't silently drop them.
    p = ai_reviewer.build_system_prompt()
    assert "EVIDENCE RULES" in p
    assert "named parser" in p
    assert "external attacker repeatedly denying a shared service" in p
    assert "Try to disprove candidates" in p
    # Raw-sink presumption: without it, a bare eval/os.system on a parameter counts as
    # "hypothetical" and the min_severity gate skips it entirely (missed 3 criticals live).
    assert "assumed to receive untrusted input unless the diff shows the input is a constant" in p
    # Gitleaks boundary must be explicit: the model can't know gitleaks' coverage, and
    # "don't duplicate gitleaks" alone made it skip DB-URL passwords entirely (live miss).
    # Keep the proven paragraph wording: moving the same boundary into EVIDENCE RULES
    # made DeepSeek omit DB credentials in 5/5 live calls.
    assert "scheme://user:password@host" in p
    assert "even when standard-format secrets appear in the same diff" in p


def test_build_system_prompt_requests_all_fields_by_default():
    p = ai_reviewer.build_system_prompt()
    assert '"category"' in p and '"description": str' in p and '"suggestion": str' in p
    assert "`description` <= 25 words with observed evidence only" in p
    assert "`suggestion` <= 15 words" in p


def test_build_system_prompt_omits_disabled_output_fields():
    p = ai_reviewer.build_system_prompt(
        include_category=False, include_description=False, include_suggestion=False
    )
    # the three toggleable, model-generated fields are gone from the requested schema
    assert '"category"' not in p
    assert '"description": str' not in p
    assert '"suggestion": str' not in p
    # ...but the load-bearing fields the gate needs are ALWAYS requested
    for keep in ('"rule": str', '"severity"', '"file": str', '"start_line"', '"end_line"', '"secret"'):
        assert keep in p
    # no prose fields left to constrain -> no word-cap sentence
    assert "<= 25 words" not in p and "<= 15 words" not in p


def test_build_system_prompt_one_prose_field():
    p = ai_reviewer.build_system_prompt(include_suggestion=False)
    assert '"description": str' in p and '"suggestion": str' not in p
    assert "`description` <= 25 words with observed evidence only" in p
    assert "`suggestion` <= 15 words" not in p


def test_review_prompt_shaped_by_report_fields():
    # Turning off description/suggestion/category must drop them from what the model is asked
    # to produce -- a shorter response is the whole point (output tokens dominate latency).
    captured = {}

    def fake_post(url, headers=None, json=None, **kwargs):
        captured["system"] = json["messages"][0]["content"]
        return FakeResponse("[]")

    with patch.object(ai_reviewer.requests, "post", side_effect=fake_post):
        review("some diff", STAGED, api_key="k", provider="deepseek", min_severity="low",
               report_fields={"category": False, "description": False, "suggestions": False})

    assert '"description": str' not in captured["system"]
    assert '"suggestion": str' not in captured["system"]
    assert '"category"' not in captured["system"]
    assert '"severity"' in captured["system"]     # load-bearing field still requested


def test_review_defaults_to_full_prompt_when_fields_unset():
    # report_fields omitted + a config with no reporting section -> fail open, request all.
    captured = {}

    def fake_post(url, headers=None, json=None, **kwargs):
        captured["system"] = json["messages"][0]["content"]
        return FakeResponse("[]")

    with patch("commitgate.config.load_config", return_value={"ai": {"provider": "deepseek"}}), \
         patch.object(ai_reviewer, "ai_api_key", return_value="k"), \
         patch.object(ai_reviewer.requests, "post", side_effect=fake_post):
        review("some diff", STAGED)

    assert '"description": str' in captured["system"]
    assert '"suggestion": str' in captured["system"]


def test_review_cli_prompt_shaped_by_report_fields():
    # The CLI transport inlines the system prompt on stdin -> the shaping must reach it too.
    captured = {}

    def fake_call_cli(command, args, prompt, timeout, result_key="result", env=None,
                      output_mode="envelope", prompt_mode="stdin"):
        captured["prompt"] = prompt
        return "[]"

    with patch.object(ai_reviewer, "call_cli", side_effect=fake_call_cli):
        review("some diff", STAGED, provider="claude-cli", min_severity="low",
               report_fields={"category": False, "description": False, "suggestions": False})

    assert '"suggestion": str' not in captured["prompt"]
    assert '"description": str' not in captured["prompt"]
    assert '"file": str' in captured["prompt"]     # load-bearing field survives


# --- prompt-level min_severity cut (the real latency lever: the model never generates them) ---

def test_build_system_prompt_no_threshold_at_low():
    # "low" == report everything -> no severity gate (default prompt stays unchanged).
    p = ai_reviewer.build_system_prompt(min_severity="low")
    assert "Report all" not in p and "Skip low-severity" not in p


def test_build_system_prompt_adds_min_severity_threshold():
    # The gate names sub-threshold CATEGORIES to skip rather than asking the model to
    # self-rate severity: "rate then drop" made deepseek-flash return [] even for blatant
    # criticals, and a bare "report >= X" made it inflate lows to clear the bar.
    p = ai_reviewer.build_system_prompt(min_severity="high")
    assert "Report all high and critical findings" in p
    assert "Skip low- and medium-severity issues" in p


def test_review_threads_min_severity_into_prompt():
    # review() must push min_severity into the system prompt so the model omits sub-threshold
    # findings at the source -- fewer generated findings is where the latency win comes from.
    captured = {}

    def fake_post(url, headers=None, json=None, **kwargs):
        captured["system"] = json["messages"][0]["content"]
        return FakeResponse("[]")

    with patch.object(ai_reviewer.requests, "post", side_effect=fake_post):
        review("some diff", STAGED, api_key="k", provider="deepseek", min_severity="high")

    assert "Report all high and critical findings" in captured["system"]
    assert "Skip low- and medium-severity issues" in captured["system"]
