"""AI reviewer — the semantic scanning layer.

Gitleaks catches known secret *shapes*. This module catches what regex can't:
hardcoded internal hostnames/URLs, credentials that match no known pattern, risky
`eval`/`exec`, `.env` values pasted into source, data-leaking logic. That semantic
gap is CommitGate's actual differentiator.

Pipeline: staged diff -> build_prompt -> call_llm -> parse_findings -> (findings, ok).

Finding shape: a plain dict matching `gitleaks_runner`'s keys so `decision_engine`
sees one structure from both scanners. Core keys (always present): `source`, `rule`,
`severity`, `file`, `start_line`, `end_line`, `description`. AI-only extras, included
only when the model supplies them: `secret`, `category`, `suggestion`.
Gitleaks dicts are a subset of this (no `severity`/`source`); the AI adds the semantic
severity the decision engine needs.

Design notes:
- **Two transports.** `call_llm` speaks HTTP to an OpenAI-compatible `/chat/completions`
  endpoint (DeepSeek default). `call_cli` instead shells out to a local coding-agent CLI
  (e.g. Claude Code) that runs on the user's own subscription -- no API key. `review`
  dispatches on the provider's `kind`; both feed the same `parse_findings`.
- **Least-privilege:** we send only the staged diff, never the whole repo.
- **Fail-safe:** any LLM error/timeout -> warn + return `([], False)`. The `ok` flag lets the
  caller fail closed (warn) instead of mistaking a blind review for a clean one. The
  deterministic gitleaks gate is the floor; the AI only ever *adds* findings and never
  crashes a commit on its own.
- **API key from env only:** `AI_KEY`, never config/source.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import List, Optional, Tuple

import requests

DEFAULT_TIMEOUT = 20        # seconds; suits the fast HTTP providers. override w/ COMMITGATE_AI_TIMEOUT
DEFAULT_MAX_TOKENS = 2048
CONNECT_TIMEOUT = 5         # separate connect timeout — fail fast if network is down
CLI_MIN_TIMEOUT = 30        # CLI agents cold-start a process first

DEFAULT_PROVIDER = "deepseek"

# Providers are either `kind: "http"` (default -- OpenAI-compatible endpoint, needs AI_KEY)
# or `kind: "cli"` (shell out to a local coding-agent CLI on the user's own subscription,
# no API key). Switch provider by editing `ai.provider` in commitgate.yaml -- no code change.
PROVIDER_CONFIG = {
    "openai": {
        "label": "OpenAI",         
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-5.4-mini",
        "extra_body": None,
        "max_tokens_key": "max_completion_tokens",  # GPT-5.x dropped max_tokens
    },
    "deepseek": {
        "label": "DeepSeek",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-flash",
        "extra_body": {"thinking": {"type": "disabled"}},  # V4 defaults thinking ON — too slow for a hook
    },
    "gemini": {
        "label": "Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.5-flash",
        "extra_body": None,
    },
    "groq": {
        "label": "Groq",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "openai/gpt-oss-120b",
        "extra_body": None,
    },
    "claude-cli": {
        "kind": "cli",
        "label": "Claude Code",
        "command": "claude",
        # -p            : non-interactive print; json envelope so we can pull the answer cleanly.
        # --safe-mode   : skip CLAUDE.md/MCP/plugins/hooks discovery
        # --tools ""    : no tools -> can't read unstaged files (least-privilege) + faster
        # --model haiku : the task is small; bump to sonnet for a deeper review
        # --max-turns 1 : single shot
        "args": [
            "-p", "--output-format", "json",
            "--model", "haiku",
            "--safe-mode",
            "--tools", "",
            "--max-turns", "1",
        ],
        "result_key": "result",
        "env": {"MAX_THINKING_TOKENS": "0"},
        "output": "envelope",   # single JSON object; answer at result_key
    },
    "codex-cli": {
        "kind": "cli",
        "label": "Codex",
        "command": "codex",
        # exec              : non-interactive. --json: JSONL event stream (we read the last
        #                     agent_message). No API key: uses your `codex login` session.
        # -s read-only      : no writes/network for shell commands (least-privilege). NOTE:
        #                     Codex has no "no tools" mode, so it may still READ workspace files.
        # -c ...effort=low  : cut reasoning latency (Codex's analogue of Claude's thinking-off).
        # trailing "-"      : read the prompt from stdin.
        # exec is non-interactive -> never prompts for approval, so no -a/approval flag is needed.
        # Model comes from ~/.codex/config.toml; add "-m","<model>" to override.
        "args": [
            "exec", "--json",
            "-s", "read-only",
            "-c", "model_reasoning_effort=low",
            "-",
        ],
        "output": "jsonl",      # Codex event stream; answer in the last agent_message
    },
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# Characters an LLM may emit that Windows cp1252 cannot encode — map to ASCII equivalents.
_UNICODE_SANITIZE = str.maketrans({
    "‑": "-",   # non-breaking hyphen
    "–": "-",   # en dash
    "—": "-",   # em dash
    "‘": "'",   # left single quote
    "’": "'",   # right single quote
    "“": '"',   # left double quote
    "”": '"',   # right double quote
    "…": "...", # ellipsis
})


def _sanitize(s: str) -> str:
    return s.translate(_UNICODE_SANITIZE)

SYSTEM_PROMPT = """\
You are a security code reviewer for a git pre-commit gate, given a STAGED DIFF.

Gitleaks already catches standard secret patterns - do NOT duplicate that. Report other security issues: hardcoded internal hostnames/URLs/IPs, non-standard credentials, eval/exec or command/SQL injection, insecure deserialization, path traversal, SSRF, disabled TLS verification, weak crypto, non-cryptographic randomness for security values (tokens/passwords/reset codes), broad file permissions, missing cookie flags (HttpOnly/Secure/SameSite), verbose error/stack exposure, debug mode enabled, and sensitive-data leaks. Report minor issues too - rate them `low`, don't drop them; only skip non-security noise (style, formatting, performance, naming).

Set `severity` by what an attacker can actually reach in THIS diff, not hypothetical misuse. high/critical need untrusted input (user/request/file/env/arg an attacker controls) reaching a dangerous operation as written; for a raw sink (eval/exec, SQL/command injection, unsafe deserialization) assume input is untrusted unless the diff shows it constant.
- critical: attacker-controlled input reaching code execution or SQL/command injection; a live leaked credential.
- high: exploitable with a realistic precondition, or sensitive data (secrets/PII) reaching an untrusted party - logs, responses, SSRF, path traversal, auth bypass.
- medium: risky but not directly exploitable - TLS off, weak hashing, non-crypto randomness, broad permissions, test creds.
- low: limited-impact hardening/info-disclosure (internal URLs, missing cookie flags, verbose errors, debug on), AND any hypothetical-only risk - input is hardcoded/config/constant, or it needs "if called with untrusted input" / "if a dependency were compromised" / is defense-in-depth. Still report it, just don't inflate.

Respond with ONLY a JSON array (no prose, no code fences). Each element:
{"rule": str, "category": str (sentence case, e.g. "Secret leak", "Hardcoded url", "Injection risk"), "severity": "low"|"medium"|"high"|"critical", "file": str, "start_line": int|null, "end_line": int|null, "secret": str|null, "description": str, "suggestion": str}

Be specific in `description` and `suggestion`. The "file" must appear in the diff. If you find nothing, return [].
"""


def ai_api_key() -> Optional[str]:
    """Read the key from the environment, loading a local .env first if present.
    Never read it from config/source."""
    try:
        from dotenv import load_dotenv
        load_dotenv()  # populate os.environ from .env (does NOT override real env vars)
    except ImportError:
        pass
    return os.environ.get("AI_KEY")


def _ai_timeout() -> int:
    """Return the configured AI timeout. Set COMMITGATE_AI_TIMEOUT (seconds) to override.
    Loads .env so the setting works the same way as DEEPSEEK_API_KEY."""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    val = os.environ.get("COMMITGATE_AI_TIMEOUT")
    if val:
        try:
            return max(1, int(val))
        except ValueError:
            pass
    return DEFAULT_TIMEOUT


def build_prompt(diff: str) -> str:
    """Wrap the staged diff into the user prompt (least-privilege: diff only)."""
    return f"Review this staged diff:\n\n```diff\n{diff}\n```"


def call_llm(
    base_url: str,
    model: str,
    api_key: Optional[str],
    prompt: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    extra_body: Optional[dict] = None,
    max_tokens_key: str = "max_tokens",
) -> str:
    """Single provider-agnostic call to an OpenAI-compatible /chat/completions endpoint.

    Streams the response and accumulates chunks until [DONE] or the time budget expires.
    Stopping early (budget exhausted) returns whatever arrived — `_salvage_objects` in
    `parse_findings` recovers complete findings from a partial array. Raises on HTTP error
    or connection failure; the caller (`review`) handles the fail-safe.
    """
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        max_tokens_key: max_tokens,
        "stream": True,
    }
    if extra_body:                      # provider-specific knobs, e.g. DeepSeek thinking toggle
        body.update(extra_body)

    deadline = time.monotonic() + timeout
    buffer = ""
    with requests.post(url, headers=headers, json=body, stream=True,
                       timeout=(CONNECT_TIMEOUT, timeout)) as res:
        if not res.ok:
            raise RuntimeError(f"LLM HTTP {res.status_code}: {res.text}")
        for raw_line in res.iter_lines():
            if time.monotonic() > deadline:
                break
            # line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
            if isinstance(raw_line, bytes):
                line = raw_line.decode("utf-8")
            else:
                line = str(raw_line)
                
            if not line.startswith("data: "):
                continue
            data = line[6:]
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
                delta = chunk["choices"][0]["delta"].get("content") or ""
                buffer += delta
            except (json.JSONDecodeError, KeyError, IndexError):
                continue
    return buffer


def _cli_argv(exe: str, args: List[str]) -> List[str]:
    """Build the argv for a CLI provider.

    On Windows, npm installs `claude` as a `claude.cmd` shim, which CreateProcess can't
    launch directly -- route those through `cmd /c`. This is NOT shell=True: every token
    stays a separate argv element (the prompt goes via stdin, never the command line).
    """
    if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c", exe, *args]
    return [exe, *args]


def _unwrap_cli_output(stdout: str, result_key: str = "result") -> str:
    """Pull the model's text answer out of a CLI's JSON envelope.

    Claude Code's `--output-format json` prints one JSON object whose `result` field holds
    the assistant's final text (which is our findings JSON). If stdout isn't that envelope,
    return it verbatim and let `parse_findings`' tolerant extraction handle it.
    """
    text = (stdout or "").strip()
    if not text:
        return ""
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError:
        return text   # not the JSON envelope -- let parse_findings salvage
    if isinstance(envelope, dict):
        if envelope.get("is_error"):
            raise RuntimeError(f"CLI reported an error: {str(envelope.get(result_key))[:200]}")
        return str(envelope.get(result_key, ""))
    return text


def _unwrap_codex_jsonl(stdout: str) -> str:
    """Pull the model's answer out of Codex's `exec --json` JSONL event stream.

    Codex prints one JSON object per line; the assistant's answer is the last
    `item.completed` event whose item type is `agent_message` (text at `item.text`).
    Non-JSON progress lines are skipped; if no agent message is found, returns "".
    """
    text = ""
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue   # progress / noise line -- skip
        item = event.get("item") if isinstance(event, dict) else None
        if isinstance(item, dict) and item.get("type") == "agent_message" and item.get("text"):
            text = item["text"]   # keep the latest agent_message
    return text


def call_cli(
    command: str,
    args: List[str],
    prompt: str,
    timeout: int = DEFAULT_TIMEOUT,
    result_key: str = "result",
    env: Optional[dict] = None,
    output_mode: str = "envelope",
) -> str:
    """Run a local coding-agent CLI (e.g. Claude Code, Codex) as the LLM transport.

    Unlike `call_llm`, this makes no HTTP call of its own: it shells out to an already
    installed and logged-in CLI, which reaches its provider under the user's own
    subscription -- so no API key is needed.
    """
    exe = shutil.which(command)
    if exe is None:
        raise RuntimeError(
            f"'{command}' not found on PATH -- install it, or set a different ai.provider "
            f"in commitgate.yaml"
        )
    try:
        proc = subprocess.run(
            _cli_argv(exe, args),
            input=prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            env={**os.environ, **env} if env else None,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"'{command}' timed out after {timeout}s")
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"'{command}' exited {proc.returncode}: {detail[:200]}")
    if output_mode == "jsonl":
        return _unwrap_codex_jsonl(proc.stdout)
    return _unwrap_cli_output(proc.stdout, result_key)


def _extract_json(raw: str):
    """Best-effort JSON recovery from a model response. Returns parsed data or None.

    Tolerates code fences and surrounding prose by grabbing the outermost array/object.
    """
    if not raw:
        return None
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for open_c, close_c in (("[", "]"), ("{", "}")):
        start, end = text.find(open_c), text.rfind(close_c)
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                continue
    return None


def _as_int(value) -> Optional[int]:
    """Coerce a model-supplied line number to int, or None. `bool` is rejected
    (it's an int subclass and `True`/`False` are never valid line numbers)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _salvage_objects(text: str) -> list:
    """Pull complete JSON objects out of a possibly-truncated array.

    Used when the response was cut off (e.g. hit max_tokens) and normal parsing failed:
    instead of losing everything, we recover the findings that fully arrived and stop at
    the incomplete trailing one. Uses the json decoder itself, so strings/escapes/nested
    braces are handled correctly.
    """
    start = text.find("[")
    if start == -1:
        return []
    decoder = json.JSONDecoder()
    objects: list = []
    idx, n = start + 1, len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n,":   # skip whitespace + commas
            idx += 1
        if idx >= n or text[idx] == "]":
            break
        try:
            obj, idx = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            break   # truncated/incomplete trailing object — stop, keep what we have
        objects.append(obj)
    return objects


def parse_findings(
    raw: str, staged_files: List[str], provider_label: Optional[str] = None
) -> Tuple[List[dict], bool]:
    """Turn a raw model response into validated finding dicts plus a parse-ok flag.

    `provider_label` names the model that produced the findings (e.g. "DeepSeek"); when
    given it is shown in each finding's source as `AI Review (DeepSeek)`.

    Returns `(findings, parse_ok)`. `parse_ok` answers "did we get a usable response?" —
    True whenever the JSON parsed, *including* a clean empty `[]` or a response whose
    findings were all dropped as hallucinated; False only when nothing parseable could be
    recovered. This lets the caller tell a clean review (`[], True`) from a blind one
    (`[], False`) and warn accordingly. Never raises. Output matches `gitleaks_runner`'s
    dict keys so `decision_engine` sees one shape from both scanners (see module docstring).
    Drops hallucinated entries whose `file` is not in the staged set.
    """
    data = _extract_json(raw)
    if isinstance(data, dict):
        items = data.get("findings", [])
        parse_ok = True
    elif isinstance(data, list):
        items = data
        parse_ok = True
    else:
        items = _salvage_objects(raw)   # response likely truncated — recover what completed
        parse_ok = bool(items)          # salvaged something = partial success; nothing = unparseable

    source = f"AI Review ({provider_label})" if provider_label else "AI Review"
    staged = set(staged_files)
    findings: List[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        file = item.get("file")
        if not file or file not in staged:   # drop hallucinated / non-staged findings
            continue
        severity = str(item.get("severity", "medium")).lower()
        if severity not in VALID_SEVERITIES:
            severity = "medium"

        # core keys — always present, mirroring gitleaks_runner's dict
        finding: dict = {
            "source": source,
            "rule": _sanitize(str(item.get("rule") or item.get("category") or "ai-finding")),
            "severity": severity,
            "file": file,
            "start_line": _as_int(item.get("start_line")),
            "end_line": _as_int(item.get("end_line")),
            "description": _sanitize(str(item.get("description", ""))),
        }

        # AI-only extras — included only when the model actually supplied them
        secret = item.get("secret")
        if secret:
            finding["secret"] = _sanitize(str(secret))
        category = item.get("category")
        if category:
            finding["category"] = _sanitize(str(category).replace("-", " ").capitalize())
        suggestion = item.get("suggestion")
        if suggestion:
            finding["suggestion"] = _sanitize(str(suggestion))

        findings.append(finding)
    return findings, parse_ok


def _resolve_provider(provider: Optional[str] = None) -> dict:
    """Return the PROVIDER_CONFIG entry for `provider`; when None, read `ai.provider`
    from commitgate.yaml. Raises ValueError on an unknown provider so a misconfig fails loud, 
    not by silently hitting the wrong endpoint."""
    if provider is None:
        from commitgate.config import load_config
        provider = load_config()["ai"].get("provider", DEFAULT_PROVIDER)
    if provider not in PROVIDER_CONFIG:
        raise ValueError(
            f"Unknown provider '{provider}' in commitgate.yaml. "
            f"Valid options: {', '.join(sorted(PROVIDER_CONFIG))}"
        )
    return PROVIDER_CONFIG[provider]


def _warn_ai_skipped(exc: Exception) -> None:
    """Print the fail-safe warning for a dead/absent AI review. The deterministic gitleaks
    gate is the floor, so a skipped AI check warns but never blocks or crashes the commit."""
    msg = str(exc)
    if len(msg) > 160:
        msg = msg[:160] + "..."
    print(f"[commitgate] AI review skipped ({msg}); deterministic gate unaffected.", file=sys.stderr)


def review(
    diff: str,
    staged_files: List[str],
    *,
    provider: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    extra_body: Optional[dict] = None,
    max_tokens_key: Optional[str] = None,
    provider_label: Optional[str] = None,
) -> Tuple[List[dict], bool]:
    """Run the AI review over a diff. Returns `(findings, ok)`; never raises on an LLM error.

    `ok` reports whether the AI layer actually completed a review, so the caller can fail
    closed: an empty diff or a clean pass is `([], True)` (nothing to warn about), but a
    dead/timed-out call, a missing CLI, or an unparseable response is `(..., False)` — the
    decision engine should then warn rather than treat "no findings" as all-clear.

    Transport is chosen by the provider's `kind`: `cli` shells out to a local coding-agent
    CLI (no API key), anything else speaks HTTP to an OpenAI-compatible endpoint.
    """
    if not diff or not diff.strip():
        return [], True   # nothing to review is not a failure

    prompt = build_prompt(diff)

    # Resolve the configured provider unless the caller pinned an explicit HTTP endpoint.
    pconf = None
    if base_url is None or model is None:
        pconf = _resolve_provider(provider)
        if provider_label is None:
            provider_label = pconf.get("label")

    # CLI transport: run a local CLI on the user's own subscription — no key involved.
    if pconf is not None and pconf.get("kind") == "cli":
        timeout = max(timeout, CLI_MIN_TIMEOUT)   # the agent boot alone can exceed a 20s cap
        try:
            raw = call_cli(
                pconf["command"], pconf["args"],
                f"{SYSTEM_PROMPT}\n\n{prompt}", timeout,
                pconf.get("result_key", "result"),
                env=pconf.get("env"),
                output_mode=pconf.get("output", "envelope"),
            )
        except Exception as exc:  # noqa: BLE001 - fail-safe must catch everything
            _warn_ai_skipped(exc)
            return [], False
        return parse_findings(raw, staged_files, provider_label)

    # HTTP transport: OpenAI-compatible /chat/completions.
    if pconf is not None:
        base_url = base_url or pconf["base_url"]
        model = model or pconf["model"]
        if extra_body is None:
            extra_body = pconf["extra_body"]
        if max_tokens_key is None:
            max_tokens_key = pconf.get("max_tokens_key", "max_tokens")
    if max_tokens_key is None:
        max_tokens_key = "max_tokens"
    if api_key is None:
        api_key = ai_api_key()      # load AI_KEY from env

    if base_url is None or model is None:
        # Malformed/partial provider config; fail closed rather than pass None to the HTTP client.
        _warn_ai_skipped(RuntimeError("AI provider missing base_url or model"))
        return [], False

    try:
        raw = call_llm(base_url, model, api_key, prompt, timeout, max_tokens, extra_body, max_tokens_key)
    except Exception as exc:  # noqa: BLE001 - fail-safe must catch everything
        _warn_ai_skipped(exc)
        return [], False
    return parse_findings(raw, staged_files, provider_label)


def review_staged(*, timeout: Optional[int] = None) -> Tuple[List[dict], bool]:
    """Convenience entry: pull the staged diff/files from git, then review. Provider and
    key are resolved inside `review` (config + env). Returns `(findings, ok)`. Timeout
    defaults to the COMMITGATE_AI_TIMEOUT env var or 20s."""
    from commitgate.git_utils import get_staged_diff, get_staged_files
    return review(
        get_staged_diff(),
        get_staged_files(),
        timeout=timeout if timeout is not None else _ai_timeout(),
    )
