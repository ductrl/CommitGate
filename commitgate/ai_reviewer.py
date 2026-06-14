"""AI reviewer — the semantic scanning layer.

Gitleaks catches known secret *shapes*. This module catches what regex can't:
hardcoded internal hostnames/URLs, credentials that match no known pattern, risky
`eval`/`exec`, `.env` values pasted into source, data-leaking logic. That semantic
gap is CommitGate's actual differentiator.

Pipeline: staged diff -> build_prompt -> call_llm -> parse_findings -> (findings, ok).

Finding shape: a plain dict matching `gitleaks_runner`'s keys so `decision_engine`
sees one structure from both scanners. Core keys (always present): `source`, `rule`,
`severity`, `file`, `start_line`, `end_line`, `description`. AI-only extras, included
only when the model supplies them: `secret`, `category`, `confidence`, `suggestion`.
Gitleaks dicts are a subset of this (no `severity`/`source`); the AI adds the semantic
severity the decision engine needs.

Design notes:
- **Provider-agnostic client.** `call_llm` takes `(base_url, model, api_key, ...)` and
  speaks the OpenAI-compatible `/chat/completions` API. DeepSeek is the default today;
  a local Ollama model drops in later by swapping the config triple (~90% reuse).
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
import sys
import time
from typing import List, Optional, Tuple

import requests

DEFAULT_TIMEOUT = 20        # seconds; override with COMMITGATE_AI_TIMEOUT env var
DEFAULT_MAX_TOKENS = 2048
CONNECT_TIMEOUT = 5         # separate connect timeout — fail fast if network is down

DEFAULT_PROVIDER = "deepseek"

PROVIDER_CONFIG = {
    "openai": {
        "label": "OpenAI",          # shown in finding source, e.g. "AI Review (OpenAI)"
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
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_CONFIDENCE = {"low", "medium", "high"}

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
You are a security code reviewer for a git pre-commit gate. You are given a STAGED DIFF.

A separate regex+entropy secret-scanner (gitleaks) ALREADY catches standard secret patterns — API keys, access tokens, private-key blocks, and known credential formats. Do NOT duplicate that work. Focus ONLY on what regex cannot catch: hardcoded internal hostnames/URLs, credentials or tokens in a non-standard shape, risky eval/exec or command/SQL injection, .env values pasted into source, and logic that leaks sensitive data. Do NOT report style nits or generic advice.

Be thorough and specific in `description` and `suggestion`.

Respond with ONLY a JSON array (no prose, no code fences). Each element:
{"rule": str, "category": str (sentence case, e.g. "Secret leak", "Hardcoded url", "Injection risk"), "severity": "low"|"medium"|"high"|"critical", "confidence": "low"|"medium"|"high", "file": str, "start_line": int|null, "end_line": int|null, "secret": str|null, "description": str, "suggestion": str}

The "file" must be a path that appears in the diff. If you find nothing, return [].
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
        confidence = item.get("confidence")
        if confidence is not None:
            confidence = str(confidence).lower()
            if confidence in VALID_CONFIDENCE:
                finding["confidence"] = confidence
        suggestion = item.get("suggestion")
        if suggestion:
            finding["suggestion"] = _sanitize(str(suggestion))

        findings.append(finding)
    return findings, parse_ok


def review(
    diff: str,
    staged_files: List[str],
    *,
    base_url: str = PROVIDER_CONFIG[DEFAULT_PROVIDER]["base_url"],
    model: str = PROVIDER_CONFIG[DEFAULT_PROVIDER]["model"],
    api_key: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    extra_body: Optional[dict] = PROVIDER_CONFIG[DEFAULT_PROVIDER]["extra_body"],
    max_tokens_key: str = "max_tokens",
    provider_label: Optional[str] = None,
) -> Tuple[List[dict], bool]:
    """Run the AI review over a staged diff. Returns `(findings, ok)`, never raises.

    `ok` reports whether the AI layer actually completed a review, so the caller can fail
    closed: an empty diff or a clean pass is `([], True)` (nothing to warn about), but a
    dead/timed-out call or an unparseable response is `(..., False)` — the decision engine
    should then warn rather than treat "no findings" as all-clear. Fail-safe: any LLM
    error/timeout warns to stderr and returns `([], False)` so the deterministic gate
    still decides alone.
    """
    if not diff or not diff.strip():
        return [], True   # nothing to review is not a failure
    prompt = build_prompt(diff)
    try:
        raw = call_llm(base_url, model, api_key, prompt, timeout, max_tokens, extra_body, max_tokens_key)
    except Exception as exc:  # noqa: BLE001 - fail-safe must catch everything
        msg = str(exc)
        if len(msg) > 120:
            msg = msg[:120] + "..."
        print(f"[commitgate] AI review skipped ({msg}); deterministic gate unaffected.", file=sys.stderr)
        return [], False
    return parse_findings(raw, staged_files, provider_label)


def review_staged(*, timeout: Optional[int] = None) -> Tuple[List[dict], bool]:
    """Convenience entry: pull the staged diff/files from git and the key from env,
    then route to the configured provider. Returns `(findings, ok)` like `review`.
    Provider is read from commitgate.yaml (`ai.provider`). Timeout defaults to
    COMMITGATE_AI_TIMEOUT env var or 20s."""
    from commitgate.git_utils import get_staged_diff, get_staged_files
    from commitgate.config import load_config

    config = load_config()
    provider = config["ai"].get("provider", DEFAULT_PROVIDER)

    if provider not in PROVIDER_CONFIG:
        raise ValueError(
            f"Unknown provider '{provider}' in commitgate.yaml. "
            f"Valid options: {', '.join(sorted(PROVIDER_CONFIG))}"
        )

    pconf = PROVIDER_CONFIG[provider]

    return review(
        get_staged_diff(),
        get_staged_files(),
        base_url=pconf["base_url"],
        model=pconf["model"],
        api_key=ai_api_key(),
        extra_body=pconf["extra_body"],
        max_tokens_key=pconf.get("max_tokens_key", "max_tokens"),
        timeout=timeout if timeout is not None else _ai_timeout(),
        provider_label=pconf.get("label", provider),
    )
