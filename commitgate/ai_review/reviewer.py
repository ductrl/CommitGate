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
  caller fail closed (warn) instead of mistaking a blind review for a clean one.
- **API key from env only:** `AI_KEY`, never config/source.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import List, Optional, Tuple

import requests

# Keep the review orchestration and its directly tested collaborators in one module.
# The package initializer exposes the supported public entry points.
from commitgate.ai_review.prompt import (
    SYSTEM_PROMPT,
    _SEVERITY_GATE,
    _SYSTEM_PROMPT_HEAD,
    build_prompt,
    build_system_prompt,
)
from commitgate.ai_review.transport import (
    CLI_MIN_TIMEOUT,
    CONNECT_TIMEOUT,
    DEFAULT_MAX_TOKENS,
    DEFAULT_PROVIDER,
    DEFAULT_TIMEOUT,
    PROVIDER_CONFIG,
    WINDOWS_ARGV_SAFE_LIMIT,
    _cli_argv,
    _unwrap_cli_output,
    _unwrap_codex_jsonl,
    call_cli,
    call_llm,
)
from commitgate.ai_review.findings import (
    VALID_SEVERITIES,
    _HUNK_HEADER,
    _REDACTED_SECRET_VALUES,
    _UNICODE_SANITIZE,
    _added_lines_by_file,
    _as_int,
    _diff_path,
    _extract_json,
    _normalize_secret_locations,
    _salvage_objects,
    _sanitize,
    _secret_needles,
    parse_findings,
)

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


def _resolve_report_fields() -> dict:
    """Read `reporting.fields` from commitgate.yaml so the prompt can request only the fields
    the user wants shown. Fail open -- any error, or a config without a reporting section,
    returns {}, which build_system_prompt reads as 'request everything'. Pruning a field is a
    speed optimization; never worth risking a dropped finding when config resolution hiccups."""
    try:
        from commitgate.config import load_config
        fields = load_config().get("reporting", {}).get("fields", {})
        return fields if isinstance(fields, dict) else {}
    except Exception:  # noqa: BLE001 - a config hiccup must not break the review
        return {}


def _resolve_min_severity() -> str:
    try:
        from commitgate.config import load_config
        sev = load_config().get("reporting", {}).get("min_severity", "low")
        return sev if sev in ("low", "medium", "high", "critical") else "low"
    except Exception:
        return "low"


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
    report_fields: Optional[dict] = None,
    min_severity: Optional[str] = None,
) -> Tuple[List[dict], bool]:
    """Run the AI review over a diff. Returns `(findings, ok)`; never raises on an LLM error.

    `ok` reports whether the AI layer actually completed a review, so the caller can fail
    closed: an empty diff or a clean pass is `([], True)` (nothing to warn about), but a
    dead/timed-out call, a missing CLI, or an unparseable response is `(..., False)` — the
    decision engine should then warn rather than treat "no findings" as all-clear.
    """
    if not diff or not diff.strip():
        return [], True   # nothing to review is not a failure

    if report_fields is None:
        report_fields = _resolve_report_fields()
    if min_severity is None:
        min_severity = _resolve_min_severity()
    system_prompt = build_system_prompt(
        include_category=report_fields.get("category", True),
        include_description=report_fields.get("description", True),
        include_suggestion=report_fields.get("suggestions", True),
        min_severity=min_severity,
    )
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
                f"{system_prompt}\n\n{prompt}", timeout,
                pconf.get("result_key", "result"),
                env=pconf.get("env"),
                output_mode=pconf.get("output", "envelope"),
                prompt_mode=pconf.get("prompt_mode", "stdin"),
            )
        except Exception as exc:  # noqa: BLE001 - fail-safe must catch everything
            _warn_ai_skipped(exc)
            return [], False
        return parse_findings(raw, staged_files, provider_label, diff=diff)

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
        raw = call_llm(base_url, model, api_key, prompt, timeout, max_tokens, extra_body, max_tokens_key,
                       system_prompt=system_prompt)
    except Exception as exc:  # noqa: BLE001 - fail-safe must catch everything
        _warn_ai_skipped(exc)
        return [], False
    return parse_findings(raw, staged_files, provider_label, diff=diff)


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
