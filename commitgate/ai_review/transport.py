"""Provider registry and HTTP/CLI transports for AI review."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import List, Optional

import requests

from commitgate.ai_review.prompt import SYSTEM_PROMPT

DEFAULT_TIMEOUT = 20        # seconds; suits the fast HTTP providers. override w/ COMMITGATE_AI_TIMEOUT
DEFAULT_MAX_TOKENS = 2048
CONNECT_TIMEOUT = 5         # separate connect timeout — fail fast if network is down
CLI_MIN_TIMEOUT = 30        # CLI agents cold-start a process first
WINDOWS_ARGV_SAFE_LIMIT = 30_000  # CreateProcess has a 32,767-character command-line limit

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
    "gemini": {
        "label": "Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.5-flash",
        "extra_body": None,
    },
    "deepseek": {
        "label": "DeepSeek",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-flash",
        "extra_body": {"thinking": {"type": "disabled"}},  # V4 defaults thinking ON — too slow for a hook
    },
    "kimi": {
        "label": "Kimi",
        "base_url": "https://api.moonshot.ai/v1",
        "model": "kimi-k2.7-code-highspeed",
        "extra_body": {"temperature": 1},
        "max_tokens_key": "max_completion_tokens",
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
        # exec              : non-interactive. --json: JSONL event stream (we read the last agent_message)
        # -s read-only      : no writes/network for shell commands (least-privilege). NOTE:
        #                     Codex has no "no tools" mode, so it may still READ workspace files.
        # -c ...effort=low  : cut reasoning latency (Codex's analogue of Claude's thinking-off).
        # trailing "-"      : read the prompt from stdin.
        # exec is non-interactive -> never prompts for approval, so no -a/approval flag is needed.
        "args": [
            "exec", "--json",
            "-s", "read-only",
            "-c", "model_reasoning_effort=low",
            "-",
        ],
        "output": "jsonl",      # Codex event stream; answer in the last agent_message
    },
    "agy-cli": {
        "kind": "cli",
        "label": "Antigravity",
        "command": "agy",
        # Non-interactive, restricted, read-only review. The prompt follows --print.
        "args": [
            "--model", "Gemini 3.5 Flash (Low)",
            "--sandbox", "--mode", "plan", "--print",
        ],
        "prompt_mode": "argv",
        "output": "plain",
    },
}

def call_llm(
    base_url: str,
    model: str,
    api_key: Optional[str],
    prompt: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    extra_body: Optional[dict] = None,
    max_tokens_key: str = "max_tokens",
    system_prompt: Optional[str] = None,
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
            {"role": "system", "content": system_prompt or SYSTEM_PROMPT},
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
    prompt_mode: str = "stdin",
) -> str:
    """Run a local coding-agent CLI (e.g. Claude Code, Codex, Antigravity) as transport.

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
    argv = _cli_argv(exe, args)
    process_input = prompt
    if prompt_mode == "argv":
        argv.append(prompt)
        process_input = None
        # CreateProcess limits the entire command line to 32,767 characters.
        if os.name == "nt" and len(subprocess.list2cmdline(argv)) > WINDOWS_ARGV_SAFE_LIMIT:
            raise RuntimeError(
                f"'{command}' prompt is too large for the Windows command line; "
                "reduce the staged diff or use another AI provider"
            )
    elif prompt_mode != "stdin":
        raise ValueError(f"Unsupported CLI prompt mode: {prompt_mode}")

    try:
        proc = subprocess.run(
            argv,
            input=process_input,
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
    if output_mode == "plain":
        return (proc.stdout or "").strip()
    return _unwrap_cli_output(proc.stdout, result_key)
