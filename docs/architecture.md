# Architecture

## Stack

- **Language:** Python ≥ 3.10
- **CLI:** Typer
- **Terminal output:** Rich
- **Config:** PyYAML (`commitgate.yaml`)
- **LLM (HTTP):** requests (OpenAI-compatible — Groq, DeepSeek, OpenAI, Gemini)
- **LLM (CLI):** `subprocess` to a local coding-agent CLI (Claude Code) — no API key
- **Secret scanning:** Gitleaks — external binary invoked via `subprocess`

## Orchestration Flow

```
git commit → .git/hooks/pre-commit   (the hook calls commitgate scan)
git push   → .git/hooks/pre-push     (same, for the push range)
        →  commitgate scan   (the hook passes its type internally)
        ├─ git_utils.get_staged_diff() | get_pre_push_changes()  # staged diff OR push-range diff → (diff, files)
        ├─ config.load_config()                # commitgate.yaml — thresholds, flags
        ├─ gitleaks_runner.run_gitleaks_scan(files)  # deterministic secret detection
        ├─ ai_reviewer.review(diff, files)     # semantic LLM review → (findings, ok)
        ├─ decision_engine.decide(findings)    # allow / warn / block
        ├─ report_generator                    # Rich terminal output
        ├─ splunk_logger.log_decision()        # audit event (skipped if unconfigured)
        └─ exit code                           # block → non-zero (stops commit/push) · allow/warn → 0
```

## Modules

#### `cli.py`
Typer entry point. Commands: `scan`, `install-hook`, `init`, `version`. `install-hook` and `init` install either a pre-commit or pre-push hook (chosen interactively).

#### `git_utils.py`
All Git operations via subprocess.
- `get_staged_files()` — list of staged file paths
- `get_staged_diff()` — full staged diff as a string
- `get_pre_push_changes()` — `(diff, files)` for the push range, read from the pre-push hook's stdin ref metadata; fails closed (raises) if run outside a hook
- `is_git_repo()` — validates the working directory is a Git repo
- `install_git_hook(hook_type)` — writes `.git/hooks/pre-commit` or `.git/hooks/pre-push` (prompts for the type when not given)

#### `config.py`
Loads `commitgate.yaml` from the repo root and merges with built-in defaults.
- `load_config()` — returns the merged config dict
- `create_default_config()` — writes `commitgate.yaml` if not present

#### `gitleaks_runner.py`
Locates the gitleaks binary on PATH, runs `run_gitleaks_scan(file_paths)` per file in the change set (staged files for pre-commit, push-range files for pre-push), and parses the JSON report into finding dicts.

#### `decision_engine.py`
`decide(findings) → Decision`. Reads `policy.block_severity` from config; derives warn threshold as one rank below block. Returns `allow`, `warn`, or `block`.

#### `report_generator.py`
Rich terminal output. Formats findings with severity colouring, deduplicates overlapping gitleaks and AI findings.

#### `ai_reviewer.py`
Semantic review of the staged diff. Provider is set in `commitgate.yaml` (`ai.provider`); `review()` dispatches on the provider's transport `kind`:

- **HTTP providers** (`kind: http`, the default) — an OpenAI-compatible `/chat/completions` call; the API key is read from the `AI_KEY` environment variable.
- **CLI providers** (`kind: cli`) — shells out via `subprocess` to a local coding-agent CLI that runs on the user's own login, so **no API key is needed**.

Supported providers and their defaults:

| Provider | Transport | Model / command | API key |
|----------|-----------|-----------------|---------|
| `groq` | HTTP | `openai/gpt-oss-120b` | `AI_KEY` |
| `deepseek` | HTTP | `deepseek-v4-flash` | `AI_KEY` |
| `openai` | HTTP | `gpt-5.4-mini` | `AI_KEY` |
| `gemini` | HTTP | `gemini-2.5-flash` | `AI_KEY` |
| `claude-cli` | CLI | `claude` (Claude Code, model `haiku`) | none — uses your Claude login |
| `codex-cli` | CLI | `codex` (`codex exec --json`) | none — uses your `codex login` |

- `review(diff, staged_files)` — main orchestrator (called by `scan` for both hook types); resolves the provider from `PROVIDER_CONFIG`, then either calls the HTTP endpoint (key from env) or the CLI, and returns `(findings, ok)`
- `review_staged()` — convenience wrapper that pulls the staged diff/files from git, then delegates to `review()`
- `build_prompt(diff)` — wraps the diff into the security-review prompt
- `call_llm(...)` — OpenAI-compatible `/chat/completions` call with SSE streaming (HTTP providers)
- `call_cli(...)` — runs the CLI via subprocess (prompt piped on stdin), then unwraps its output per `output_mode`: Claude's single JSON envelope, or Codex's JSONL event stream (last `agent_message`). The timeout is floored so a per-commit review isn't spuriously skipped on a cold start
- `parse_findings(raw, staged_files)` — validates model output into finding dicts; returns `(findings, parse_ok)`

`ok=False` on any LLM error, timeout, or a missing/failed CLI — the caller warns and continues on the deterministic gate only. Never raises.

#### `splunk_logger.py`
`log_decision(decision) → None`. POSTs the scan decision to a Splunk HEC endpoint. Skips silently if `SPLUNK_HEC_TOKEN` is not set. Redacts the `secret` field before sending. Never raises.
