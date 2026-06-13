# Architecture

## Stack

- **Language:** Python ≥ 3.10
- **CLI:** Typer
- **Terminal output:** Rich
- **Config:** PyYAML (`commitgate.yaml`)
- **LLM HTTP:** requests (OpenAI-compatible — Groq, DeepSeek, OpenAI, Gemini)
- **Secret scanning:** Gitleaks — external binary invoked via `subprocess`

## Orchestration Flow

```
git commit
   └─ .git/hooks/pre-commit  →  commitgate scan
        ├─ git_utils.get_staged_files/diff()
        ├─ config.load_config()               # commitgate.yaml — thresholds, flags
        ├─ gitleaks_runner.run_gitleaks_scan() # deterministic secret detection
        ├─ ai_reviewer.review_staged()        # semantic LLM review → (findings, ok)
        ├─ decision_engine.decide(findings)   # allow / warn / block
        ├─ report_generator                   # Rich terminal output
        ├─ splunk_logger.log_decision()       # audit event (skipped if unconfigured)
        └─ exit code                          # block → non-zero · allow/warn → 0
```

## Modules

#### `cli.py`
Typer entry point. Commands: `scan`, `install-hook`, `init`, `version`.

#### `git_utils.py`
All Git operations via subprocess.
- `get_staged_files()` — list of staged file paths
- `get_staged_diff()` — full staged diff as a string
- `is_git_repo()` — validates the working directory is a Git repo
- `install_pre_commit_hook()` — writes `.git/hooks/pre-commit`

#### `config.py`
Loads `commitgate.yaml` from the repo root and merges with built-in defaults.
- `load_config()` — returns the merged config dict
- `create_default_config()` — writes `commitgate.yaml` if not present

#### `gitleaks_runner.py`
Locates the gitleaks binary on PATH, runs it per staged file, and parses the JSON report into finding dicts.

#### `decision_engine.py`
`decide(findings) → Decision`. Reads `policy.block_severity` from config; derives warn threshold as one rank below block. Returns `allow`, `warn`, or `block`.

#### `report_generator.py`
Rich terminal output. Formats findings with severity colouring, deduplicates overlapping gitleaks and AI findings.

#### `ai_reviewer.py`
Semantic review of the staged diff via an OpenAI-compatible LLM. Provider is set in `commitgate.yaml` (`ai.provider`); the API key is read from the `AI_KEY` environment variable.

Supported providers and their defaults:

| Provider | Model |
|----------|-------|
| `groq` | `openai/gpt-oss-120b` |
| `deepseek` | `deepseek-v4-flash` |
| `openai` | `gpt-5.4-mini` |
| `gemini` | `gemini-2.5-flash` |

- `review_staged()` — main entry; loads config, selects provider from `PROVIDER_CONFIG`, pulls staged diff from git, calls the LLM, returns `(findings, ok)`
- `review(diff, staged_files)` — core orchestrator
- `build_prompt(diff)` — wraps the diff into the security-review prompt
- `call_llm(...)` — OpenAI-compatible `/chat/completions` call with SSE streaming
- `parse_findings(raw, staged_files)` — validates model output into finding dicts; returns `(findings, parse_ok)`

`ok=False` on any LLM error or timeout — the caller warns and continues on the deterministic gate only. Never raises.

#### `splunk_logger.py`
`log_decision(decision) → None`. POSTs the scan decision to a Splunk HEC endpoint. Skips silently if `SPLUNK_HEC_TOKEN` is not set. Redacts the `secret` field before sending. Never raises.
