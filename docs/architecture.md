This document provides a high-level overview of the project architecture. Detailed implementation behavior should be documented in code comments and docstrings.

## Module Descriptions

#### cli.py

User-facing command-line interface

- `scan()` – Runs a CommitGate security scan.
- `install_hook()` – Installs the Git pre-commit hook.
- `version()` – Displays the current CommitGate version.

#### git_utils.py

Git-related utility functions.

- `get_staged_files()` – Returns a list of staged file paths.
- `get_staged_diff()` – Returns the staged Git diff as a string.
- `is_git_repo()` – Checks whether the current directory is inside a Git repository.
- `install_pre_commit_hook()` – Creates a pre-commit hook that runs `commitgate scan`.

#### gitleaks_runner.py

- Execute Gitleaks
- Parse Gitleaks output
- Return findings

#### ai_reviewer.py

Semantic (LLM) review of the staged diff. Findings are gitleaks-shaped dicts; key comes from `DEEPSEEK_API_KEY`. Fail-safe: any LLM error returns `([], False)` (deterministic gate unaffected).

- `review(diff, staged_files, ...)` – **Main entry for the CLI.** Runs the full AI review over a staged diff. Returns `(findings, ok)` — the finding dicts plus a bool flagging whether the review completed, so the caller can warn rather than treat a failed/blind review as clean. Never raises.
- `review_staged()` – Convenience entry: pulls the staged diff/files from git and the API key from env, then calls `review()` with defaults. Returns `(findings, ok)` too.
- `deepseek_api_key()` – Reads `DEEPSEEK_API_KEY` from the environment (loads `.env` if present).
- `build_prompt(diff)` – Wraps the staged diff into the user prompt.
- `call_llm(base_url, model, api_key, prompt, ...)` – Provider-agnostic call to an OpenAI-compatible `/chat/completions` endpoint; returns the raw response text.
- `parse_findings(raw, staged_files)` – Validates the model response into finding dicts (drops findings for files not in the staged set). Returns `(findings, parse_ok)`; `parse_ok` is `False` only when nothing parseable could be recovered — a clean empty result is `True`.

```text
review(diff, staged_files, ...) -> (list[dict], ok: bool)
  ├─ empty diff            → ([], True)    # nothing to review ≠ failure, don't warn
  ├─ call_llm() raises     → ([], False)   # network/timeout/HTTP — warn stays
  └─ else parse_findings(raw, staged) → return (findings, parse_ok)

parse_findings(raw, staged) -> (list[dict], parse_ok: bool)
  ├─ nothing parseable     → ([], False)   # _extract_json None AND _salvage_objects []
  └─ parsed (any length)   → (findings, True)   # incl. valid "[]" = clean, ok=True
```

#### decision_engine.py

- Determine action: allow / warn / block

#### report_generator.py

- Generate security report

#### config.py

- Load YAML configs
- Provide application settings