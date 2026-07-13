# Architecture

CommitGate is a Python CLI and Git-hook security gate. It builds one change set, runs deterministic and semantic scanners, normalizes their findings into one contract, and turns the result into an `allow`, `warn`, or `block` exit code.

## Design principles

- **Git owns the boundary.** Pre-commit reviews the staged diff; pre-push reviews the push range.
- **The deterministic scanner is the floor.** Gitleaks runs independently of AI availability.
- **The AI layer receives a diff, not the whole repository.** Model output is untrusted and validated before use.
- **One finding shape crosses module boundaries.** Gitleaks and AI findings are merged before policy evaluation.
- **Exact evidence beats fuzzy heuristics.** Secret locations are corrected only from one exact added-line evidence match; deduplication uses exact file and line coordinates.
- **The CLI orchestrates but does not implement scanner logic.** Each component remains independently testable.

## Runtime flow

```text
git commit / git push
        |
        v
installed Git hook
        |
        v
cli.scan()
  1. load and validate commitgate.yaml
  2. honor enabled / one-time skip settings
  3. collect (diff, files) for pre-commit or pre-push
  4. run Gitleaks over the selected files
  5. call ai_review.review(diff, files) when AI is enabled
  6. merge findings and deduplicate exact normalized locations
  7. apply reporting.min_severity without hiding blockers
  8. decide allow / warn / block
  9. log warn/block decisions to Splunk when configured
 10. render the terminal report and return the Git-facing exit code
```

`block` returns a non-zero exit code, so Git aborts the commit or push. `allow` and `warn` return zero. If pre-push metadata is unavailable, pre-push mode fails closed rather than silently scanning the wrong range.

## Package layout

```text
commitgate/
├── cli.py
├── config.py
├── git_utils.py
├── gitleaks_runner.py
├── decision_engine.py
├── report_generator.py
├── splunk_logger.py
└── ai_review/
    ├── __init__.py
    ├── reviewer.py
    ├── prompt.py
    ├── transport.py
    └── findings.py
```

The supported AI import path is:

```python
from commitgate.ai_review import review
```

The former `commitgate.ai_reviewer` module was removed. `ai_review/__init__.py` is not an implementation dumping ground; it defines and exports the package's supported entry points.

## Module map

| Module | Responsibility |
|--------|----------------|
| `cli.py` | Typer commands: `scan`, `reset-config`, `install-hook`, `init`, and `version`. Owns runtime sequencing and exit codes. |
| `config.py` | Loads, merges, validates, creates, and resets `commitgate.yaml`. |
| `git_utils.py` | Git subprocess operations, staged/push-range collection, and hook installation. |
| `gitleaks_runner.py` | Locates Gitleaks, scans the selected files, and maps its JSON report into finding dictionaries. |
| `decision_engine.py` | Converts the merged findings into `allow`, `warn`, or `block` using `policy.block_severity`. |
| `report_generator.py` | Exact-location deduplication, severity display filtering, and Rich-compatible finding formatting. |
| `splunk_logger.py` | Sends sanitized warn/block decision events to Splunk HEC when configured. |
| `ai_review/__init__.py` | Public AI package API. Re-exports review, prompt, transport, and parsing entry points. |
| `ai_review/reviewer.py` | AI configuration resolution, prompt/transport/parser orchestration, provider dispatch, and fail-safe warnings. |
| `ai_review/prompt.py` | Evidence-gated security prompt, diff wrapper, output-field pruning, and prompt-level minimum-severity rules. |
| `ai_review/transport.py` | Provider registry, OpenAI-compatible HTTP/SSE requests, local agent subprocess execution, and response-envelope unwrapping. |
| `ai_review/findings.py` | JSON extraction/salvage, schema validation, staged-file filtering, text sanitization, and deterministic secret-location normalization. |

## AI review internals

```text
cli.py
  |
  v
ai_review.review()                 public package entry point
  |
  v
reviewer.py                        resolve config + orchestrate
  |----------> prompt.py           build system prompt + wrap diff
  |----------> transport.py        HTTP provider or local agent CLI
  |                |
  |                v
  |          configured AI provider
  |                |
  |<--------- raw model output
  |
  |----------> findings.py         parse + validate + normalize
  |
  v
(findings, ok) -> cli.py
```

### Public package API

`ai_review/__init__.py` exports:

- `review()` and `review_staged()`
- `build_system_prompt()` and `build_prompt()`
- `call_llm()` and `call_cli()`
- `parse_findings()`
- `SYSTEM_PROMPT`

Normal runtime callers should use `review()`. The lower-level exports exist for focused integration and testing; they do not bypass validation automatically.

### Reviewer orchestration

`reviewer.review(diff, staged_files, ...)`:

1. Treats an empty diff as a successful empty review.
2. Resolves reporting fields and the prompt severity floor.
3. Builds the system prompt and diff-only user prompt.
4. Resolves the configured provider.
5. Dispatches either `call_llm()` or `call_cli()`.
6. Passes raw output, the selected file list, provider label, and original diff to `parse_findings()`.
7. Returns `(findings, ok)`.

Transport failures, timeouts, missing agent binaries, and unusable model output produce `([], False)` plus a warning. The CLI then continues using deterministic findings only. Configuration errors are rejected separately rather than silently selecting another provider.

### Prompt construction

`prompt.py` owns model policy rather than transport code. Its prompt:

- treats diff contents as untrusted data rather than instructions;
- reports only issues introduced or completed by added lines;
- requires concrete evidence for high/critical injection and exposure findings;
- excludes standard token formats already covered by Gitleaks while retaining non-standard credentials such as URL-embedded passwords;
- prunes optional output fields and sub-threshold categories based on reporting configuration.

### Provider transport

Providers are data entries in `PROVIDER_CONFIG`; orchestration branches only on transport `kind`.

| Provider | Kind | Default model or command | Credential source |
|----------|------|--------------------------|-------------------|
| `openai` | HTTP | `gpt-5.4-mini` | `AI_KEY` |
| `gemini` | HTTP | `gemini-2.5-flash` | `AI_KEY` |
| `deepseek` | HTTP | `deepseek-v4-flash` | `AI_KEY` |
| `kimi` | HTTP | `kimi-k2.7-code-highspeed` | `AI_KEY` |
| `groq` | HTTP | `openai/gpt-oss-120b` | `AI_KEY` |
| `claude-cli` | CLI | `claude`, Haiku | Claude login |
| `codex-cli` | CLI | `codex exec --json` | Codex login |
| `agy-cli` | CLI | `agy`, Gemini 3.5 Flash Low | Antigravity login |

HTTP providers use OpenAI-compatible chat completions with SSE handling. CLI providers use list-form subprocess arguments and one-shot output modes:

- Claude: JSON envelope, prompt on stdin, tools/thinking disabled.
- Codex: JSONL event stream, prompt on stdin, read-only sandbox and low reasoning.
- Antigravity: plain output, prompt in `--print`, sandboxed plan mode, guarded against Windows command-line overflow.

### Finding validation and location normalization

`findings.py` treats model output as untrusted:

1. Parse JSON directly, extract JSON from fences/prose, or salvage complete objects from a truncated array.
2. Drop non-object entries and findings whose `file` is not in the selected file list.
3. Normalize severity, line-number types, text encoding, and the shared finding keys.
4. Parse added lines from unified-diff file headers and hunk headers.
5. For a secret finding, correct its line only when the returned secret is usable and appears on exactly one added line in that file.

Missing, redacted, short, non-matching, context-only, removed-only, or ambiguous evidence leaves the model's location unchanged. This conservative fallback may leave a visible duplicate, but it does not delete a potentially distinct finding.

After parsing, `report_generator.remove_dup()` uses the exact `(file, start_line)` key. When AI and Gitleaks report that same normalized location, Gitleaks wins. There is no `+/-1` window or credential-name vocabulary.

## Cross-module contracts

### AI review return

```python
findings, ok = review(diff, files)
```

- `([], True)`: empty diff or a successful clean review.
- `([finding, ...], True)`: usable model response with validated findings.
- `([], False)`: transport failure or unusable response; deterministic scanning continues with a warning.

### Finding dictionary

Both scanners feed dictionaries into the same list. AI findings always normalize these core keys:

```python
{
    "source": str,
    "rule": str,
    "severity": "low" | "medium" | "high" | "critical",
    "file": str,
    "start_line": int | None,
    "end_line": int | None,
    "description": str,
    # optional: secret, category, suggestion
}
```

The decision engine does not depend on scanner-specific classes.

## Trust boundaries and data egress

- Gitleaks runs locally as an external binary.
- HTTP AI providers receive the selected diff over HTTPS using `AI_KEY`.
- Agent CLI providers use local login sessions, but their configured vendor still receives the diff; they are not local/offline models.
- Claude is invoked without tools. Codex and Antigravity may retain read access to workspace files within their configured restrictions.
- AI responses are untrusted until `findings.py` validates them.
- Splunk receives sanitized finding data with the `secret` field removed.
- No-findings/allow scans currently exit before Splunk logging; configured audit events cover warn/block decisions.

### Current scanner-coordinate limitation

The AI parser derives locations from the Git-selected diff. Gitleaks currently receives selected file paths and scans their working-tree contents. If unstaged edits shift a file after staging, the scanners can temporarily use different line-coordinate spaces. The exact evidence normalizer fixes model-generated secret locations within the diff, but it does not solve that scanner-input mismatch; feeding Gitleaks staged/push-range snapshots is separate work.

## Dependency direction

```text
cli -> ai_review (public API)
ai_review.__init__ -> reviewer, prompt, transport, findings
reviewer -> config, prompt, transport, findings
transport -> prompt
findings -> standard library only
```

New provider-specific I/O belongs in `transport.py`; new prompt policy belongs in `prompt.py`; new output validation belongs in `findings.py`; orchestration belongs in `reviewer.py`. Avoid recreating a monolithic reviewer module.
