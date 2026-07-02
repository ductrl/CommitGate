# CommitGate
An AI-powered security gate for Git. On every `git commit` — or every `git push` — CommitGate scans your changes for potential vulnerabilities and **blocks them** before secrets or risky code ever reach your history.

It runs two scanners over your staged changes and merges their findings:

| Layer | Tool | Catches |
|-------|------|---------|
| Deterministic | [**Gitleaks**](https://github.com/gitleaks/gitleaks) | Known secret shapes — API keys, tokens, passwords matching standard patterns |
| Semantic | **AI reviewer** (OpenAI-compatible — DeepSeek, OpenAI, Gemini, or Groq) | What regex misses — internal URLs, non-standard credentials, `eval`/`os.system`, data-leaking logic |

Findings from both layers are merged, deduplicated, and fed into a **decision engine** that rules `allow / warn / block`. A Rich terminal report explains why.

---

## Demo

![CommitGate Demo](assets/demo.gif)

*CommitGate blocking a vulnerable commit before it reaches Git history.*

---

## Table of Contents

- [Setup](#setup)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Splunk Setup](#splunk-setup-optional)
- [Module map](#module-map)
- [Data Privacy](#data-privacy)
- [License](#license)

---

## Setup

### 1. Install prerequisites

Install these on your machine **before** installing CommitGate:

- **Python ≥ 3.10**
- **Git**
- **Gitleaks** — an external binary that must be installed separately (it is *not* pulled in by `pip`):
  - Windows: `winget install gitleaks`
  - macOS: `brew install gitleaks`
  - Linux: download the release binary and place it on your `PATH`
  - Or follow Gitleaks's install instructions [here](https://github.com/gitleaks/gitleaks#installing)

  Confirm it's on your `PATH` before continuing:

  ```bash
  gitleaks version
  ```

- **AI API key** — required for the AI reviewer (pick one provider; you'll add the key to your `.env` in step 3):
  - [Groq](https://console.groq.com) — free tier available, recommended for getting started
  - [DeepSeek](https://platform.deepseek.com) — low cost
  - [OpenAI](https://platform.openai.com)
  - [Gemini](https://aistudio.google.com)

### 2. Install CommitGate

```bash
pip install git+https://github.com/ductrl/CommitGate.git
```

### 3. Configure environment variables

Create a `.env` file in the root of **your project** (not CommitGate's repo):

```env
# Required — AI reviewer (one key for whichever provider you set in commitgate.yaml)
AI_KEY=your-api-key-here
# Free option: get a Groq key at https://console.groq.com, then set provider: groq in commitgate.yaml

# Optional — AI review timeout in seconds (default: 20)
# COMMITGATE_AI_TIMEOUT=20

# Optional — Splunk audit logging (see Splunk Setup below)
# SPLUNK_HEC_TOKEN=your-hec-token-here
# SPLUNK_HEC_URL=https://prd-p-yourinstance.splunkcloud.com:8088/services/collector/event
# SPLUNK_VERIFY_SSL=false                   # required for Splunk Cloud free trial
```

**`.env` should be gitignored — your keys should never enter source or git history.**

### 4. Initialize CommitGate

Run this inside the repo you want to protect:

```bash
commitgate init
```

This does two things at once:
- Creates a `commitgate.yaml` config file in the repo root
- Installs a Git hook so CommitGate scans automatically. It asks whether you want a **pre-commit** hook (scan on every commit) or a **pre-push** hook (scan on every push) — see [Pre-commit vs pre-push](#pre-commit-vs-pre-push)

The generated `commitgate.yaml` looks like this — edit it to match your needs:

```yaml
ai:
  enabled: true          # set to false to run gitleaks only (no API key needed)
  # Options: openai, deepseek, gemini, groq
  # Tip: groq offers a free API key — get one at https://console.groq.com
  provider: deepseek
  timeout: 20            # seconds before AI review is abandoned (fail closed → warn)
policy:
  block_severity: high   # findings at this severity or above stop the commit, available options: low / medium / high / critical
reporting:
  show_suggestions: true # include AI fix suggestions in the terminal report
```

**Commit `commitgate.yaml`** so your whole team shares the same gate policy — it contains no secrets.

---

## Usage

```bash
commitgate init          # create commitgate.yaml + install a hook (asks: pre-commit or pre-push)
commitgate scan          # scan your changes (runs automatically via the installed hook)
commitgate install-hook  # install a hook only, no config file (asks: pre-commit or pre-push)
commitgate version       # print version
SKIP=commitgate git commit ...  # bypass CommitGate for a single commit
```

Once the hook is installed, just commit (or push) normally. CommitGate intercepts the action, scans the changes, and either lets it through or blocks it with a report.

### Pre-commit vs pre-push

`commitgate init` and `commitgate install-hook` ask which Git hook to install:

| Hook | Fires on | Scans | Use when |
|------|----------|-------|----------|
| **pre-commit** | every `git commit` | the staged diff | you want fast, incremental feedback as you work — the default |
| **pre-push** | every `git push` | every commit in the push range, not just the latest | you want a final gate before code leaves your machine — it catches a secret buried in an earlier local commit that a per-commit scan might have missed |

A blocked **commit** and a blocked **push** both stop with a non-zero exit code. Install both hooks if you want defense in depth.

### Decision outcomes

| Outcome | Meaning | Exit code |
|---------|---------|-----------|
| `allow` | No findings, or all below warn threshold | `0` — commit proceeds |
| `warn` | Medium-severity findings | `0` — commit proceeds, warnings printed |
| `block` | High or critical findings | `1` — commit stopped |

### Manual scan (without committing)

```bash
git add <file>
commitgate scan
git restore --staged <file>
```

---

## How it works

Both hooks feed the same scan pipeline — they differ only in what changes they hand it: the staged diff (pre-commit) or the full push range (pre-push).

```
git commit → .git/hooks/pre-commit   (staged diff)
git push   → .git/hooks/pre-push     (every commit in the push range)
        →  commitgate scan
        ├─ gitleaks_runner    scan the changes for known secret patterns
        ├─ ai_reviewer        LLM semantic review for issues regex can't catch
        ├─ decision_engine    merge findings → allow / warn / block
        ├─ report_generator   Rich terminal output
        ├─ splunk_logger      audit event to Splunk HEC (optional)
        └─ exit code          block → non-zero (stops the commit/push) · allow/warn → 0
```

---

## Splunk Setup (optional)

CommitGate can send an audit event to Splunk after every scan, giving you a searchable history of every commit decision.

### 1. Create a Splunk account

Sign up at `splunk.com`. Start a **Splunk Cloud free trial** from your account dashboard.

### 2. Enable HTTP Event Collector (HEC)

In your Splunk UI:

1. **Settings** → **Data Inputs** → **HTTP Event Collector**
2. Click **Global Settings** → set **All Tokens** to **Enabled** → **Save**

### 3. Create a HEC token

1. Still on the HTTP Event Collector page → **New Token**
2. **Name:** `commitgate-audit`
3. Click **Next** → **Source type:** type `commitgate:audit` and select **New**
4. **Index:** `main` → **Review** → **Submit**
5. Copy the token shown on the confirmation screen

### 4. Add to your `.env`

```env
SPLUNK_HEC_TOKEN=your-token-here
SPLUNK_HEC_URL=https://prd-p-yourinstance.splunkcloud.com:8088/services/collector/event
SPLUNK_VERIFY_SSL=false
```

> **Why `SPLUNK_VERIFY_SSL=false`?** Splunk Cloud free trial issues certificates missing the Authority Key Identifier extension required by Python 3.10+, making SSL verification impossible on the free plan. Paid Splunk accounts use properly signed certificates and do not need this setting.

### 5. Verify the connection

Stage any file and run a manual scan:

```bash
git add <any-staged-file>
commitgate scan
git restore --staged <any-staged-file>
```

If the audit event reaches Splunk you'll see no yellow "Splunk audit log failed" warning in the output.

### 6. View events in Splunk

**Search & Reporting** → run:

```
sourcetype="commitgate:audit"
```

Each `commitgate scan` appears as one event with `action`, `reason`, `findings_count`, and the full findings list.

### Splunk dashboard

Build a **CommitGate Security Gate** dashboard with these searches:

| Panel | Type | Search |
|-------|------|--------|
| Decisions over time | Line chart | `sourcetype="commitgate:audit" action!="allow" \| timechart count by action` |
| Blocks today | Single value | `sourcetype="commitgate:audit" action=block \| stats count as Blocked` |
| Top triggered categories | Bar chart | `sourcetype="commitgate:audit" \| stats count by findings{}.category \| sort -count` |
| Findings by severity | Pie chart | `sourcetype="commitgate:audit" \| stats count by findings{}.severity` |
| Recent blocked commits | Table | `sourcetype="commitgate:audit" \| table _time reason findings_count \| sort -_time` |

---

## Module map

| Module | Role |
|--------|------|
| `cli.py` | Typer commands: `scan`, `install-hook`, `init`, `version` |
| `git_utils.py` | Git ops via subprocess: staged files/diff, pre-push change range (read from the hook's stdin), is-git-repo, install pre-commit/pre-push hook |
| `gitleaks_runner.py` | Run gitleaks binary, parse findings into dicts |
| `ai_reviewer.py` | LLM semantic review (OpenAI-compatible — provider set in `commitgate.yaml`), returns `(findings, ok)` |
| `decision_engine.py` | Merge findings → `allow / warn / block` (reads `commitgate.yaml` thresholds) |
| `report_generator.py` | Format findings for Rich terminal output |
| `splunk_logger.py` | POST audit event to Splunk HEC after every scan |
| `config.py` | Generate and load `commitgate.yaml`, merge with built-in defaults |

See `docs/architecture.md` for the full architecture and `CONTRIBUTING.md` for the branch/PR workflow.

---

## Data Privacy

When `ai.enabled: true`, CommitGate sends your **staged code diffs to an external AI provider** (whichever you configure in `commitgate.yaml`). Do not use the AI reviewer on confidential or proprietary code without your organization's authorization. Set `ai.enabled: false` to run gitleaks only — no data leaves your machine.

Supported providers: **Groq**, **DeepSeek**, **OpenAI**, **Gemini**. Local LLM support (Ollama) and self-hosted Splunk are on the roadmap so CommitGate can operate fully air-gapped.

---

## License

[MIT](LICENSE) © 2026 Mike Ly

CommitGate is free to use, modify, and distribute under the terms of the MIT License.
