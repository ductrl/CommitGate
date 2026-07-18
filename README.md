<div align="center">

# CommitGate

An AI-powered security gate for Git. On every `git commit` or every `git push`.

CommitGate scans your changes and **blocks them** before secrets or risky code ever reach your history.

[How it works](#how-it-works) · [Providers](#providers) · [Setup](#setup) · [How to use](#how-to-use) · [Configuration](#configuration) · [Data Privacy](#data-privacy)

</div>

---

## Demo

<div align="center">
  <img src="assets/demo.gif" alt="CommitGate Demo">
  <p><em>CommitGate blocking a vulnerable commit before it reaches Git history.</em></p>
</div>

---

## How it works

CommitGate runs two scanners over your changes and merges their findings:

| Scanner | Catches |
|---------|---------|
| [![Gitleaks][gitleaks-badge]][gitleaks-link] | Known secret shapes: API keys, tokens, passwords |
| **AI Reviewer** | What regex missed: code understanding, private knowledge |

- You run `git commit` (or `git push`). The installed Git hook hands your changes to CommitGate.

- CommitGate decides an outcome **allow**, **warn**, or **block**.

- You get a report in your terminal. On **block**, the commit or push is stopped; otherwise it proceeds.

See [`docs/architecture.md`](docs/architecture.md) for the module-by-module design.

---

## Providers

These are the available providers that we support for the AI reviewer. You can choose between use an OpenAI-compatible API key (faster, recommended) or use your own AI agents.

| Type | Providers |
|------|-----------|
| **OpenAI-compatible API** (needs an API key) | [![OpenAI][openai-badge]][openai-link] [![Gemini][gemini-badge]][gemini-link] [![DeepSeek][deepseek-badge]][deepseek-link] [![Kimi][kimi-badge]][kimi-link] [![Groq][groq-badge]][groq-link] |
| **AI Agents** (no API key, uses your local login) | [![Claude Code][claude-badge]][claude-link] [![Codex][codex-badge]][codex-link] [![Antigravity][antigravity-badge]][antigravity-link] |

---

## Setup

### 1. Install the prerequisites

| Requirement | How to install |
|-------------|----------------|
| **Python ≥ 3.10** | [python.org](https://www.python.org/downloads/) |
| **Git** | [git-scm.com](https://git-scm.com/downloads) |
| **Gitleaks** (separate binary, *not* installed by `pip`) | See installation instructions below. |

#### Installing Gitleaks

- **Windows**
  ```powershell
  winget install gitleaks
  ```

- **macOS**
  ```bash
  brew install gitleaks
  ```

- **Linux**
  - Download the latest release from the
    [Gitleaks Releases](https://github.com/gitleaks/gitleaks/releases)
  - Place the binary somewhere on your `PATH`

- For additional installation methods (Snap, Docker, package managers, etc.), see the official [Gitleaks installation guide](https://github.com/gitleaks/gitleaks#installing).

Confirm Gitleaks is ready:

```bash
gitleaks version
```

### 2. Install CommitGate

```bash
pip install git+https://github.com/ductrl/CommitGate.git
```

### 3. Protect your repo

Run this **inside the repo you want to guard**:

```bash
commitgate init
```

This creates a `commitgate.yaml` config file and installs a Git hook. It asks whether you want a **pre-commit** or **pre-push** hook (see [How to use](#how-to-use)).

### 4. Set up the AI Reviewer

Open `commitgate.yaml` and set `provider` to match one of the paths below.

**Option A: API key** (OpenAI · Gemini · DeepSeek · Kimi · Groq)

```yaml
ai:
  provider: groq        # or openai / gemini / deepseek / kimi
```

Create a `.env` file in your project root and add your key

```env
AI_KEY=your-api-key-here
```

**Keep `.env` out of Git, it holds your key.**

**Option B: AI Agent** (Claude Code, Codex, or Antigravity; no API key)

First confirm the agent is installed and logged in:

```bash
claude --version    # Claude Code
codex --version     # Codex
agy --version       # Antigravity
```

Then set the provider:

```yaml
ai:
  provider: claude-cli   # or codex-cli / agy-cli
```

**Option C: No AI** (Gitleaks only)

```yaml
ai:
  enabled: false
```

It is recommended to commit `commitgate.yaml` so your whole team shares the same gate policy. The file doesn't and shouldn't include any secrets.

---

## How to use

After `commitgate init`, just `git commit` / `git push` as usual and CommitGate will automatically scan your changes.

### pre-commit vs pre-push

You pick one when you run `commitgate init` (or `commitgate install-hook`):

| Hook | Runs on | Scans |
|------|---------|-------|
| **pre-commit** | every `git commit` | your staged changes → fast, per-commit feedback |
| **pre-push** | every `git push` | every commit in the push range → a final gate before code leaves your machine |

To switch, or add the other one later, run `commitgate install-hook` and choose. Install both for defense in depth.

### What each outcome means

| Outcome | When |
|---------|------|
| `allow` | no findings |
| `warn` | findings **below** the block severity |
| `block` | findings **at or above** the block severity (default: `high`) |

Change the bar with `policy.block_severity` in `commitgate.yaml` (`low` / `medium` / `high` / `critical`). See [Configuration](#configuration) for that and other options.

### Scan manually

Check your staged changes any time, without committing:

```bash
git add app.py
commitgate scan
```

If `app.py` hardcodes a secret, you'll see:

```
CommitGate detected 1 security finding(s):
[CRITICAL] Finding #1
	- Source: gitleaks
	- Category: Secret leak
	- Severity: critical
	- File: app.py
	- Location: Line 12 to 12
	- Description: AWS Access Key detected
Commit blocked by CommitGate.
```

### Skip once

Need to bypass the gate for a single commit:

```bash
SKIP=commitgate git commit -m "your message"
```

---

## Configuration

`commitgate init` writes a `commitgate.yaml` in your repo root. Every option has a safe default — edit only what you need. To restore the file to defaults at any time:

```bash
commitgate reset-config
```

The full file, annotated:

```yaml
# Enable or disable CommitGate for this repository.
enabled: true

ai:
  # Enable AI-powered security review.
  enabled: true

  # AI provider to use.
  # Option 1: (AI_KEY in .env): openai, gemini, deepseek, kimi, groq (Tip: groq offers a free API key - at https://console.groq.com)
  # Option 2: local agent login (no API key): claude-cli, codex-cli, agy-cli
  provider: deepseek

  # Maximum time (seconds) allowed for AI review.
  timeout: 20

policy:
  # Findings at or above this severity block the commit/push.
  # Options: low, medium, high, critical
  block_severity: high

reporting:
  # Minimum severity shown in CommitGate output.
  # Must be <= block_severity, so a blocking finding is never hidden
  # Options: low, medium, high, critical
  # Example: medium shows medium, high, and critical findings, but hides low findings.
  # Raising this to high speeds up the AI review significantly, but may hide some lower-severity findings.
  min_severity: medium

  # Control which optional fields are displayed for each finding.
  # Turning off description and suggestions also speeds up the AI review.
  fields:
    source: true
    category: true
    description: true
    suggestions: true
```

### Tuning for speed

- CommitGate scan time is mostly determined by how much output it needs to generate. In general, the less information it needs to print, the faster it runs.
- **`reporting.min_severity`**: Raising to `medium` or `high` returns fewer findings and reduces scan time.
- **`reporting.fields.description` / `suggestions`**: AI will skip generating those fields entirely and significantly improve scan speed.

Both stay bounded by `policy.block_severity` (`min_severity` can't be raised above it), so a blocking finding is never hidden or skipped.

---

## Data Privacy

When the AI Reviewer is enabled, CommitGate sends the **selected change diff to the AI provider you configure** in `commitgate.yaml` (staged diff for pre-commit, push-range diff for pre-push). This applies to AI Agents too (Claude Code → Anthropic, Codex → OpenAI, Antigravity → Google), as your diff is still sent to their provider, so they are *not* air-gapped options.

**Do not** use the AI Reviewer on confidential or proprietary code without your organization's authorization. Set `ai.enabled: false` to run Gitleaks only. 

**Fully local LLM support is on the roadmap.**

---

## License

[MIT](LICENSE) © 2026 Mike Ly

CommitGate is free to use, modify, and distribute under the terms of the MIT License.

<!-- provider badge + link definitions -->
[openai-badge]: assets/badges/openai.svg
[gemini-badge]: assets/badges/gemini.svg
[deepseek-badge]: https://img.shields.io/badge/DeepSeek-4D6BFE?logo=deepseek&logoColor=white
[kimi-badge]: https://img.shields.io/badge/Kimi-111827?logo=moonrepo&logoColor=white
[groq-badge]: assets/badges/groq.svg
[claude-badge]: https://img.shields.io/badge/Claude_Code-C15F3C?logo=claude&logoColor=white
[codex-badge]: assets/badges/codex.svg
[antigravity-badge]: assets/badges/antigravity.svg
[openai-link]: https://platform.openai.com
[gemini-link]: https://aistudio.google.com/
[deepseek-link]: https://platform.deepseek.com
[kimi-link]: https://platform.kimi.ai/console/account
[groq-link]: https://console.groq.com
[claude-link]: https://www.anthropic.com/claude-code
[codex-link]: https://openai.com/codex/
[antigravity-link]: https://antigravity.google/product/antigravity-cli
[gitleaks-badge]: assets/badges/gitleaks.svg
[gitleaks-link]: https://gitleaks.org/
