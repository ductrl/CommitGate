# CommitGate

An AI-powered Git **pre-commit security gate**. On `git commit` it scans the staged diff
with two layers and decides whether to let the commit through:

1. **Gitleaks** — fast, deterministic regex/entropy scan for known secret shapes.
2. **AI reviewer** — an LLM (DeepSeek) that catches what regex can't: hardcoded internal
   URLs, non-standard credentials, risky `eval`/`os.system`, data-leaking logic.

## Pipeline

```
git commit
  └─ .git/hooks/pre-commit → commitgate scan
        ├─ gitleaks_runner   → deterministic secret scan   [working]
        ├─ ai_reviewer       → semantic LLM review         [working, run standalone for now]
        └─ decision_engine   → allow / warn / block        [not built yet]
```

Today `commitgate scan` runs the **gitleaks** layer and blocks the commit (exit 1) if it
finds secrets. The **AI reviewer** is built and works, but is not yet wired into `scan` —
it runs standalone until `decision_engine` lands.

## Prerequisites

- **Python ≥ 3.9**
- **Git**
- **Gitleaks** — an external binary, installed separately (not a pip package):
  - Windows: `winget install gitleaks`
  - macOS: `brew install gitleaks`
  - Linux: download the release binary and put it on your `PATH`
- **DeepSeek API key** — only needed to run the AI reviewer (see step 4)

## Setup

### 1. Clone

```bash
git clone https://github.com/ductrl/CommitGate.git
cd CommitGate
```

### 2. Create and activate a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install CommitGate (editable, with dev tools)

```bash
pip install -e ".[dev]"
```
This installs the `commitgate` command plus all dependencies.

### 4. Configure the AI reviewer key (optional)

The AI reviewer reads its key from a local `.env` file (never committed).

```bash
cp .env.example .env          # Windows: Copy-Item .env.example .env
```
Then open `.env` and replace the placeholder with your real DeepSeek key:
```
DEEPSEEK_API_KEY=sk-your-real-key
```
`.env` is gitignored — your key never enters source or git history.

### 5. Install the Git hook

```bash
commitgate install-hook
```
This writes `.git/hooks/pre-commit` so `commitgate scan` runs automatically on every commit.

> ⚠️ **Known issue — not cross-platform yet.** `install_pre_commit_hook()` shells out to Unix
> commands (`echo`, `chmod`). On **Windows it fails** (verified: `chmod` errors with exit 1, and
> the hook file is written with literal quotes). The **macOS/Linux path is untested.** Until this
> is fixed, run `commitgate scan` manually instead of relying on the hook.

## Usage

```bash
commitgate scan          # scan staged files with gitleaks (exit 1 = blocked)
commitgate version       # print version
commitgate install-hook  # install the pre-commit hook
```

Once the hook is installed, just commit normally — the scan runs first and stops the commit
if gitleaks finds a secret.

### Running the AI reviewer standalone

Until it's wired into `scan`, run it directly on your staged changes (needs the `.env` key):

```bash
git add <file>
python -c "from commitgate.ai_reviewer import review_staged; print(review_staged())"
```
It returns a tuple `(findings, ok)`: `findings` is a list of finding dicts (`file`, `start_line`,
`severity`, `description`, …), and `ok` is a bool flagging whether the review actually completed.
A clean pass is `([], True)`; a failed/unavailable review is `([], False)` — so the caller can tell
"nothing found" from "couldn't review" and warn instead of assuming all-clear. It fails safe — an LLM
error returns `([], False)`, never blocks.

## Running the tests

```bash
pytest -q
```

## Module map

| Module | Role | Status |
|--------|------|--------|
| `cli.py` | Typer commands: `scan`, `install-hook`, `version` | working |
| `git_utils.py` | Staged files/diff, is-git-repo, hook install | staged files/diff working; **hook install fails on Windows, untested on Unix** |
| `gitleaks_runner.py` | Run gitleaks, parse findings | working |
| `ai_reviewer.py` | LLM semantic review (DeepSeek), finding dicts | working (standalone) |
| `decision_engine.py` | Merge findings → allow/warn/block | not built |
| `report_generator.py` | Rich terminal report | not built |
| `config.py` | Load `.commitgate.yml` settings | not built |

See `docs/architecture.md` for details, and `CONTRIBUTING.md` for the branch/PR workflow.
