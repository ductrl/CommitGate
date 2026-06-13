# CommitGate

An AI-powered Git **pre-commit security gate**. On every `git commit`, CommitGate scans the staged diff with two layers and decides whether to let the commit through.

| Layer | Tool | Catches |
|-------|------|---------|
| Deterministic | **Gitleaks** | Known secret shapes — API keys, tokens, passwords matching standard patterns |
| Semantic | **AI reviewer** (DeepSeek) | What regex misses — internal URLs, non-standard credentials, `eval`/`os.system`, data-leaking logic |

Findings from both layers are merged, deduplicated, and fed into a **decision engine** that rules `allow / warn / block`. A Rich terminal report explains why.

---

## How it works

```
git commit
  └─ .git/hooks/pre-commit  →  commitgate scan
        ├─ gitleaks_runner    scan staged diff for known secret patterns
        ├─ ai_reviewer        LLM semantic review for issues regex can't catch
        ├─ decision_engine    merge findings → allow / warn / block
        ├─ report_generator   Rich terminal output
        ├─ splunk_logger      audit event to Splunk HEC (optional)
        └─ exit code          block → non-zero (stops commit) · allow/warn → 0
```

---

## Prerequisites

- **Python ≥ 3.9**
- **Git**
- **Gitleaks** — external binary, installed separately:
  - Windows: `winget install gitleaks`
  - macOS: `brew install gitleaks`
  - Linux: download the release binary and place it on your `PATH`
- **DeepSeek API key** — required for the AI reviewer (`platform.deepseek.com`)

---

## Setup

### 1. Clone the repo

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

### 3. Install CommitGate

```bash
pip install -e ".[dev]"
```

This installs the `commitgate` CLI and all dependencies.

### 4. Configure environment variables

```bash
cp .env.example .env          # Windows: Copy-Item .env.example .env
```

Open `.env` and fill in your values:

```env
# Required — AI reviewer
DEEPSEEK_API_KEY=sk-your-key-here

# Optional — AI review timeout in seconds (default: 20)
# COMMITGATE_AI_TIMEOUT=20

# Optional — Splunk audit logging (see Splunk Setup below)
# SPLUNK_HEC_TOKEN=your-hec-token-here
# SPLUNK_HEC_URL=https://prd-p-yourinstance.splunkcloud.com:8088/services/collector/event
# SPLUNK_CA_BUNDLE=/path/to/splunk-ca.pem   # for self-signed certs — see Splunk Setup
```

`.env` is gitignored — your keys never enter source or git history.

### 5. Install the Git hook

```bash
commitgate install-hook
```

This writes `.git/hooks/pre-commit` so `commitgate scan` fires automatically on every commit.

---

## Usage

```bash
commitgate scan          # scan staged files (runs automatically via hook)
commitgate install-hook  # write .git/hooks/pre-commit
commitgate version       # print version
```

Once the hook is installed, just commit normally. CommitGate intercepts the commit, scans the diff, and either lets it through or blocks it with a report.

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

### Manual scan (testing)

Stage any file with a planted secret or vulnerability, run a scan, then unstage:

```bash
git add <file-with-issue>
commitgate scan
git restore --staged <file-with-issue>
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

### 4. Export the Splunk certificate

Splunk Cloud free trial uses a self-signed certificate on port 8088. Export it once so CommitGate can verify the connection securely:

**Windows (PowerShell):**
```powershell
python -c "
import ssl, socket
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection(('prd-p-yourinstance.splunkcloud.com', 8088)) as sock:
    with ctx.wrap_socket(sock, server_hostname='prd-p-yourinstance.splunkcloud.com') as s:
        pem = ssl.DER_cert_to_PEM_cert(s.getpeercert(binary_form=True))
        open('splunk-ca.pem', 'w').write(pem)
print('Saved splunk-ca.pem')
"
```

Replace `prd-p-yourinstance` with your actual Splunk hostname. The file `splunk-ca.pem` is gitignored — it stays local to your machine.

> If your Splunk instance has a proper CA-signed certificate (e.g. paid account), skip this step and omit `SPLUNK_CA_BUNDLE` from your `.env`.

### 5. Add to your `.env`

```env
SPLUNK_HEC_TOKEN=your-token-here
SPLUNK_HEC_URL=https://prd-p-yourinstance.splunkcloud.com:8088/services/collector/event
SPLUNK_CA_BUNDLE=/path/to/your/splunk-ca.pem
```

### 6. Verify the connection

Stage any file and run a manual scan:

```bash
git add <any-staged-file>
commitgate scan
git restore --staged <any-staged-file>
```

If the audit event reaches Splunk you'll see no yellow "Splunk audit log failed" warning in the output.

### 7. View events in Splunk

**Search & Reporting** → run:

```
sourcetype="commitgate:audit"
```

Each `commitgate scan` appears as one event with `action`, `reason`, `findings_count`, and the full findings list.

### Splunk dashboard

Build a **CommitGate Security Gate** dashboard with these searches:

| Panel | Type | Search |
|-------|------|--------|
| Decisions over time | Line chart | `sourcetype="commitgate:audit" \| timechart count by action` |
| Blocks today | Single value | `sourcetype="commitgate:audit" action=block \| stats count as Blocked` |
| Top triggered rules | Bar chart | `sourcetype="commitgate:audit" \| stats count by findings{}.rule \| sort -count \| head 10` |
| Findings by severity | Pie chart | `sourcetype="commitgate:audit" \| stats count by findings{}.severity` |
| Recent blocked commits | Table | `sourcetype="commitgate:audit" action=block \| table _time reason findings_count \| sort -_time` |

---

## Running tests

```bash
pytest -q
```

Integration tests (live Splunk) are skipped automatically unless `SPLUNK_HEC_TOKEN` is set in your shell. To run them:

```bash
pytest tests/test_splunk_logger.py -v
```

---

## Module map

| Module | Role | Status |
|--------|------|--------|
| `cli.py` | Typer commands: `scan`, `install-hook`, `version` | Working |
| `git_utils.py` | Staged files/diff, is-git-repo, hook install | Working |
| `gitleaks_runner.py` | Run gitleaks binary, parse findings into dicts | Working |
| `ai_reviewer.py` | LLM semantic review (DeepSeek), returns `(findings, ok)` | Working |
| `decision_engine.py` | Merge findings → `allow / warn / block` | Working |
| `report_generator.py` | Format findings for Rich terminal output | Working |
| `splunk_logger.py` | POST audit event to Splunk HEC after every scan | Working |
| `config.py` | Load `.commitgate.yml` settings and defaults | Planned |

See `docs/architecture.md` for the full architecture and `CONTRIBUTING.md` for the branch/PR workflow.
