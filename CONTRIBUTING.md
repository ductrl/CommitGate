# Contributing to CommitGate

## Development Setup

Clone the repository:

```bash
git clone https://github.com/ductrl/CommitGate.git
cd CommitGate
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install CommitGate in editable mode:

```bash
pip install -e ".[dev]"
```

---

## Branching Strategy

Do not commit directly to `main`.

Create a feature branch:

```bash
git checkout main
git pull origin main
git checkout -b feature/my-feature
```

Examples:

```bash
git checkout -b feature/ai-reviewer
git checkout -b feature/gitleaks-runner
git checkout -b feature/splunk-logging
```

---

## Commit Guidelines

Commit small, working changes.

Examples:

```bash
git commit -m "Add Typer CLI foundation"
git commit -m "Implement staged diff retrieval"
git commit -m "Add Gitleaks integration"
```

Avoid:

```bash
git commit -m "Update files"
git commit -m "Fix stuff"
```

---

## Pull Request Workflow

1. Push feature branch.
2. Open Pull Request into `main`.
3. Request review.
4. Merge after approval.

---

## GitHub Issues

Every major task should be tracked by a GitHub Issue.

Reference issues in commits when appropriate:

```bash
git commit -m "Implement staged diff retrieval (#3)"
```

---

## Project Structure

commitgate/   
├── cli.py    
├── git_utils.py   
├── gitleaks_runner.py   
├── ai_reviewer.py   
├── decision_engine.py   
├── report_generator.py   
├── splunk_logger.py   
├── config.py  

See `docs/architecture.md` for details.
