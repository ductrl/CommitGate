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

- Build AI prompt
- Call LLM API (DeepSeek; key from `DEEPSEEK_API_KEY`)
- Parse findings into gitleaks-shaped dicts
- Fail safe: return no findings on LLM error

#### decision_engine.py

- Determine action: allow / warn / block

#### report_generator.py

- Generate security report

#### config.py

- Load YAML configs
- Provide application settings