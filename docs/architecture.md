**CommitGate** is an AI-powered Git pre-commit security gate.

## Module Descriptions

#### cli.py

- Typer entry point for the program
- This is where user-facing commands will live

#### git_utils.py

- For Git-related operations 
- Retrieve stage diffs
- Retrieve staged files
- Install Git hooks

#### gitleaks_runner.py

- Execute Gitleaks
- Parse Gitleaks output
- Return findings

#### ai_reviewer.py

- Build AI prompts
- Gather least-privilege context/code
- Call LLM API
- Parse findings

#### decision_engine.py

- Determine action: allow / warn / block

#### report_generator.py

- Generate security report

#### config.py

- Load YAML configs
- Provide application settings