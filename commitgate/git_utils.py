import subprocess
from pathlib import Path
from typing import Literal
import questionary

SHELL_SHEBANGS = {
    "#!/bin/sh",
    "#!/bin/bash",
    "#!/usr/bin/env sh",
    "#!/usr/bin/env bash",
}

def get_staged_files() -> list[str]:
    """
    Return a list of staged file paths.
    """
    res = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True
    )

    if res.returncode != 0:
        raise RuntimeError(res.stderr)

    return res.stdout.split()

def get_staged_diff() -> str:
    """
    Return the staged diff as a string.
    """
    res = subprocess.run(
        ["git", "diff", "--cached"],
        capture_output=True,
        text=True
    )

    if res.returncode != 0:
        raise RuntimeError(res.stderr)

    return res.stdout

def get_pre_push_diff() -> str:
    raise NotImplementedError("Pre-push diff retrieval is not implemented yet.")

def is_git_repo() -> bool:
    """
    Return True if the current directory is inside a Git repository, False otherwise.
    """
    res = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True
    )

    return (res.returncode == 0 and res.stdout.strip() == "true")

def _is_shell_hook(content: str) -> bool:
    lines = content.splitlines()

    if not lines:
        return False

    return lines[0].strip() in SHELL_SHEBANGS

def build_commitgate_hook_block(hook_type: str) -> str:
    return f"""
# >>> CommitGate start >>>
commitgate scan --hook-type {hook_type}
# <<< CommitGate end <<<
"""

def _write_commitgate_hook(hook_type: str, hook_path: Path) -> None:
    hook_path.write_text(
        f"#!/bin/sh{build_commitgate_hook_block(hook_type=hook_type)}",
        encoding="utf-8",
    )
    hook_path.chmod(0o755)

def prompt_for_hook_type() -> str:
    answer = questionary.select(
        "Which Git hook do you want to install?",
        choices=["pre-commit", "pre-push"],
        default="pre-commit",
    ).ask()

    if answer is None:
        raise KeyboardInterrupt("Hook selection cancelled.")
    
    return answer


def install_git_hook(hook_type: str | None = None) -> Path:
    """
    Install a Git pre-commit hook that runs CommitGate before each commit.

    Returns the path to the installed hook.
    """

    if not is_git_repo():
        raise RuntimeError("Not inside a Git repository.")
    
    if hook_type is None:
        hook_type = prompt_for_hook_type()
    
    hook_path = Path(".git/hooks") / hook_type

    # We should handle 3 cases:
    # 1. There is no pre-commit hook installed, so we create a new file
    # 2. There is already a pre-commit hook installed, so we avoid overwritting the file
    # 3. CommitGate hook is already installed, so we don't do anything

    # CASE 1: There is no pre-commit hook installed
    if not hook_path.exists():
        _write_commitgate_hook(hook_type=hook_type, hook_path=hook_path)
        return hook_path

    existing_content = hook_path.read_text(encoding="utf-8")

    # EDGE CASE: If pre-commit hook exists but is empty
    if not existing_content.strip():
        _write_commitgate_hook(hook_type=hook_type, hook_path=hook_path)
        return hook_path

    # CASE 3: CommitGate hook is already installed
    if "commitgate scan" in existing_content:
        hook_path.chmod(0o755)
        return hook_path

    # CASE 2: There is already a pre-commit hook installed -> We add the hook to the end of the file
    # NOTE: If the installed pre-commit hook is non-shell, then the user will have to install the hook manually
    if not _is_shell_hook(existing_content):
        raise RuntimeError(
            "A non-shell pre-commit hook already exists. "
            "CommitGate will not modify it automatically. "
            "Please manually add a command that runs `commitgate scan`."
        )

    hook_path.write_text(
        existing_content.rstrip() + build_commitgate_hook_block(hook_type=hook_type),
        encoding="utf-8",
    )
    hook_path.chmod(0o755)
    
    return hook_path