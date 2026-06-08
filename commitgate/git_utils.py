import subprocess
from pathlib import Path

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

def install_pre_commit_hook() -> Path:
    """
    Install a Git pre-commit hook that runs CommitGate before each commit.

    Returns the path to the installed hook.
    """

    if not is_git_repo():
        raise RuntimeError("Not inside a Git repository.")
    
    hook_path = Path(".git/hooks/pre-commit")
    
    subprocess.run(
        f"echo '#!/bin/sh' > {hook_path}",
        shell=True,
        check=True
    )

    subprocess.run(
        f'echo \'commitgate scan\' >> {hook_path}',
        shell=True,
        check=True
    )

    # Add permission to execute
    subprocess.run(
        f"chmod +x {hook_path}",
        shell=True,
        check=True
    )

    return hook_path