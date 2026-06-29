import subprocess
from pathlib import Path
import questionary
import sys
import re

SHELL_SHEBANGS = {
    "#!/bin/sh",
    "#!/bin/bash",
    "#!/usr/bin/env sh",
    "#!/usr/bin/env bash",
}

GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ZERO_SHA = "0" * 40

# The SHA of Git's empty tree object. This is helpful when we need to
# diff against an empty repo
EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
DEFAULT_REMOTE_BRANCH = "origin/main"

class PrePushHookError(RuntimeError):
    """Raised when pre-push information is unavailable."""

def _run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout

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

def get_pre_push_changes() -> tuple[str, list[str]]:
    # Git provides this information on the hook's stdin:
    # <local-ref> SP <local-object-name> SP <remote-ref> SP <remote-object-name> LF
    # Which is extremely helpful to retrieve the code that's about to be pushed
    ranges = _get_pre_push_ranges()

    if not ranges:
        raise PrePushHookError(
            "Pre-push mode requires Git pre-push metadata via stdin."
        )

    diffs: list[str] = []
    files : set[str] = set()

    for base_sha, local_sha in ranges:
        diff = _run_git(["diff", base_sha, local_sha])
        file_output = _run_git(["diff", "--name-only", base_sha, local_sha])

        if diff.strip():
            diffs.append(diff)

        for file in file_output.splitlines():
            if file:
                files.add(file)

    return "\n".join(diffs), list(files)

def _get_merge_base(commit_a: str, commit_b: str) -> str:
    # Receive the SHA of commit A and B, and find their last common ancestor
    return _run_git(["merge-base", commit_a, commit_b]).strip()

def _git_ref_exists(branch: str) -> bool:
    try:
        _run_git(["rev-parse", "--verify", branch])
        return True
    except subprocess.CalledProcessError:
        return False
    
def _get_pre_push_ranges() -> list[tuple[str, str]]:
    """
    Returns a list of (base_sha, local_sha)
    """
    if sys.stdin.isatty():
        raise PrePushHookError(
            "Pre-push mode must be run from a Git pre-push hook."
        )

    lines = sys.stdin.read().strip().splitlines()
    ranges : list[tuple[str, str]] = []

    for line in lines:
        if len(line.split()) != 4:
            continue

        local_ref, local_sha, remote_ref, remote_sha = line.split()

        if not (_is_valid_sha(local_sha) and _is_valid_sha(remote_sha)):
            continue

        # EGDE CASE: When a remote branch is being deleted -> There is no code being pushed
        if local_sha == ZERO_SHA:
            continue

        if remote_sha != ZERO_SHA:
            # Existing remote branch
            base_sha = remote_sha
        elif _git_ref_exists(DEFAULT_REMOTE_BRANCH):
            # New branch, but the remote already has a main branch
            # So we compare commits that only this branch has
            base_sha = _get_merge_base(local_sha, "origin/main")
        else:
            # First push into an empty remote repository.
            # Compare against an empty tree (which means scanning the entire repo)
            base_sha = EMPTY_TREE_SHA
        
        ranges.append((base_sha, local_sha))
    
    return ranges


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

def _is_valid_sha(value: str) -> bool:
    return bool(GIT_SHA_RE.fullmatch(value))

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