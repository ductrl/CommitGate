"""Hook-install tests. Run inside a throwaway git repo so they never touch the
real .git/hooks. `install_git_hook(hook_type=...)` is passed an explicit type to
skip the interactive questionary prompt."""

import subprocess
from pathlib import Path

import pytest

from commitgate.git_utils import install_git_hook


@pytest.fixture
def temp_git_repo(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.mark.parametrize("hook_type", ["pre-commit", "pre-push"])
def test_install_writes_commitgate_block(temp_git_repo, hook_type):
    hook_path = install_git_hook(hook_type=hook_type)

    assert hook_path == Path(".git/hooks") / hook_type
    assert hook_path.exists()

    content = hook_path.read_text(encoding="utf-8")
    assert content.startswith("#!/bin/sh")
    assert f"commitgate scan --hook-type {hook_type}" in content


def test_install_is_idempotent(temp_git_repo):
    before = install_git_hook(hook_type="pre-commit").read_text(encoding="utf-8")
    after = install_git_hook(hook_type="pre-commit").read_text(encoding="utf-8")

    # Re-installing leaves an existing CommitGate hook untouched — no duplicate block.
    assert after == before
    assert after.count("commitgate scan") == 1


def test_install_appends_to_existing_shell_hook(temp_git_repo):
    hook_path = Path(".git/hooks/pre-commit")
    hook_path.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")

    install_git_hook(hook_type="pre-commit")
    content = hook_path.read_text(encoding="utf-8")

    assert "echo existing" in content          # original preserved
    assert "commitgate scan --hook-type pre-commit" in content


def test_install_refuses_non_shell_hook(temp_git_repo):
    hook_path = Path(".git/hooks/pre-commit")
    hook_path.write_text("#!/usr/bin/env python\nprint('hi')\n", encoding="utf-8")

    with pytest.raises(RuntimeError):
        install_git_hook(hook_type="pre-commit")
