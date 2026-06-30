"""Tests for pre-push change detection. The git calls and the hook's stdin are
always mocked — these never shell out to git or require a remote."""

from contextlib import nullcontext
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from commitgate import cli, git_utils
from commitgate.git_utils import (
    EMPTY_TREE_SHA,
    ZERO_SHA,
    PrePushHookError,
    _is_valid_sha,
    get_pre_push_changes,
)

LOCAL = "a" * 40
REMOTE = "b" * 40


class FakeStdin:
    """Stand-in for the hook's stdin (Git writes the push ref metadata here)."""

    def __init__(self, text, tty=False):
        self._text = text
        self._tty = tty

    def isatty(self):
        return self._tty

    def read(self):
        return self._text


def _ranges(text, *, tty=False, **patches):
    """Run _get_pre_push_ranges with stdin = `text` and any helper overrides."""
    helpers = patch.multiple(git_utils, **patches) if patches else nullcontext()
    with patch.object(git_utils.sys, "stdin", FakeStdin(text, tty=tty)), helpers:
        return git_utils._get_pre_push_ranges()


# --- SHA validation (the "minor security fix" guard) --------------------------

@pytest.mark.parametrize("value", [LOCAL, REMOTE, ZERO_SHA, EMPTY_TREE_SHA])
def test_valid_sha_accepts_40_hex(value):
    assert _is_valid_sha(value) is True


@pytest.mark.parametrize("value", ["", "abc", "g" * 40, LOCAL.upper(), LOCAL + "0", "; rm -rf /"])
def test_valid_sha_rejects_junk(value):
    assert _is_valid_sha(value) is False


# --- range derivation ---------------------------------------------------------

def test_existing_remote_branch_uses_remote_sha():
    line = f"refs/heads/main {LOCAL} refs/heads/main {REMOTE}"
    assert _ranges(line) == [(REMOTE, LOCAL)]


def test_new_branch_with_origin_main_uses_merge_base():
    line = f"refs/heads/feat {LOCAL} refs/heads/feat {ZERO_SHA}"
    ranges = _ranges(
        line,
        _git_ref_exists=lambda branch: True,
        _get_merge_base=lambda a, b: "c" * 40,
    )
    assert ranges == [("c" * 40, LOCAL)]


def test_first_push_empty_remote_uses_empty_tree():
    line = f"refs/heads/main {LOCAL} refs/heads/main {ZERO_SHA}"
    ranges = _ranges(line, _git_ref_exists=lambda branch: False)
    assert ranges == [(EMPTY_TREE_SHA, LOCAL)]


def test_branch_deletion_is_skipped():
    # Deleting a remote branch pushes nothing -> no range to scan.
    line = f"(delete) {ZERO_SHA} refs/heads/old {REMOTE}"
    assert _ranges(line) == []


def test_malformed_and_invalid_lines_are_skipped():
    lines = "\n".join([
        "only three fields here",                         # wrong field count
        f"refs/heads/x notasha refs/heads/x {REMOTE}",    # invalid local sha
        f"refs/heads/y {LOCAL} refs/heads/y {REMOTE}",    # valid -> kept
    ])
    assert _ranges(lines) == [(REMOTE, LOCAL)]


def test_tty_stdin_raises():
    # Run outside a hook (interactive terminal) -> fail closed, do not scan nothing.
    with pytest.raises(PrePushHookError):
        _ranges("", tty=True)


# --- get_pre_push_changes -----------------------------------------------------

def test_get_pre_push_changes_raises_when_no_ranges():
    with patch.object(git_utils, "_get_pre_push_ranges", return_value=[]):
        with pytest.raises(PrePushHookError):
            get_pre_push_changes()


def test_get_pre_push_changes_returns_diff_and_unique_files():
    def fake_run_git(args):
        if "--name-only" in args:
            return "app/a.py\napp/b.py\n"
        return "diff --git a/app/a.py\n+secret = 'x'\n"

    with patch.object(git_utils, "_get_pre_push_ranges", return_value=[(REMOTE, LOCAL)]), \
         patch.object(git_utils, "_run_git", side_effect=fake_run_git):
        diff, files = get_pre_push_changes()

    assert "secret = 'x'" in diff
    assert sorted(files) == ["app/a.py", "app/b.py"]


def test_get_pre_push_changes_dedupes_files_across_ranges():
    def fake_run_git(args):
        if "--name-only" in args:
            return "app/a.py\n"
        return "some diff\n"

    ranges = [(REMOTE, LOCAL), (EMPTY_TREE_SHA, LOCAL)]
    with patch.object(git_utils, "_get_pre_push_ranges", return_value=ranges), \
         patch.object(git_utils, "_run_git", side_effect=fake_run_git):
        _, files = get_pre_push_changes()

    assert files == ["app/a.py"]   # same file in both ranges -> one entry


# --- cli fail-closed wiring (Hard Constraint #7) ------------------------------

def test_scan_pre_push_outside_hook_exits_nonzero():
    runner = CliRunner()
    with patch.object(cli, "get_pre_push_changes", side_effect=PrePushHookError("no stdin")):
        result = runner.invoke(cli.app, ["scan", "--hook-type", "pre-push"])

    assert result.exit_code == 1
    assert "pre-push mode must be run from a Git pre-push hook" in result.output
