# just a smoke test

from commitgate.git_utils import get_staged_diff, get_staged_files, is_git_repo

def test_is_git_repo():
    assert is_git_repo() is True

def test_get_staged_files_returns_list():
    assert isinstance(get_staged_files(), list)

def test_get_staged_diff_returns_string():
    assert isinstance(get_staged_diff(), str)