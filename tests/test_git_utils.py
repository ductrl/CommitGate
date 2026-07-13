import subprocess
from types import SimpleNamespace

from commitgate.git_utils import get_staged_diff, get_staged_files, is_git_repo

def test_is_git_repo():
    assert is_git_repo() is True

def test_get_staged_files_returns_list():
    assert isinstance(get_staged_files(), list)

def test_get_staged_diff_returns_string():
    assert isinstance(get_staged_diff(), str)


def test_get_staged_diff_preserves_utf8_unicode(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    unicode_file = tmp_path / "unicode.txt"
    unicode_file.write_text("security heart: \u2764\n", encoding="utf-8")
    subprocess.run(["git", "add", "unicode.txt"], cwd=tmp_path, check=True)
    monkeypatch.chdir(tmp_path)

    diff = get_staged_diff()

    assert "security heart: \u2764" in diff


def test_get_staged_diff_requests_utf8_decoding(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="diff", stderr="")

    monkeypatch.setattr("commitgate.git_utils.subprocess.run", fake_run)

    assert get_staged_diff() == "diff"
    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"
