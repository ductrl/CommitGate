"""Config generation/loading tests."""

import subprocess

from typer.testing import CliRunner

from commitgate import config
from commitgate.cli import app
from commitgate.config import (
    DEFAULT_CONFIG,
    DEFAULT_CONFIG_YAML,
    create_default_config,
    load_config,
)


def test_generated_config_loads_to_defaults(tmp_path, monkeypatch):
    # The written file must load back to exactly the runtime defaults (single source of
    # truth: DEFAULT_CONFIG drives both the write and the load).
    monkeypatch.chdir(tmp_path)
    path = create_default_config()
    assert path.read_text(encoding="utf-8") == DEFAULT_CONFIG_YAML
    assert load_config() == DEFAULT_CONFIG


def test_generated_config_advertises_claude_cli(tmp_path, monkeypatch):
    # A new user should see the no-key CLI option in the generated config, not just the docs.
    monkeypatch.chdir(tmp_path)
    text = create_default_config().read_text(encoding="utf-8")
    assert "claude-cli" in text
    assert "agy-cli" in text


def test_init_generates_current_defaults_and_hook(tmp_path, monkeypatch):
    git_init = subprocess.run(
        ["git", "init", "-q"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert git_init.returncode == 0, git_init.stderr

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("commitgate.git_utils.prompt_for_hook_type", lambda: "pre-commit")

    result = CliRunner().invoke(app, ["init"])

    assert result.exit_code == 0, result.output
    assert config.get_config_path().read_text(encoding="utf-8") == DEFAULT_CONFIG_YAML
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    assert "commitgate scan --hook-type pre-commit" in hook.read_text(encoding="utf-8")


def test_antigravity_is_valid_provider(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.get_config_path().write_text("ai:\n  provider: agy-cli\n", encoding="utf-8")
    assert load_config()["ai"]["provider"] == "agy-cli"


def test_kimi_is_valid_provider(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.get_config_path().write_text("ai:\n  provider: kimi\n", encoding="utf-8")
    assert load_config()["ai"]["provider"] == "kimi"

def test_create_default_config_does_not_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.get_config_path().write_text("ai:\n  provider: groq\n", encoding="utf-8")
    create_default_config()                            # must not clobber an existing file
    assert load_config()["ai"]["provider"] == "groq"
