"""Config generation/loading tests."""
from commitgate import config
from commitgate.config import DEFAULT_CONFIG, create_default_config, load_config


def test_generated_config_loads_to_defaults(tmp_path, monkeypatch):
    # The written file must load back to exactly the runtime defaults (single source of
    # truth: DEFAULT_CONFIG drives both the write and the load).
    monkeypatch.chdir(tmp_path)
    create_default_config()
    assert load_config() == DEFAULT_CONFIG


def test_generated_config_advertises_claude_cli(tmp_path, monkeypatch):
    # A new user should see the no-key CLI option in the generated config, not just the docs.
    monkeypatch.chdir(tmp_path)
    text = create_default_config().read_text(encoding="utf-8")
    assert "claude-cli" in text


def test_kimi_is_valid_provider(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.get_config_path().write_text("ai:\n  provider: kimi\n", encoding="utf-8")
    assert load_config()["ai"]["provider"] == "kimi"

def test_create_default_config_does_not_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.get_config_path().write_text("ai:\n  provider: groq\n", encoding="utf-8")
    create_default_config()                            # must not clobber an existing file
    assert load_config()["ai"]["provider"] == "groq"
