from pathlib import Path

from commitgate.git_utils import install_pre_commit_hook

def test_install_pre_commit_hook():
    hook_path = install_pre_commit_hook()

    assert hook_path.exists

    content = hook_path.read_text()

    assert "#!/bin/sh" in content
    assert "commitgate scan" in content