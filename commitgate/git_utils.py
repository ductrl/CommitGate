import subprocess

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