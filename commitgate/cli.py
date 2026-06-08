import typer
from rich import print

from commitgate.git_utils import install_pre_commit_hook

app = typer.Typer()

@app.command()
def scan():
    # TODO: Implement
    print("[green]CommitGate scanned![/green]")

@app.command()
def install_hook():
    hook_path = install_pre_commit_hook()

    print(f"Installed pre-commit hook at {hook_path}")

@app.command()
def version():
    print("CommitGate 0.1.0")

if __name__ == "__main__":
    app()