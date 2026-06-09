import typer
from rich import print

from commitgate.git_utils import install_pre_commit_hook
from commitgate.gitleaks_runner import run_gitleaks_scan, format_finding

app = typer.Typer()

@app.command()
def scan():
    # TODO: Implement
    gitleaks_findings = run_gitleaks_scan()

    if not gitleaks_findings:
        print("[green]No Gitleaks leaked secrets found.[/green]")
        print("[green]CommitGate scan completed![/green]")
        raise typer.Exit(code=0)

    print(f"[red]Gitleaks detected {len(gitleaks_findings)} secret(s):[/red]")

    for index, finding in enumerate(gitleaks_findings):
        print(f"[yellow]Secret #{index + 1}[/yellow]")
        print(format_finding(finding=finding))

    print("[red]Commit blocked by CommitGate.[/red]")
    raise typer.Exit(code=1)
    
@app.command()
def install_hook():
    hook_path = install_pre_commit_hook()

    print(f"Installed pre-commit hook at {hook_path}")

@app.command()
def version():
    print("CommitGate 0.1.0")

if __name__ == "__main__":
    app()