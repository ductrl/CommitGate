import typer
from rich import print

from commitgate.git_utils import install_pre_commit_hook
from commitgate.gitleaks_runner import run_gitleaks_scan, format_finding
from commitgate.ai_reviewer import review_staged

app = typer.Typer()

@app.command()
def scan(
    timeout: int = typer.Option(
        20,
        "--timeout",
        "-t",
        help="Maximum time (seconds) allowed for AI review.",
    )
):
    # TODO: Move format_finding to report_generator
    # TODO: We can think about adding a configuration files for user next (to set things like timeout)
    # TODO: Maybe also change the finding color based on severity

    gitleaks_findings = run_gitleaks_scan()

    ai_findings, ai_review_ok = review_staged(timeout=timeout)

    all_findings = gitleaks_findings + ai_findings

    # AI review failed
    if not ai_review_ok:
        print("[yellow]AI review failed or returned an unusable response.[/yellow]")
        print("[yellow]Continuing with deterministic checks only.[/yellow]")

    # No secrets and vulnerabilities found
    if not all_findings:
        print("[green]No security findings found![/green]")
        print("[green]CommitGate scan completed![/green]")
        raise typer.Exit(code=0)

    print(f"[red]CommitGate detected {len(all_findings)} security finding(s):[/red]")

    for index, finding in enumerate(all_findings):
        print(f"[yellow]Secret #{index + 1}[/yellow]")
        print(format_finding(finding=finding))
        print()

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