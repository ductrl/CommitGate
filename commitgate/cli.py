import typer
from rich import print

from commitgate.git_utils import install_pre_commit_hook
from commitgate.gitleaks_runner import run_gitleaks_scan
from commitgate.report_generator import format_finding, severity_color, remove_dup
from commitgate.ai_reviewer import review_staged
from commitgate.config import create_default_config, load_config

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
    # TODO: Add a skip option to commit without having CommitGate scan it

    # Load configs from commitgate.yaml

    config = load_config()

    timeout = config["ai"]["timeout"]
    show_suggestions = config["reporting"]["show_suggestions"]

    gitleaks_findings = run_gitleaks_scan()

    ai_findings, ai_review_ok = review_staged(timeout=timeout)

    all_findings = remove_dup(gitleaks_findings + ai_findings)

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
        # Formatting color based on severity
        severity = finding.get("severity", "").lower()
        color = severity_color(severity=severity)

        # Printing finding

        print(
            f"[{color}]"
            f"[{severity.upper()}] Finding #{index + 1}"
            f"[/{color}]"
        )
        finding_output: str
        
        if finding.get("suggestion"):
            finding_output = format_finding(finding=finding, include_suggestion=show_suggestions)
        else:
            finding_output = format_finding(finding=finding)

        print(finding_output)
        print()

    print("[red]Commit blocked by CommitGate.[/red]")
    raise typer.Exit(code=1)
    
@app.command()
def install_hook():
    hook_path = install_pre_commit_hook()

    print(f"Installed pre-commit hook at {hook_path}")

@app.command()
def init():
    config_file = create_default_config()
    hook_path = install_pre_commit_hook()

    print(f"[green]Created config file:[/green] {config_file}")
    print(f"[green]Installed pre-commit hook:[/green] {hook_path}")

@app.command()
def version():
    print("CommitGate 0.1.0")

if __name__ == "__main__":
    app()