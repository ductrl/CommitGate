import typer
from rich import print

from commitgate.git_utils import install_pre_commit_hook
from commitgate.gitleaks_runner import run_gitleaks_scan
from commitgate.report_generator import format_finding, severity_color, remove_dup
from commitgate.ai_reviewer import review_staged
from commitgate.config import create_default_config, load_config
from commitgate.decision_engine import decide
from commitgate.splunk_logger import log_decision

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

    # LOAD CONFIGS

    config = load_config()

    timeout = config["ai"]["timeout"]
    show_suggestions = config["reporting"]["show_suggestions"]
    ai_enabled = config["ai"]["enabled"]

    # SECURITY SCAN

    gitleaks_findings = run_gitleaks_scan()

    if ai_enabled:
        ai_findings, ai_review_ok = review_staged(timeout=timeout)
    else:
        ai_findings, ai_review_ok = [], True

    all_findings = remove_dup(gitleaks_findings + ai_findings)

    if not ai_review_ok:
        print("[yellow]AI review failed or returned an unusable response.[/yellow]")
        print("[yellow]Continuing with deterministic checks only.[/yellow]")

    # No secrets and vulnerabilities found
    if not all_findings:
        if not ai_enabled:
            print("[yellow]AI review disabled by config.[/yellow]")
        
        print("[green]No security findings found![/green]")
        print("[green]CommitGate scan completed![/green]")
        raise typer.Exit(code=0)

    decision = decide(all_findings)
    log_decision(decision)
    action = decision["action"]

    color = "yellow" if action == "warn" else "red"
    print(f"[{color}]CommitGate detected {len(all_findings)} security finding(s):[/{color}]")

    for index, finding in enumerate(all_findings):
        severity = finding.get("severity", "").lower()
        sev_color = severity_color(severity=severity)

        print(
            f"[{sev_color}]"
            f"[{severity.upper()}] Finding #{index + 1}"
            f"[/{sev_color}]"
        )

        if finding.get("suggestion"):
            finding_output = format_finding(finding=finding, include_suggestion=show_suggestions)
        else:
            finding_output = format_finding(finding=finding)

        print(finding_output)
        print()

    if not ai_enabled:
        print("[yellow]AI review disabled by config.[/yellow]")

    if action == "warn":
        print("[yellow]CommitGate: warnings found. Commit proceeding.[/yellow]")
        raise typer.Exit(code=0)

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