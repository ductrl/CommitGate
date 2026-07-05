import typer
from rich import print
import os

from commitgate.git_utils import install_git_hook, get_staged_diff, get_staged_files, get_pre_push_changes, PrePushHookError
from commitgate.gitleaks_runner import run_gitleaks_scan
from commitgate.report_generator import format_finding, severity_color, remove_dup
from commitgate.ai_reviewer import review
from commitgate.config import create_default_config, load_config
from commitgate.decision_engine import decide
from commitgate.splunk_logger import log_decision

app = typer.Typer()

@app.command()
def scan(
    hook_type: str = typer.Option(
        "pre-commit",
        "--hook-type",
        help="Git hook type: pre-commit or pre-push",
    ),
    timeout: int = typer.Option(
        20,
        "--timeout",
        "-t",
        help="Maximum time (seconds) allowed for AI review.",
    )
):
    # LOAD CONFIG

    config = load_config()

    if not config["enabled"]:
        print("[yellow]CommitGate disabled in commitgate.yaml[/yellow]")
        raise typer.Exit(0)

    timeout = config["ai"]["timeout"]
    show_suggestions = config["reporting"]["fields"]["suggestions"]
    ai_enabled = config["ai"]["enabled"]

    # HANDLE SKIP
    skip = os.environ.get("SKIP", "")
    if skip == "commitgate":
        print("[yellow]CommitGate skipped via SKIP=commitgate[/yellow]")
        raise typer.Exit(code=0)

    if hook_type == "pre-commit":
        diff, file_paths = get_staged_diff(), get_staged_files()
    elif hook_type == "pre-push":
        try:
            diff, file_paths = get_pre_push_changes()
        except PrePushHookError:
            print(
                "[red]Error: CommitGate pre-push mode must be run from a Git pre-push hook.[/red]\n"
            )
            raise typer.Exit(1)
    else:
        raise ValueError(f"Invalid hook type: {hook_type}")

    # SECURITY SCAN

    gitleaks_findings = run_gitleaks_scan(file_paths=file_paths)

    if ai_enabled:
        ai_findings, ai_review_ok = review(diff=diff, staged_files=file_paths, timeout=timeout)
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

    if hook_type == "pre-push":
        print("[red]Push blocked by CommitGate.[/red]")
    else:
        print("[red]Commit blocked by CommitGate.[/red]")

    raise typer.Exit(code=1)
    
@app.command()
def install_hook():
    hook_path = install_git_hook()

    print(f"Installed {hook_path.name} hook at {hook_path}")

@app.command()
def init():
    config_file = create_default_config()
    hook_path = install_git_hook()

    print(f"[green]Created config file:[/green] {config_file}")
    print(f"[green]Installed {hook_path.name} hook:[/green] {hook_path}")

@app.command()
def version():
    print("CommitGate 0.1.0")

if __name__ == "__main__":
    app()