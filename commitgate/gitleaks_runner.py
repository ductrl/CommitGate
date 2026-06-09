import shutil
import subprocess
from pathlib import Path
import tempfile
import json

from commitgate.git_utils import get_staged_files

def is_gitleaks_installed() -> bool:
    """
    Check whether the `gitleaks` command is available on the system.

    Returns:
        True if Gitleaks is installed, False otherwise.
    """

    return shutil.which("gitleaks") is not None

def parse_gitleaks_findings(report_path: str | Path) -> list[dict]:
    """
    Parse a Gitleaks JSON report into CommitGate findings.

    Args:
        report_path: Path to a Gitleaks JSON report file.

    Returns:
        List of CommitGate findings - a dictionary that includes description, start_line, end_line, start_column, end_column, and file.

    Raises:
        FileNotFoundError: If the report file does not exist.
        ValueError: If the report file is empty or contains invalid JSON.
    """

    report_path = Path(report_path)

    if not report_path.exists():
        raise FileNotFoundError(f"Gitleaks file report not found: {report_path}")
    
    if not report_path.is_file():
        raise ValueError(f"Expected a file but received: {report_path}")
    
    if report_path.suffix.lower() != ".json":
        raise ValueError(f"Expected a .json report file, got: {report_path}")
    
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            # getting the Gitleaks report output as a Python dict
            raw_findings = json.load(f) 
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in Gitleaks report: {report_path}") from e
    
    if not isinstance(raw_findings, list):
        raise ValueError("Expected Gitleaks report to contain a list of findings.")
    
    findings = []

    for item in raw_findings:
        findings.append(
            {
                "description": item.get("Description"),
                "start_line": item.get("StartLine"),
                "end_line": item.get("EndLine"),
                "start_column": item.get("StartColumn"),
                "end_column": item.get("EndColumn"),
                "file": item.get("File"),
                "rule": item.get("RuleID")
            }
        )
    
    return findings

def format_finding(finding: dict) -> str:
    """
    Parse the finding into a readable rich format so that it can be printed by the CLI.
    """

    return (
        f"\t- File: {finding.get('file')}\n" \
        f"\t- Location: From line {finding.get('start_line')} to {finding.get('end_line')}\n" \
        f"\t- Rule: {finding.get('rule')}\n" \
        f"\t- Description: {finding.get('description')}"
    )

def run_gitleaks_scan() -> list[dict]:
    """
    Scan staged files with Gitleaks.

    Returns:
        List of CommitGate findings - a dictionary that includes description, start_line, end_line, start_column, end_column, and file.
    """

    if not is_gitleaks_installed():
        raise RuntimeError("Gitleaks is not installed. Please install it before running CommitGate")

    staged_files = get_staged_files()

    findings = []

    for file_path in staged_files:
        path = Path(file_path)

        # if path doesn't exist for path is not a file then we'll skip it
        if not path.exists() or not path.is_file():
            continue

        # for each file to be scanned, we create a temporary JSON report file for gitleaks
        # and then parse that result
        with tempfile.NamedTemporaryFile(mode="w+t", suffix=".json", delete=True) as report_file:
            report_path = report_file.name
        
            command = [
                "gitleaks",
                "dir",
                file_path,
                "--report-format",
                "json",
                "--no-banner",
                "--redact",
                "--report-path",
                report_path
            ]

            result = subprocess.run(
                command, 
                capture_output=True,
                text=True
            )

            """
            According to Gitleaks' repo, the exitcodes are:
                0 - no leaks present
                1 - leaks or error encountered
                126 - unknown flag
            """

            if result.returncode == 126:
                raise RuntimeError(f"Gitleaks failed while scanning {file_path}:\n{result.stderr}")

            if result.returncode not in (0, 1):
                raise RuntimeError(f"Gitleaks failed while scanning {file_path}:\n{result.stderr}")
            
            findings.extend(parse_gitleaks_findings(report_path=report_path))
    
    return findings