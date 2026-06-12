from typing import List

SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_color(severity: str) -> str:
    severity = severity.lower()

    if severity == "critical":
        return "red"
    elif severity == "high":
        return "orange1"
    elif severity == "medium":
        return "yellow"
    else:
        return "white"


def format_finding(finding: dict, include_suggestion: bool = False) -> str:
    """
    Parse the finding into a readable rich format so that it can be printed by the CLI.
    """

    output = (
        f"\t- Source: {finding.get('source')}\n"
        f"\t- Category: {finding.get('category')}\n"
        f"\t- Severity: {finding.get('severity')}\n"
        f"\t- File: {finding.get('file')}\n"
        f"\t- Location: Line {finding.get('start_line')} to {finding.get('end_line')}\n"
        f"\t- Description: {finding.get('description')}"
    )

    if include_suggestion and finding.get("suggestion"):
        output += f"\n\t- Suggestion: {finding.get('suggestion')}"

    return output


def remove_dup(findings: List[dict]) -> List[dict]:
    """Remove duplicate findings and sort from lowest to highest severity.

    Two findings are duplicates when they share the same (file, start_line).
    When gitleaks and AI flag the same location, gitleaks wins.
    """
    seen: dict[tuple, dict] = {}
    for finding in findings:
        key = (finding.get("file"), finding.get("start_line"))
        if key not in seen or finding.get("source") == "gitleaks":
            seen[key] = finding

    result = list(seen.values())
    result.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity", "low"), 0))
    return result
