from typing import List, Optional

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


def format_finding(
    finding: dict,
    fields: Optional[dict] = None,
) -> str:
    if fields is None:
        output = (
            f"\t- Source: {finding.get('source')}\n"
            f"\t- Category: {finding.get('category')}\n"
            f"\t- Severity: {finding.get('severity')}\n"
            f"\t- File: {finding.get('file')}\n"
            f"\t- Location: Line {finding.get('start_line')} to {finding.get('end_line')}\n"
            f"\t- Description: {finding.get('description')}"
        )
        return output

    lines: List[str] = []
    if fields.get("source", True) and finding.get("source"):
        lines.append(f"\t- Source: {finding.get('source')}")
    if fields.get("category", True) and finding.get("category"):
        lines.append(f"\t- Category: {finding.get('category')}")
    lines.append(f"\t- Severity: {finding.get('severity')}")
    lines.append(f"\t- File: {finding.get('file')}")
    lines.append(f"\t- Location: Line {finding.get('start_line')} to {finding.get('end_line')}")
    if fields.get("description", True) and finding.get("description"):
        lines.append(f"\t- Description: {finding.get('description')}")
    if fields.get("suggestions", True) and finding.get("suggestion"):
        lines.append(f"\t- Suggestion: {finding.get('suggestion')}")
    return "\n".join(lines)


def filter_by_min_severity(
    findings: List[dict],
    min_severity: str = "low",
    block_severity: str = "high",
) -> List[dict]:
    """
    Drop findings below ``min_severity``
    """
    floor = SEVERITY_RANK.get(str(min_severity or "low").lower(), 0)
    block = SEVERITY_RANK.get(str(block_severity or "high").lower(), 2)
    kept: List[dict] = []
    for finding in findings:
        rank = SEVERITY_RANK.get(str(finding.get("severity", "low")).lower(), 0)
        if rank >= floor or rank >= block:
            kept.append(finding)
    return kept


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
