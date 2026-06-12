def severity_color(severity: str):
    severity = severity.lower()

    if severity in ("critical", "high"):
        return "red"
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