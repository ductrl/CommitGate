from typing import List

SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def decide(
    findings: List[dict],
    warn_threshold: int = 1,
    block_threshold: int = 2,
) -> dict:
    if not findings:
        return {"action": "allow", "findings": [], "reason": "No findings detected."}

    max_sev = max(SEVERITY_RANK.get(f.get("severity", "low"), 0) for f in findings)
    n = len(findings)

    if max_sev >= block_threshold:
        return {
            "action": "block",
            "findings": findings,
            "reason": f"{n} finding(s) at or above block threshold.",
        }
    if max_sev >= warn_threshold:
        return {
            "action": "warn",
            "findings": findings,
            "reason": f"{n} finding(s) at or above warn threshold.",
        }
    return {
        "action": "allow",
        "findings": findings,
        "reason": f"{n} low-severity finding(s), below warn threshold.",
    }
