from typing import List

from commitgate.config import load_config

SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def decide(findings: List[dict]) -> dict:
    if not findings:
        return {"action": "allow", "findings": [], "reason": "No findings detected."}

    config = load_config()
    block_threshold = SEVERITY_RANK.get(config["policy"]["block_severity"], 2)

    max_sev = max(SEVERITY_RANK.get(f.get("severity", "low"), 0) for f in findings)
    n = len(findings)

    if max_sev >= block_threshold:
        return {
            "action": "block",
            "findings": findings,
            "reason": f"{n} finding(s) at or above block threshold.",
        }
    # Any finding below the block threshold warns: commit proceeds, dev still sees it.
    return {
        "action": "warn",
        "findings": findings,
        "reason": f"{n} finding(s) below block threshold.",
    }
