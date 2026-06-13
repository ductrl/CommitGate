import json
import os
from datetime import datetime, timezone

import requests

_HEC_TIMEOUT = 5  # keep the hook fast; logging never blocks a commit


def _sanitize_findings(findings: list) -> list:
    # Drop 'secret' before sending — avoid exfilling raw credential material
    return [{k: v for k, v in f.items() if k != "secret"} for f in findings]


def log_decision(decision: dict) -> None:
    """POST the scan decision to Splunk HEC as an audit event.

    Silently skips when SPLUNK_HEC_TOKEN is not set.
    Never raises — a logging failure must not block a commit.
    """
    token = os.environ.get("SPLUNK_HEC_TOKEN")
    if not token:
        return

    url = os.environ.get(
        "SPLUNK_HEC_URL",
        "http://localhost:8088/services/collector/event",
    )

    findings = _sanitize_findings(decision.get("findings", []))
    payload = {
        "event": {
            "action": decision.get("action"),
            "reason": decision.get("reason"),
            "findings_count": len(findings),
            "findings": findings,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "sourcetype": "commitgate:audit",
    }

    verify_ssl = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() != "false"

    try:
        import urllib3
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        resp = requests.post(
            url,
            headers={"Authorization": f"Splunk {token}"},
            data=json.dumps(payload),
            timeout=_HEC_TIMEOUT,
            verify=verify_ssl,
        )
        resp.raise_for_status()
    except Exception as exc:
        from rich import print as rprint
        rprint(f"[yellow]Splunk audit log failed: {exc}[/yellow]")
