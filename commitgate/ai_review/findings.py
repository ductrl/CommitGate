"""Parse, validate, and deterministically locate AI security findings."""

from __future__ import annotations

import json
import re
from typing import List, Optional, Tuple

VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# Characters an LLM may emit that Windows cp1252 cannot encode — map to ASCII equivalents.
_UNICODE_SANITIZE = str.maketrans({
    "‑": "-",   # non-breaking hyphen
    "–": "-",   # en dash
    "—": "-",   # em dash
    "‘": "'",   # left single quote
    "’": "'",   # right single quote
    "“": '"',   # left double quote
    "”": '"',   # right double quote
    "…": "...", # ellipsis
})


def _sanitize(s: str) -> str:
    return s.translate(_UNICODE_SANITIZE)

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_REDACTED_SECRET_VALUES = {"redacted", "[redacted]", "<redacted>", "***", "none", "null"}


def _diff_path(header: str) -> Optional[str]:
    """Extract a staged path from a git ``+++`` header, or None when unsafe to parse."""
    value = header[4:].strip()
    if not value or value == "/dev/null":
        return None
    if value.startswith('"'):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return None
    else:
        value = value.split("\t", 1)[0]
    return value[2:] if value.startswith("b/") else value


def _added_lines_by_file(diff: str) -> dict[str, List[Tuple[int, str]]]:
    """Map each file to its added ``(new-file line, text)`` entries in a unified diff."""
    added: dict[str, List[Tuple[int, str]]] = {}
    current_file: Optional[str] = None
    new_line: Optional[int] = None

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current_file = None
            new_line = None
            continue
        if line.startswith("+++ "):
            current_file = _diff_path(line)
            new_line = None
            continue
        hunk = _HUNK_HEADER.match(line)
        if hunk:
            new_line = int(hunk.group(1))
            continue
        if current_file is None or new_line is None:
            continue
        if line.startswith("+"):
            added.setdefault(current_file, []).append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-") or line.startswith("\\ No newline at end of file"):
            continue
        else:
            new_line += 1
    return added


def _secret_needles(value: object) -> set[str]:
    secret = str(value or "").strip()
    if len(secret) < 6 or secret.lower() in _REDACTED_SECRET_VALUES:
        return set()
    needles = {secret}
    if len(secret) >= 2 and secret[0] == secret[-1] and secret[0] in "'\"`":
        unquoted = secret[1:-1].strip()
        if len(unquoted) >= 6:
            needles.add(unquoted)
    return needles


def _normalize_secret_locations(findings: List[dict], diff: str) -> List[dict]:
    """Correct AI secret locations only when its evidence has one exact added-line match.

    Ambiguous, absent, redacted, or non-matching evidence leaves the model location unchanged.
    That conservative fallback may leave a duplicate, but never deletes a distinct finding.
    """
    added = _added_lines_by_file(diff)
    for finding in findings:
        needles = _secret_needles(finding.get("secret"))
        if not needles:
            continue
        matches = {
            line_no
            for line_no, text in added.get(str(finding.get("file", "")), [])
            if any(needle in text for needle in needles)
        }
        if len(matches) == 1:
            line_no = matches.pop()
            finding["start_line"] = line_no
            finding["end_line"] = line_no
    return findings


def _extract_json(raw: str):
    """Best-effort JSON recovery from a model response. Returns parsed data or None.

    Tolerates code fences and surrounding prose by grabbing the outermost array/object.
    """
    if not raw:
        return None
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for open_c, close_c in (("[", "]"), ("{", "}")):
        start, end = text.find(open_c), text.rfind(close_c)
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                continue
    return None


def _as_int(value) -> Optional[int]:
    """Coerce a model-supplied line number to int, or None. `bool` is rejected
    (it's an int subclass and `True`/`False` are never valid line numbers)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _salvage_objects(text: str) -> list:
    """Pull complete JSON objects out of a possibly-truncated array.

    Used when the response was cut off (e.g. hit max_tokens) and normal parsing failed:
    instead of losing everything, we recover the findings that fully arrived and stop at
    the incomplete trailing one. Uses the json decoder itself, so strings/escapes/nested
    braces are handled correctly.
    """
    start = text.find("[")
    if start == -1:
        return []
    decoder = json.JSONDecoder()
    objects: list = []
    idx, n = start + 1, len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n,":   # skip whitespace + commas
            idx += 1
        if idx >= n or text[idx] == "]":
            break
        try:
            obj, idx = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            break   # truncated/incomplete trailing object — stop, keep what we have
        objects.append(obj)
    return objects


def parse_findings(
    raw: str,
    staged_files: List[str],
    provider_label: Optional[str] = None,
    diff: Optional[str] = None,
) -> Tuple[List[dict], bool]:
    """Turn a raw model response into validated finding dicts plus a parse-ok flag.

    `provider_label` names the model that produced the findings (e.g. "DeepSeek"); when
    given it is shown in each finding's source as `AI Review (DeepSeek)`.

    Returns `(findings, parse_ok)`. `parse_ok` answers "did we get a usable response?" —
    True whenever the JSON parsed, *including* a clean empty `[]` or a response whose
    findings were all dropped as hallucinated; False only when nothing parseable could be
    recovered. This lets the caller tell a clean review (`[], True`) from a blind one
    (`[], False`) and warn accordingly. Never raises. Output matches `gitleaks_runner`'s
    dict keys so `decision_engine` sees one shape from both scanners (see module docstring).
    Drops hallucinated entries whose `file` is not in the staged set. When `diff` is
    provided, secret findings with one exact evidence match on an added line have their
    model-generated location corrected before cross-scanner deduplication.
    """
    data = _extract_json(raw)
    if isinstance(data, dict):
        items = data.get("findings", [])
        parse_ok = True
    elif isinstance(data, list):
        items = data
        parse_ok = True
    else:
        items = _salvage_objects(raw)   # response likely truncated — recover what completed
        parse_ok = bool(items)          # salvaged something = partial success; nothing = unparseable

    source = f"AI Review ({provider_label})" if provider_label else "AI Review"
    staged = set(staged_files)
    findings: List[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        file = item.get("file")
        if not file or file not in staged:   # drop hallucinated / non-staged findings
            continue
        severity = str(item.get("severity", "medium")).lower()
        if severity not in VALID_SEVERITIES:
            severity = "medium"

        # core keys — always present, mirroring gitleaks_runner's dict
        finding: dict = {
            "source": source,
            "rule": _sanitize(str(item.get("rule") or item.get("category") or "ai-finding")),
            "severity": severity,
            "file": file,
            "start_line": _as_int(item.get("start_line")),
            "end_line": _as_int(item.get("end_line")),
            "description": _sanitize(str(item.get("description", ""))),
        }

        # AI-only extras — included only when the model actually supplied them
        secret = item.get("secret")
        if secret:
            finding["secret"] = _sanitize(str(secret))
        category = item.get("category")
        if category:
            finding["category"] = _sanitize(str(category).replace("-", " ").capitalize())
        suggestion = item.get("suggestion")
        if suggestion:
            finding["suggestion"] = _sanitize(str(suggestion))

        findings.append(finding)
    if diff:
        _normalize_secret_locations(findings, diff)
    return findings, parse_ok
