"""Tests for report_generator: the field-toggle rendering + min_severity display filter.

Legacy `format_finding(finding)` / `format_finding(finding, include_suggestion=...)` must stay
byte-for-byte the same (cli.py still calls it that way). The new fields-driven mode honors
reporting.fields; severity/file/location are always shown.
"""

from commitgate.report_generator import (
    filter_by_min_severity,
    format_finding,
    remove_dup,
    severity_color,
)

FULL = {
    "source": "AI Review (DeepSeek)",
    "category": "Injection risk",
    "severity": "high",
    "file": "app/db.py",
    "start_line": 4,
    "end_line": 6,
    "description": "os.system on user input",
    "suggestion": "Use subprocess with a list of args.",
}

ALL_ON = {"source": True, "category": True, "description": True, "suggestions": True}


# --- legacy mode (cli.py path) must not change --------------------------------

def test_format_legacy_mode_shows_core_no_suggestion():
    out = format_finding(FULL)   # fields=None, include_suggestion default False
    assert "- Source: AI Review (DeepSeek)" in out
    assert "- Category: Injection risk" in out
    assert "- Severity: high" in out
    assert "- File: app/db.py" in out
    assert "- Location: Line 4 to 6" in out
    assert "- Description: os.system on user input" in out
    assert "Suggestion" not in out


def test_format_legacy_include_suggestion():
    out = format_finding(FULL, include_suggestion=True)
    assert "- Suggestion: Use subprocess with a list of args." in out


# --- fields-driven mode -------------------------------------------------------

def test_format_fields_hide_toggled_off():
    fields = {"source": False, "category": False, "description": True, "suggestions": True}
    out = format_finding(FULL, fields=fields)
    assert "Source:" not in out
    assert "Category:" not in out
    assert "- Description: os.system on user input" in out
    assert "- Suggestion: Use subprocess with a list of args." in out
    # always-on fields survive regardless of toggles
    assert "- Severity: high" in out
    assert "- File: app/db.py" in out
    assert "- Location: Line 4 to 6" in out


def test_format_fields_all_on_shows_everything():
    out = format_finding(FULL, fields=ALL_ON)
    for label in ("Source:", "Category:", "Severity:", "File:", "Location:", "Description:", "Suggestion:"):
        assert label in out


def test_format_fields_hides_absent_field_no_none():
    # gitleaks-style finding has no description/suggestion; description toggle ON but absent.
    gitleaks = {
        "source": "gitleaks", "category": "Secret leak", "severity": "critical",
        "file": "x.py", "start_line": 1, "end_line": 1,
    }
    out = format_finding(gitleaks, fields=ALL_ON)
    assert "None" not in out          # no "Description: None"
    assert "Description:" not in out  # absent -> hidden even though the toggle is on
    assert "Suggestion:" not in out
    assert "- Category: Secret leak" in out


# --- min_severity display filter ----------------------------------------------

def test_filter_min_severity_drops_below():
    findings = [
        {"severity": "low", "file": "a"},
        {"severity": "medium", "file": "b"},
        {"severity": "high", "file": "c"},
    ]
    kept = filter_by_min_severity(findings, min_severity="medium", block_severity="high")
    assert [f["file"] for f in kept] == ["b", "c"]


def test_filter_min_severity_never_hides_blocker():
    # min_severity set ABOVE block_severity -> the blocking finding must still show.
    findings = [{"severity": "high", "file": "blocker"}, {"severity": "low", "file": "noise"}]
    kept = filter_by_min_severity(findings, min_severity="critical", block_severity="high")
    assert [f["file"] for f in kept] == ["blocker"]


def test_filter_min_severity_low_keeps_all():
    findings = [{"severity": "low", "file": "a"}, {"severity": "critical", "file": "b"}]
    kept = filter_by_min_severity(findings, min_severity="low", block_severity="high")
    assert len(kept) == 2


# --- unchanged helpers still behave -------------------------------------------

def test_remove_dup_gitleaks_wins_and_sorts():
    findings = [
        {"file": "a.py", "start_line": 1, "severity": "low", "source": "AI Review (DeepSeek)"},
        {"file": "a.py", "start_line": 1, "severity": "critical", "source": "gitleaks"},
        {"file": "b.py", "start_line": 2, "severity": "medium", "source": "AI Review (DeepSeek)"},
    ]
    result = remove_dup(findings)
    assert len(result) == 2                       # the a.py:1 pair collapsed
    assert result[-1]["source"] == "gitleaks"     # gitleaks kept, sorted last (critical)
    assert [f["severity"] for f in result] == ["medium", "critical"]


def test_severity_color():
    assert severity_color("CRITICAL") == "red"
    assert severity_color("low") == "white"
