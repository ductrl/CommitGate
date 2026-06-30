"""Tests for gitleaks_runner. Parsing is the high-value target; the binary and
subprocess are never required — missing-file and missing-binary paths are mocked."""

import json

import pytest

from commitgate import gitleaks_runner
from commitgate.gitleaks_runner import parse_gitleaks_findings, run_gitleaks_scan


def test_parse_maps_gitleaks_fields(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps([{
        "Description": "AWS Access Key",
        "StartLine": 3, "EndLine": 3,
        "StartColumn": 5, "EndColumn": 40,
        "File": "config.py",
        "RuleID": "aws-access-key",
    }]), encoding="utf-8")

    findings = parse_gitleaks_findings(report)

    assert len(findings) == 1
    f = findings[0]
    assert f["source"] == "gitleaks"
    assert f["severity"] == "critical"     # gitleaks hits are always treated as critical
    assert f["file"] == "config.py"
    assert f["rule"] == "aws-access-key"
    assert f["start_line"] == 3


def test_parse_empty_report_is_empty_list(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")
    assert parse_gitleaks_findings(report) == []


def test_parse_rejects_non_json_extension(tmp_path):
    bad = tmp_path / "report.txt"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_gitleaks_findings(bad)


def test_run_scan_missing_binary_raises(monkeypatch):
    monkeypatch.setattr(gitleaks_runner, "is_gitleaks_installed", lambda: False)
    with pytest.raises(RuntimeError):
        run_gitleaks_scan(["anything.py"])


def test_run_scan_skips_nonexistent_files(monkeypatch):
    # Binary present, but the path doesn't exist -> skipped, never shells out.
    monkeypatch.setattr(gitleaks_runner, "is_gitleaks_installed", lambda: True)
    assert run_gitleaks_scan(["does/not/exist.py"]) == []
