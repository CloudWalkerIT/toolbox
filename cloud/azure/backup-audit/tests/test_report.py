"""Tests for the report emitters."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from backup_audit.report import ExitCode, classify, write_run


def test_write_run_produces_expected_files(tmp_path: Path, sample_result) -> None:
    code = write_run(sample_result, tmp_path)
    assert code == ExitCode.FINDINGS  # has unprotected VM and a failing item

    assert (tmp_path / "data.json").is_file()
    assert (tmp_path / "vaults_policies.csv").is_file()
    assert (tmp_path / "protected_items.csv").is_file()
    assert (tmp_path / "unprotected.csv").is_file()
    assert (tmp_path / "summary.md").is_file()


def test_data_json_matches_contract(tmp_path: Path, sample_result) -> None:
    write_run(sample_result, tmp_path)
    data = json.loads((tmp_path / "data.json").read_text())
    assert data["schema_version"] == 1
    assert data["tool"] == "azure-backup-audit"
    assert "tool_version" in data
    assert "generated_at" in data
    assert "scope" in data and "subscriptions" in data["scope"]
    assert "findings" in data
    assert "errors" in data
    assert isinstance(data["errors"], list)


def test_vaults_policies_csv_rows(tmp_path: Path, sample_result) -> None:
    write_run(sample_result, tmp_path)
    rows = list(csv.DictReader((tmp_path / "vaults_policies.csv").open()))
    assert len(rows) == 2
    by_name = {r["policy_name"]: r for r in rows}
    assert by_name["daily-30"]["has_protected_items"] == "yes"
    assert by_name["orphan-policy"]["has_protected_items"] == "no"
    assert by_name["daily-30"]["retention_daily"] == "30Days"


def test_protected_items_csv_rows(tmp_path: Path, sample_result) -> None:
    write_run(sample_result, tmp_path)
    rows = list(csv.DictReader((tmp_path / "protected_items.csv").open()))
    assert len(rows) == 3
    names = {r["friendly_name"] for r in rows}
    assert names == {"vm-good", "vm-failing", "vm-warning"}
    failing = next(r for r in rows if r["friendly_name"] == "vm-failing")
    assert failing["last_backup_status"] == "Failed"
    assert failing["last_error_code"] == "UserErrorVmNotInRunningState"


def test_unprotected_csv_rows(tmp_path: Path, sample_result) -> None:
    write_run(sample_result, tmp_path)
    rows = list(csv.DictReader((tmp_path / "unprotected.csv").open()))
    assert len(rows) == 1
    assert rows[0]["name"] == "vm-orphan"
    assert rows[0]["resource_type"] == "VM"


def test_summary_md_contains_key_sections(tmp_path: Path, sample_result) -> None:
    write_run(sample_result, tmp_path)
    md = (tmp_path / "summary.md").read_text()
    assert "# Azure Backup Audit" in md
    assert "## Totals" in md
    assert "Items with failed backups" in md
    assert "Items requiring human review" in md
    assert "vm-failing" in md
    assert "vm-warning" in md
    assert "Policies with no protected items" in md
    assert "orphan-policy" in md
    assert "Unprotected resources" in md


def test_classify_clean(sample_result) -> None:
    # Strip the unprotected resources and keep only the cleanly-completed item.
    sample_result.findings.unprotected.clear()
    sample_result.findings.protected_items = [
        i for i in sample_result.findings.protected_items if i.last_backup_status == "Completed"
    ]
    assert classify(sample_result) == ExitCode.CLEAN


def test_classify_findings_for_bad_item(sample_result) -> None:
    assert classify(sample_result) == ExitCode.FINDINGS


def test_classify_capture_incomplete(sample_result_with_errors) -> None:
    assert classify(sample_result_with_errors) == ExitCode.CAPTURE_INCOMPLETE


def test_classify_findings_for_warn_only(sample_result) -> None:
    # Keep only the CompletedWithWarnings item. Warnings now trigger
    # FINDINGS because they require human review.
    sample_result.findings.unprotected.clear()
    sample_result.findings.protected_items = [
        i for i in sample_result.findings.protected_items if i.friendly_name == "vm-warning"
    ]
    assert classify(sample_result) == ExitCode.FINDINGS


def test_classify_backups_suspended_is_warning_not_bad(sample_result) -> None:
    """BackupsSuspended items should land in the warn bucket: human review
    required (was the pause intentional?) but not a definite failure."""
    from backup_audit.report import _item_is_bad, _item_is_warning

    sample_result.findings.unprotected.clear()
    sample_result.findings.protected_items[0].last_backup_status = "Healthy"
    sample_result.findings.protected_items[0].protection_state = "BackupsSuspended"
    sample_result.findings.protected_items[0].health_status = ""
    item = sample_result.findings.protected_items[0]
    assert _item_is_bad(item) is False
    assert _item_is_warning(item) is True


def test_classify_failed_is_bad_not_warning(sample_result) -> None:
    from backup_audit.report import _item_is_bad, _item_is_warning

    failing = next(
        i for i in sample_result.findings.protected_items if i.friendly_name == "vm-failing"
    )
    assert _item_is_bad(failing) is True
    assert _item_is_warning(failing) is False


def test_classify_action_required_is_bad(sample_result) -> None:
    from backup_audit.report import _item_is_bad

    sample_result.findings.protected_items[0].last_backup_status = "Healthy"
    sample_result.findings.protected_items[0].protection_state = "Protected"
    sample_result.findings.protected_items[0].health_status = "ActionRequired"
    assert _item_is_bad(sample_result.findings.protected_items[0]) is True


def test_classify_action_suggested_is_warning(sample_result) -> None:
    from backup_audit.report import _item_is_bad, _item_is_warning

    sample_result.findings.protected_items[0].last_backup_status = "Healthy"
    sample_result.findings.protected_items[0].protection_state = "Protected"
    sample_result.findings.protected_items[0].health_status = "ActionSuggested"
    item = sample_result.findings.protected_items[0]
    assert _item_is_bad(item) is False
    assert _item_is_warning(item) is True


def test_severity_precedence_bad_beats_warn(sample_result) -> None:
    """An item with both a BAD signal and a WARN signal must classify as
    BAD, not WARN, so it lands in exactly one bucket in the summary."""
    from backup_audit.report import Severity, _item_is_bad, _item_is_warning, severity

    item = sample_result.findings.protected_items[0]
    item.last_backup_status = "Unhealthy"  # BAD
    item.protection_state = "BackupsSuspended"  # WARN
    item.health_status = ""
    assert severity(item) is Severity.BAD
    assert _item_is_bad(item) is True
    assert _item_is_warning(item) is False


def test_severity_buckets_are_disjoint(sample_result, tmp_path) -> None:
    """End-to-end check: after write_run, the bad and warn item counts in
    the summary must sum to no more than the total protected item count."""
    from backup_audit.report import (
        Severity,
        _item_is_bad,
        _item_is_warning,
        severity,
        write_run,
    )

    # Mutate fixture so one item has both bad and warn signals.
    sample_result.findings.protected_items[0].last_backup_status = "Unhealthy"
    sample_result.findings.protected_items[0].protection_state = "BackupsSuspended"

    write_run(sample_result, tmp_path)

    bad = [i for i in sample_result.findings.protected_items if _item_is_bad(i)]
    warn = [i for i in sample_result.findings.protected_items if _item_is_warning(i)]
    clean = [i for i in sample_result.findings.protected_items if severity(i) is Severity.CLEAN]
    overlap = set(id(i) for i in bad) & set(id(i) for i in warn)
    assert not overlap, "items must not appear in both bad and warn buckets"
    assert len(bad) + len(warn) + len(clean) == len(sample_result.findings.protected_items)
