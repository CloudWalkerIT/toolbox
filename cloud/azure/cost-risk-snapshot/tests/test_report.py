"""Tests for the report emitters and exit-code classification."""

from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path

from cost_risk_snapshot.report import (
    CSV_ROW_TYPES,
    ExitCode,
    advisor_savings,
    classify,
    cost_headlines,
    render_summary,
    top_services,
    write_run,
)


def test_write_run_produces_expected_files(tmp_path: Path, concerning_result) -> None:
    code = write_run(concerning_result, tmp_path)
    assert code == ExitCode.FINDINGS
    assert (tmp_path / "data.json").is_file()
    assert (tmp_path / "summary.md").is_file()
    for name in CSV_ROW_TYPES:
        assert (tmp_path / f"{name}.csv").is_file(), name


def test_every_findings_array_has_a_csv(clean_result) -> None:
    assert set(CSV_ROW_TYPES) == set(clean_result.findings.__dataclass_fields__)


def test_data_json_matches_contract(tmp_path: Path, clean_result) -> None:
    write_run(clean_result, tmp_path)
    data = json.loads((tmp_path / "data.json").read_text())
    assert data["schema_version"] == 1
    assert data["tool"] == "azure-cost-risk-snapshot"
    assert data["scope"]["cost_days"] == 90
    assert isinstance(data["errors"], list)
    for name in CSV_ROW_TYPES:
        assert isinstance(data["findings"][name], list)


def test_waste_csv_rows(tmp_path: Path, concerning_result) -> None:
    write_run(concerning_result, tmp_path)
    raw = (tmp_path / "waste.csv").read_bytes()
    assert b"\r\n" not in raw
    rows = list(csv.DictReader((tmp_path / "waste.csv").open()))
    assert len(rows) == 1
    assert rows[0]["category"] == "unattached_disk"
    assert rows[0]["est_monthly_cost"] == ""


def test_cost_headlines_last_month_and_run_rate(clean_result) -> None:
    (h,) = cost_headlines(clean_result, date(2026, 9, 27))
    assert h.currency == "USD"
    assert h.last_full_month == "2026-08"
    assert h.last_full_month_cost == 1200.0
    assert h.month_to_date == 1040.0
    # 1040 over 26 full days, extrapolated to 30 days.
    assert h.run_rate == 1200.0


def test_cost_headline_not_covered_by_short_window(clean_result) -> None:
    clean_result.scope.cost_from = "2026-09-01"
    (h,) = cost_headlines(clean_result, date(2026, 9, 27))
    assert h.last_full_month_cost is None


def test_run_rate_unavailable_on_first_of_month(clean_result) -> None:
    (h,) = cost_headlines(clean_result, date(2026, 10, 1))
    assert h.run_rate is None
    assert h.last_full_month == "2026-09"


def test_top_services_and_savings(clean_result) -> None:
    assert top_services(clean_result)[0] == ("Virtual Machines", "USD", 2000.0)
    assert advisor_savings(clean_result) == {"USD": 1234.5}


def test_summary_headline(concerning_result) -> None:
    md = render_summary(concerning_result)
    assert "# Azure Cost & Risk Snapshot" in md
    assert "Last full month (2026-08): 1,200.00 USD" in md
    assert "Current run-rate (2026-09, month-to-date extrapolated): 1,200.00 USD" in md
    assert "| Virtual Machines | 2,000.00 USD |" in md
    assert "Advisor annual savings (as reported): 1,234.50 USD" in md
    assert "| unattached_disk | 1 |" in md
    assert "| ended | 1 |" in md
    assert "Windows Server 2012 R2 (ended): 1" in md
    assert "High-severity security findings: 1" in md
    assert "Capture errors: 0" in md
    assert "## Capture errors" not in md


def test_summary_lists_errors(errored_result) -> None:
    md = render_summary(errored_result)
    assert "Capture errors: 1" in md
    assert "## Capture errors" in md
    assert "(AuthorizationFailed)" in md


def test_classify_clean(clean_result) -> None:
    assert classify(clean_result) == ExitCode.CLEAN


def test_classify_findings(concerning_result) -> None:
    assert classify(concerning_result) == ExitCode.FINDINGS


def test_classify_errors_win(errored_result) -> None:
    errored_result.findings.waste.clear()
    assert classify(errored_result) == ExitCode.CAPTURE_INCOMPLETE


def test_classify_each_concerning_signal(clean_result) -> None:
    from dataclasses import replace

    f = clean_result.findings

    # A high-impact Advisor recommendation alone is concerning.
    f.advisor[0] = replace(f.advisor[0], impact="High")
    assert classify(clean_result) == ExitCode.FINDINGS
    f.advisor[0] = replace(f.advisor[0], impact="Medium")

    # An end-of-support row ending within 12 months alone is concerning.
    f.end_of_support[0] = replace(f.end_of_support[0], status="ends_within_12_months")
    assert classify(clean_result) == ExitCode.FINDINGS
    f.end_of_support[0] = replace(f.end_of_support[0], status="supported")

    # Medium/low security findings are reported but not concerning.
    assert classify(clean_result) == ExitCode.CLEAN


def test_summary_says_secure_score_unavailable(clean_result) -> None:
    clean_result.findings.secure_scores = []
    text = render_summary(clean_result)
    assert "Secure score: not available" in text
