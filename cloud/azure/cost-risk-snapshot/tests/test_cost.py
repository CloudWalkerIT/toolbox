"""Tests for Cost Management query building and result mapping."""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace

from cost_risk_snapshot.cost import (
    build_query,
    capture_cost_for_subscription,
    map_by_resource_group,
    map_by_service,
    map_monthly,
    result_rows,
)

SUB = "s1"


def _result(columns: list[str], rows: list[list]) -> SimpleNamespace:
    return SimpleNamespace(
        columns=[SimpleNamespace(name=c) for c in columns], rows=rows, next_link=None
    )


def test_build_query_shape() -> None:
    q = build_query(date(2026, 6, 29), date(2026, 9, 26), group_by="ServiceName")
    assert q["type"] == "ActualCost"
    assert q["timeframe"] == "Custom"
    assert q["timePeriod"] == {"from": "2026-06-29T00:00:00Z", "to": "2026-09-26T23:59:59Z"}
    assert q["dataset"]["grouping"] == [{"type": "Dimension", "name": "ServiceName"}]
    assert "granularity" not in q["dataset"]


def test_monthly_mapping_handles_both_date_formats() -> None:
    res = _result(
        ["totalCost", "BillingMonth", "Currency"],
        [[100.123, "2026-07-01T00:00:00", "USD"], [50, "2026-08-01T00:00:00", "USD"]],
    )
    out = map_monthly(SUB, result_rows(res))
    assert [(r.month, r.cost, r.currency) for r in out] == [
        ("2026-07", 100.12, "USD"),
        ("2026-08", 50.0, "USD"),
    ]

    res = _result(["Cost", "UsageDate", "Currency"], [[10, 20260901, "EUR"], [5, 20260902, "EUR"]])
    out = map_monthly(SUB, result_rows(res))
    assert [(r.month, r.cost, r.currency) for r in out] == [("2026-09", 15.0, "EUR")]


def test_service_and_rg_mapping_sorted_and_capped() -> None:
    res = _result(
        ["totalCost", "ServiceName", "Currency"],
        [[5, "Storage", "USD"], [50, "Virtual Machines", "USD"]],
    )
    assert [s.service_name for s in map_by_service(SUB, result_rows(res))] == [
        "Virtual Machines",
        "Storage",
    ]

    rows = [{"totalcost": i, "resourcegroupname": f"rg{i}", "currency": "USD"} for i in range(40)]
    top = map_by_resource_group(SUB, rows)
    assert len(top) == 25
    assert top[0].resource_group == "rg39"


def test_capture_cost_records_errors_per_query() -> None:
    class Denied(Exception):
        def __init__(self) -> None:
            super().__init__("does not have authorization")
            self.error = SimpleNamespace(code="AuthorizationFailed")

    calls = []

    def usage(scope, body):
        calls.append((scope, body))
        if body["dataset"].get("granularity") == "Monthly":
            return _result(["totalCost", "BillingMonth", "Currency"], [[1, "2026-09-01", "USD"]])
        raise Denied()

    client = SimpleNamespace(query=SimpleNamespace(usage=usage))
    findings, errors = capture_cost_for_subscription(
        client, SUB, date(2026, 6, 29), date(2026, 9, 26)
    )
    assert len(calls) == 3
    assert calls[0][0] == "/subscriptions/s1"
    assert len(findings.cost_by_month) == 1
    assert findings.cost_by_service == []
    assert [(e.source, e.code) for e in errors] == [
        ("cost.s1.by_service", "AuthorizationFailed"),
        ("cost.s1.by_resource_group", "AuthorizationFailed"),
    ]
