"""Tests for Cost Management query building and result mapping."""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace

from cost_risk_snapshot.cost import (
    MAX_ATTEMPTS,
    MAX_RETRY_WAIT,
    build_query,
    capture_cost_for_subscription,
    map_by_resource_group,
    map_by_service,
    map_monthly,
    query_with_retry,
    result_rows,
    retry_after,
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


class Throttled(Exception):
    def __init__(self, headers: dict | None = None) -> None:
        super().__init__("(429) Too many requests. Please retry.")
        self.status_code = 429
        self.response = SimpleNamespace(headers=headers or {})


def _throttling_client(failures: int, headers: dict | None = None) -> SimpleNamespace:
    calls = []

    def usage(scope, body):
        calls.append(scope)
        if len(calls) <= failures:
            raise Throttled(headers)
        return _result(["totalCost", "BillingMonth", "Currency"], [[1, "2026-09-01", "USD"]])

    return SimpleNamespace(query=SimpleNamespace(usage=usage), calls=calls)


def test_retry_after_reads_cost_management_headers() -> None:
    e = Throttled(
        {
            "x-ms-ratelimit-microsoft.costmanagement-entity-retry-after": "12",
            "X-MS-RateLimit-Microsoft.CostManagement-QPU-Retry-After": "30",
            "x-ms-ratelimit-microsoft.costmanagement-qpu-remaining": "0",
        }
    )
    assert retry_after(e) == 30.0
    assert retry_after(Throttled()) is None
    assert retry_after(ValueError("no response")) is None


def test_query_retries_throttled_then_succeeds() -> None:
    client = _throttling_client(
        2, {"x-ms-ratelimit-microsoft.costmanagement-entity-retry-after": "7"}
    )
    waits: list[float] = []
    res = query_with_retry(client, "/subscriptions/s1", {}, sleep=waits.append)
    assert res.rows
    assert len(client.calls) == 3
    assert waits == [7.0, 7.0]


def test_query_backs_off_without_header_and_caps_wait() -> None:
    waits: list[float] = []
    query_with_retry(_throttling_client(2), "/subscriptions/s1", {}, sleep=waits.append)
    assert waits == [10.0, 20.0]

    waits.clear()
    client = _throttling_client(1, {"retry-after": "600"})
    query_with_retry(client, "/subscriptions/s1", {}, sleep=waits.append)
    assert waits == [MAX_RETRY_WAIT]


def test_capture_cost_records_error_after_retries_exhausted() -> None:
    client = _throttling_client(100)
    waits: list[float] = []
    findings, errors = capture_cost_for_subscription(
        client, SUB, date(2026, 6, 29), date(2026, 9, 26), sleep=waits.append
    )
    assert len(client.calls) == 3 * MAX_ATTEMPTS
    assert len(waits) == 3 * (MAX_ATTEMPTS - 1)
    assert findings.cost_by_month == []
    assert [(e.source, e.code) for e in errors] == [
        ("cost.s1.by_month", "429"),
        ("cost.s1.by_service", "429"),
        ("cost.s1.by_resource_group", "429"),
    ]
