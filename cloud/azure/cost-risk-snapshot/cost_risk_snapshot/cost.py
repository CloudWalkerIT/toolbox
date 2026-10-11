"""Cost Management queries, one set per subscription.

Three ActualCost queries run for each subscription over the same custom
time window: monthly totals, totals by ServiceName, and totals by
ResourceGroupName (top N kept). The request body is passed as a plain dict
in REST shape so it works across azure-mgmt-costmanagement major versions.

Cost Management throttles hard and answers with 429. The query is a POST,
which azure-core's retry policy never retries on 429, and the wait comes in
Cost Management's own x-ms-ratelimit-*-retry-after headers rather than
Retry-After. So throttled queries are retried here.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from datetime import date
from typing import Any

from cost_risk_snapshot.models import (
    CaptureError,
    CostByMonth,
    CostByResourceGroup,
    CostByService,
    Findings,
)

log = logging.getLogger(__name__)

TOP_RESOURCE_GROUPS = 25

_AMOUNT_COLUMNS = ("totalcost", "cost", "pretaxcost")
_DATE_COLUMNS = ("billingmonth", "usagedate")

# Throttling: attempts per query, and the longest single wait in seconds.
MAX_ATTEMPTS = 4
MAX_RETRY_WAIT = 60.0
_RETRY_AFTER_HEADERS = (
    "retry-after",
    "x-ms-ratelimit-microsoft.costmanagement-qpu-retry-after",
    "x-ms-ratelimit-microsoft.costmanagement-entity-retry-after",
    "x-ms-ratelimit-microsoft.costmanagement-tenant-retry-after",
    "x-ms-ratelimit-microsoft.costmanagement-clienttype-retry-after",
)


def build_query(
    start: date,
    end: date,
    granularity: str | None = None,
    group_by: str | None = None,
) -> dict:
    """REST-shaped QueryDefinition body for an ActualCost query."""
    dataset: dict[str, Any] = {
        "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
    }
    if granularity:
        dataset["granularity"] = granularity
    if group_by:
        dataset["grouping"] = [{"type": "Dimension", "name": group_by}]
    return {
        "type": "ActualCost",
        "timeframe": "Custom",
        "timePeriod": {
            "from": f"{start.isoformat()}T00:00:00Z",
            "to": f"{end.isoformat()}T23:59:59Z",
        },
        "dataset": dataset,
    }


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def result_rows(result: Any) -> list[dict]:
    """Turn a QueryResult (columns + positional rows) into a list of dicts
    keyed by lower-cased column name."""
    if result is None:
        return []
    columns = [str(_field(c, "name") or "").lower() for c in (_field(result, "columns") or [])]
    rows = _field(result, "rows") or []
    if _field(result, "next_link"):
        log.warning("cost query returned a next page; only the first page is used")
    return [dict(zip(columns, r, strict=False)) for r in rows]


def _amount(row: dict) -> float:
    for k in _AMOUNT_COLUMNS:
        if row.get(k) is not None:
            return float(row[k])
    return 0.0


def _month(row: dict) -> str:
    for k in _DATE_COLUMNS:
        v = row.get(k)
        if v is None:
            continue
        s = str(v)
        if re.match(r"^\d{8}", s):  # UsageDate as 20260801
            return f"{s[:4]}-{s[4:6]}"
        if re.match(r"^\d{4}-\d{2}", s):  # BillingMonth as 2026-08-01T00:00:00
            return s[:7]
    return ""


def map_monthly(sub: str, rows: list[dict]) -> list[CostByMonth]:
    totals: dict[tuple[str, str], float] = {}
    for r in rows:
        key = (_month(r), r.get("currency") or "")
        totals[key] = totals.get(key, 0.0) + _amount(r)
    return [
        CostByMonth(subscription_id=sub, month=m, cost=round(c, 2), currency=cur)
        for (m, cur), c in sorted(totals.items())
    ]


def map_by_service(sub: str, rows: list[dict]) -> list[CostByService]:
    out = [
        CostByService(
            subscription_id=sub,
            service_name=r.get("servicename") or "(unknown)",
            cost=round(_amount(r), 2),
            currency=r.get("currency") or "",
        )
        for r in rows
    ]
    return sorted(out, key=lambda x: x.cost, reverse=True)


def map_by_resource_group(
    sub: str, rows: list[dict], top: int = TOP_RESOURCE_GROUPS
) -> list[CostByResourceGroup]:
    out = [
        CostByResourceGroup(
            subscription_id=sub,
            resource_group=r.get("resourcegroupname") or "(none)",
            cost=round(_amount(r), 2),
            currency=r.get("currency") or "",
        )
        for r in rows
    ]
    return sorted(out, key=lambda x: x.cost, reverse=True)[:top]


def error_code(e: Exception) -> str | None:
    err = getattr(e, "error", None)
    code = getattr(err, "code", None)
    if code:
        return str(code)
    status = getattr(e, "status_code", None)
    return str(status) if status else None


def retry_after(e: Exception) -> float | None:
    """Longest wait, in seconds, that a throttled response asks for."""
    headers = getattr(getattr(e, "response", None), "headers", None) or {}
    lowered = {str(k).lower(): v for k, v in headers.items()}
    waits = []
    for name in _RETRY_AFTER_HEADERS:
        try:
            waits.append(float(lowered[name]))
        except (KeyError, TypeError, ValueError):
            continue
    return max(waits) if waits else None


def query_with_retry(
    client: Any,
    scope: str,
    body: dict,
    sleep: Callable[[float], None] = time.sleep,
) -> Any:
    """Run one usage query, retrying on 429 up to MAX_ATTEMPTS times."""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return client.query.usage(scope, body)
        except Exception as e:
            if getattr(e, "status_code", None) != 429 or attempt == MAX_ATTEMPTS:
                raise
            wait = retry_after(e)
            if wait is None:
                wait = 5.0 * 2**attempt
            wait = min(max(wait, 1.0), MAX_RETRY_WAIT)
            log.info("cost query for %s throttled; retrying in %.0fs", scope, wait)
            sleep(wait)
    raise AssertionError("unreachable")


def capture_cost_for_subscription(
    client: Any,
    sub: str,
    start: date,
    end: date,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[Findings, list[CaptureError]]:
    """Run the three cost queries for one subscription.

    `client` is a CostManagementClient (or anything with `.query.usage`).
    Each query fails independently into a CaptureError, after retries if
    it was throttled.
    """
    scope = f"/subscriptions/{sub}"
    findings = Findings()
    errors: list[CaptureError] = []

    queries = [
        ("by_month", build_query(start, end, granularity="Monthly")),
        ("by_service", build_query(start, end, group_by="ServiceName")),
        ("by_resource_group", build_query(start, end, group_by="ResourceGroupName")),
    ]
    for name, body in queries:
        try:
            rows = result_rows(query_with_retry(client, scope, body, sleep))
        except Exception as e:  # noqa: BLE001
            log.warning("cost query %s for %s failed: %s", name, sub, e)
            errors.append(
                CaptureError(source=f"cost.{sub}.{name}", message=str(e), code=error_code(e))
            )
            continue
        if name == "by_month":
            findings.cost_by_month = map_monthly(sub, rows)
        elif name == "by_service":
            findings.cost_by_service = map_by_service(sub, rows)
        else:
            findings.cost_by_resource_group = map_by_resource_group(sub, rows)
    return findings, errors
