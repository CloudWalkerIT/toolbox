"""Windows Server and SQL Server end-of-support detection.

Versions are parsed from whatever the resource exposes: marketplace image
offer/sku on VMs, the SQL IaaS extension's image offer, or the OS name that
the guest agent or Arc agent reports. The dates below are the end of
extended support. Paid or Azure-included Extended Security Updates (ESUs)
can cover a workload past these dates; this tool does not check ESU
enrolment.
"""

from __future__ import annotations

import re
from datetime import date

from cost_risk_snapshot.models import EndOfSupport

WINDOWS_SERVER = "Windows Server"
SQL_SERVER = "SQL Server"

# End of extended support, per the Microsoft lifecycle pages (dates are the
# last supported day, Pacific time). Cross-checked against endoflife.date.
#   https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2
#   https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2012-r2
#   https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2016
#   https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2019
#   https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2022
#   https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025
#   https://learn.microsoft.com/en-us/lifecycle/products/microsoft-sql-server-2008-r2
#   https://learn.microsoft.com/en-us/lifecycle/products/microsoft-sql-server-2012
#   https://learn.microsoft.com/en-us/lifecycle/products/sql-server-2014
#   https://learn.microsoft.com/en-us/lifecycle/products/sql-server-2016
#   https://learn.microsoft.com/en-us/lifecycle/products/sql-server-2017
#   https://learn.microsoft.com/en-us/lifecycle/products/sql-server-2019
#   https://learn.microsoft.com/en-us/lifecycle/products/sql-server-2022
LIFECYCLE: dict[tuple[str, str], date] = {
    (WINDOWS_SERVER, "2008"): date(2020, 1, 14),
    (WINDOWS_SERVER, "2008 R2"): date(2020, 1, 14),
    (WINDOWS_SERVER, "2012"): date(2023, 10, 10),
    (WINDOWS_SERVER, "2012 R2"): date(2023, 10, 10),
    (WINDOWS_SERVER, "2016"): date(2027, 1, 12),
    (WINDOWS_SERVER, "2019"): date(2029, 1, 9),
    (WINDOWS_SERVER, "2022"): date(2031, 10, 14),
    (WINDOWS_SERVER, "2025"): date(2034, 11, 14),
    (SQL_SERVER, "2008"): date(2019, 7, 9),
    (SQL_SERVER, "2008 R2"): date(2019, 7, 9),
    (SQL_SERVER, "2012"): date(2022, 7, 12),
    (SQL_SERVER, "2014"): date(2024, 7, 9),
    (SQL_SERVER, "2016"): date(2026, 7, 14),
    (SQL_SERVER, "2017"): date(2027, 10, 12),
    (SQL_SERVER, "2019"): date(2030, 1, 8),
    (SQL_SERVER, "2022"): date(2033, 1, 11),
}

# Status thresholds.
ENDED = "ended"
ENDS_SOON = "ends_within_12_months"
SUPPORTED = "supported"
UNKNOWN = "unknown"
SOON_DAYS = 365

# "Windows Server 2012 R2 Datacenter", "WS2012R2", "SQL2016SP2-WS2016"
_WS_RE = re.compile(r"(?:windows\s*server|(?<![a-z])ws)[\s_-]*(\d{4})(?:[\s_-]*(r2))?", re.I)
# Marketplace WindowsServer image skus: "2012-R2-Datacenter", "2016-Datacenter-gensecond"
_WS_SKU_RE = re.compile(r"^\s*(\d{4})(?:[\s_-]*(r2))?", re.I)
# "SQL2016SP2-WS2016", "SQL2008R2SP3-WS2008R2", "SQL Server 2014"
_SQL_RE = re.compile(r"sql[\s_-]*(?:server[\s_-]*)?(\d{4})(?:[\s_-]*(r2))?", re.I)


def _version(year: str, r2: str | None) -> str:
    return f"{year} R2" if r2 else year


def parse_windows_server(*texts: str | None) -> str | None:
    """Return a Windows Server version ("2012 R2", "2016") from free text
    such as an OS name, Arc osSku, or SQL image offer."""
    for t in texts:
        if not t:
            continue
        m = _WS_RE.search(t)
        if m:
            return _version(m.group(1), m.group(2))
    return None


def parse_windows_image(offer: str | None, sku: str | None) -> str | None:
    """Return a Windows Server version from a marketplace image reference.

    Only the WindowsServer offer encodes the version in the sku; other
    offers (SQL images, etc.) are parsed from the offer text.
    """
    if (offer or "").lower().startswith("windowsserver") and sku:
        m = _WS_SKU_RE.match(sku)
        if m:
            return _version(m.group(1), m.group(2))
    return parse_windows_server(offer)


def parse_sql_server(*texts: str | None) -> str | None:
    """Return a SQL Server version ("2016", "2008 R2") from an image offer
    like "SQL2016SP2-WS2016" or a string like "SQL Server 2014"."""
    for t in texts:
        if not t:
            continue
        m = _SQL_RE.search(t)
        if m:
            return _version(m.group(1), m.group(2))
    return None


def classify(product: str, version: str, today: date) -> tuple[str | None, str, int | None]:
    """Return (end_of_support_iso, status, days_remaining) for a version."""
    end = LIFECYCLE.get((product, version))
    if end is None:
        return None, UNKNOWN, None
    days = (end - today).days
    if days < 0:
        status = ENDED
    elif days <= SOON_DAYS:
        status = ENDS_SOON
    else:
        status = SUPPORTED
    return end.isoformat(), status, days


def _row(
    resource: dict, kind: str, product: str, version: str, source: str, today: date
) -> EndOfSupport:
    end, status, days = classify(product, version, today)
    return EndOfSupport(
        resource_id=resource.get("id", ""),
        name=resource.get("name", ""),
        subscription_id=resource.get("subscriptionId", ""),
        kind=kind,
        product=product,
        version=version,
        end_of_support=end,
        status=status,
        days_remaining=days,
        source=source,
    )


def rows_from_vm(vm: dict, today: date, has_sql_vm_resource: bool) -> list[EndOfSupport]:
    """End-of-support rows for one ARG VM row.

    Windows Server comes from the image reference, falling back to the
    guest-reported OS name (covers custom and migrated images). SQL Server
    comes from the image offer only when no SqlVirtualMachine resource
    exists for the VM, to avoid counting it twice.
    """
    out: list[EndOfSupport] = []
    offer, sku, os_name = vm.get("offer"), vm.get("sku"), vm.get("osName")

    ws = parse_windows_image(offer, sku)
    source = f"imageReference {offer}/{sku}"
    if not ws:
        ws = parse_windows_server(os_name)
        source = f"osName {os_name}"
    if ws:
        out.append(_row(vm, "vm", WINDOWS_SERVER, ws, source, today))

    if not has_sql_vm_resource:
        sql = parse_sql_server(offer)
        if sql:
            out.append(_row(vm, "vm", SQL_SERVER, sql, f"imageReference {offer}", today))
    return out


def rows_from_sql_vm(svm: dict, today: date) -> list[EndOfSupport]:
    offer = svm.get("sqlImageOffer")
    sql = parse_sql_server(offer)
    if not sql:
        return []
    return [_row(svm, "sql_vm", SQL_SERVER, sql, f"sqlImageOffer {offer}", today)]


def rows_from_arc_machine(m: dict, today: date) -> list[EndOfSupport]:
    ws = parse_windows_server(m.get("osSku"), m.get("osName"))
    if not ws:
        return []
    source = f"osSku {m.get('osSku') or m.get('osName')}"
    return [_row(m, "arc_machine", WINDOWS_SERVER, ws, source, today)]


def rows_from_arc_sql(inst: dict, today: date) -> list[EndOfSupport]:
    sql = parse_sql_server(inst.get("version"))
    if not sql:
        return []
    return [
        _row(inst, "arc_sql_instance", SQL_SERVER, sql, f"version {inst.get('version')}", today)
    ]


def derive_end_of_support(
    vms: list[dict],
    sql_vms: list[dict],
    arc_machines: list[dict],
    arc_sql: list[dict],
    today: date,
) -> list[EndOfSupport]:
    sql_vm_hosts = {(s.get("vmResourceId") or "").lower() for s in sql_vms}
    out: list[EndOfSupport] = []
    for vm in vms:
        out.extend(rows_from_vm(vm, today, (vm.get("id") or "").lower() in sql_vm_hosts))
    for s in sql_vms:
        out.extend(rows_from_sql_vm(s, today))
    for m in arc_machines:
        out.extend(rows_from_arc_machine(m, today))
    for inst in arc_sql:
        out.extend(rows_from_arc_sql(inst, today))
    return out
