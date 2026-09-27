"""Tests for Windows Server / SQL Server version parsing and lifecycle status."""

from __future__ import annotations

from datetime import date

import pytest
from cost_risk_snapshot.lifecycle import (
    ENDED,
    ENDS_SOON,
    SQL_SERVER,
    SUPPORTED,
    UNKNOWN,
    WINDOWS_SERVER,
    classify,
    derive_end_of_support,
    parse_sql_server,
    parse_windows_image,
    parse_windows_server,
    rows_from_arc_machine,
    rows_from_sql_vm,
    rows_from_vm,
)

TODAY = date(2026, 9, 27)


@pytest.mark.parametrize(
    ("offer", "sku", "expected"),
    [
        ("WindowsServer", "2012-R2-Datacenter", "2012 R2"),
        ("WindowsServer", "2012-r2-datacenter-smalldisk-g2", "2012 R2"),
        ("WindowsServer", "2012-Datacenter", "2012"),
        ("WindowsServer", "2016-Datacenter", "2016"),
        ("WindowsServer", "2016-datacenter-gensecond", "2016"),
        ("WindowsServer", "2008-R2-SP1", "2008 R2"),
        ("WindowsServer", "2022-datacenter-azure-edition", "2022"),
        ("SQL2016SP2-WS2016", "Enterprise", "2016"),
        ("sql2008r2sp3-ws2008r2sp1", "Standard", "2008 R2"),
        ("UbuntuServer", "18.04-LTS", None),
        ("", "", None),
    ],
)
def test_parse_windows_image(offer, sku, expected) -> None:
    assert parse_windows_image(offer, sku) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Windows Server 2012 R2 Datacenter", "2012 R2"),
        ("Microsoft Windows Server 2016 Datacenter", "2016"),
        ("Windows Server 2019 Standard", "2019"),
        ("WS2012R2", "2012 R2"),
        ("Windows 10 Enterprise", None),
        ("windows", None),
        ("Ubuntu 22.04", None),
    ],
)
def test_parse_windows_server_names(text, expected) -> None:
    assert parse_windows_server(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("SQL2016SP2-WS2016", "2016"),
        ("SQL2016SP3-WS2019", "2016"),
        ("SQL2008R2SP3-WS2008R2SP1", "2008 R2"),
        ("SQL2012SP4-WS2012R2", "2012"),
        ("sql2019-ws2022", "2019"),
        ("SQL2017-Ubuntu1604", "2017"),
        ("SQL Server 2014", "2014"),
        ("WindowsServer", None),
        (None, None),
    ],
)
def test_parse_sql_server(text, expected) -> None:
    assert parse_sql_server(text) == expected


def test_classify_ended() -> None:
    end, status, days = classify(WINDOWS_SERVER, "2012 R2", TODAY)
    assert end == "2023-10-10"
    assert status == ENDED
    assert days == (date(2023, 10, 10) - TODAY).days
    assert days < 0


def test_classify_ends_within_12_months() -> None:
    end, status, days = classify(WINDOWS_SERVER, "2016", TODAY)
    assert end == "2027-01-12"
    assert status == ENDS_SOON
    assert days == 107


def test_classify_supported() -> None:
    _, status, days = classify(SQL_SERVER, "2022", TODAY)
    assert status == SUPPORTED
    assert days > 365


def test_classify_boundaries() -> None:
    # Last day of support still counts as supported (0 days remaining).
    assert classify(SQL_SERVER, "2016", date(2026, 7, 14))[1:] == (ENDS_SOON, 0)
    assert classify(SQL_SERVER, "2016", date(2026, 7, 15))[1:] == (ENDED, -1)
    # Exactly 365 days out is within 12 months; 366 is not.
    assert classify(SQL_SERVER, "2017", date(2026, 10, 12))[1] == ENDS_SOON
    assert classify(SQL_SERVER, "2017", date(2026, 10, 11))[1] == SUPPORTED


def test_classify_unknown_version() -> None:
    assert classify(WINDOWS_SERVER, "2003", TODAY) == (None, UNKNOWN, None)


def _vm(**kw) -> dict:
    base = {"id": "/subscriptions/s/rg/vm1", "name": "vm1", "subscriptionId": "s"}
    base.update(kw)
    return base


def test_vm_from_image_reference() -> None:
    rows = rows_from_vm(_vm(offer="WindowsServer", sku="2012-R2-Datacenter"), TODAY, False)
    assert len(rows) == 1
    assert rows[0].kind == "vm"
    assert rows[0].product == WINDOWS_SERVER
    assert rows[0].version == "2012 R2"
    assert rows[0].status == ENDED


def test_vm_falls_back_to_os_name() -> None:
    vm = _vm(offer="", sku="", osName="Windows Server 2016 Datacenter", osVersion="10.0.14393")
    rows = rows_from_vm(vm, TODAY, False)
    assert [(r.version, r.status) for r in rows] == [("2016", ENDS_SOON)]
    assert rows[0].source.startswith("osName")


def test_sql_image_vm_yields_os_and_sql_when_no_sql_vm_resource() -> None:
    rows = rows_from_vm(_vm(offer="SQL2016SP2-WS2016", sku="Enterprise"), TODAY, False)
    assert {(r.product, r.version) for r in rows} == {
        (WINDOWS_SERVER, "2016"),
        (SQL_SERVER, "2016"),
    }


def test_sql_image_vm_skips_sql_when_sql_vm_resource_exists() -> None:
    rows = rows_from_vm(_vm(offer="SQL2016SP2-WS2016", sku="Enterprise"), TODAY, True)
    assert [(r.product, r.version) for r in rows] == [(WINDOWS_SERVER, "2016")]


def test_linux_vm_yields_nothing() -> None:
    assert (
        rows_from_vm(_vm(offer="0001-com-ubuntu-server-jammy", sku="22_04-lts"), TODAY, False) == []
    )


def test_sql_vm_row() -> None:
    rows = rows_from_sql_vm(
        {"id": "x", "name": "sql1", "subscriptionId": "s", "sqlImageOffer": "SQL2016SP2-WS2016"},
        TODAY,
    )
    assert len(rows) == 1
    assert rows[0].kind == "sql_vm"
    assert rows[0].status == ENDED  # SQL 2016 ended 2026-07-14


def test_arc_machine_row() -> None:
    rows = rows_from_arc_machine(
        {
            "id": "x",
            "name": "onprem1",
            "subscriptionId": "s",
            "osName": "windows",
            "osSku": "Windows Server 2012 R2 Standard",
        },
        TODAY,
    )
    assert [(r.kind, r.version, r.status) for r in rows] == [("arc_machine", "2012 R2", ENDED)]


def test_derive_dedupes_sql_between_vm_and_sql_vm() -> None:
    vm_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/sql1"
    vms = [{"id": vm_id, "name": "sql1", "subscriptionId": "s", "offer": "SQL2014SP3-WS2012R2"}]
    sql_vms = [
        {
            "id": "sqlvm",
            "name": "sql1",
            "subscriptionId": "s",
            "sqlImageOffer": "SQL2014SP3-WS2012R2",
            "vmResourceId": vm_id.upper(),
        }
    ]
    rows = derive_end_of_support(vms, sql_vms, [], [], TODAY)
    assert sorted((r.kind, r.product, r.version) for r in rows) == [
        ("sql_vm", SQL_SERVER, "2014"),
        ("vm", WINDOWS_SERVER, "2012 R2"),
    ]
