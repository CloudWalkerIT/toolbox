"""Tests for the ARG row mappers and per-credential capture error handling.
No Azure calls: query_arg and credential construction are patched."""

from __future__ import annotations

from datetime import date

import pytest
from cost_risk_snapshot import capture
from cost_risk_snapshot.capture import (
    map_advisor,
    map_inventory,
    map_key_vaults,
    map_nsg_rules,
    map_secure_scores,
    map_sql_servers,
    map_storage,
    map_waste,
    port_covers,
)
from cost_risk_snapshot.config import CredentialSpec
from cost_risk_snapshot.models import Findings

SUB = "s1"


def test_map_inventory_sorts_by_count() -> None:
    rows = [
        {"subscriptionId": SUB, "type": "Microsoft.Network/publicIPAddresses", "resourceCount": 2},
        {"subscriptionId": SUB, "type": "microsoft.compute/disks", "resourceCount": 9},
    ]
    out = map_inventory(rows)
    assert [(r.resource_type, r.count) for r in out] == [
        ("microsoft.compute/disks", 9),
        ("microsoft.network/publicipaddresses", 2),
    ]


def test_map_waste_row() -> None:
    rows = [
        {
            "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/disks/d1",
            "name": "d1",
            "subscriptionId": SUB,
            "resourceGroup": "rg",
            "location": "eastus",
            "sku": "Premium_LRS 128GiB",
        },
        {
            "id": "nic",
            "name": "nic1",
            "subscriptionId": SUB,
            "resourceGroup": "rg",
            "location": "eastus",
            "sku": "",
        },
    ]
    out = map_waste("unattached_disk", "not attached", rows)
    assert out[0].category == "unattached_disk"
    assert out[0].sku == "Premium_LRS 128GiB"
    assert out[0].reason == "not attached"
    assert out[0].est_monthly_cost is None
    assert out[1].sku is None


def test_every_waste_category_has_query_and_reason() -> None:
    assert set(capture.ARG_WASTE) == {
        "unattached_disk",
        "unattached_public_ip",
        "deallocated_vm",
        "stopped_vm",
        "orphaned_nic",
        "old_snapshot",
        "empty_app_service_plan",
        "empty_load_balancer",
    }
    for kql, reason in capture.ARG_WASTE.values():
        assert "resources" in kql and reason


def test_map_advisor_with_and_without_savings() -> None:
    rows = [
        {
            "subscriptionId": SUB,
            "category": "Cost",
            "impact": "High",
            "problem": "Buy reserved instances",
            "solution": "Buy reserved instances",
            "impactedResourceId": "/subscriptions/s1",
            "annualSavingsAmount": "4200.5",
            "savingsCurrency": "USD",
        },
        {
            "subscriptionId": SUB,
            "category": "Security",
            "impact": "Medium",
            "problem": "Enable MFA",
            "solution": "Enable MFA",
            "impactedResourceId": "/subscriptions/s1",
            "annualSavingsAmount": None,
            "savingsCurrency": "",
        },
    ]
    out = map_advisor(rows)
    assert out[0].problem == "Buy reserved instances"
    assert out[0].solution == ""  # identical to problem, so dropped
    assert out[0].annual_savings == 4200.5
    assert out[0].savings_currency == "USD"
    assert out[1].annual_savings is None
    assert out[1].savings_currency is None


@pytest.mark.parametrize(
    ("spec", "port", "expected"),
    [
        ("22", 22, True),
        ("3389", 22, False),
        ("20-30", 22, True),
        ("3000-3400", 3389, True),
        ("*", 3389, True),
        ("443", 22, False),
        ("bogus", 22, False),
    ],
)
def test_port_covers(spec, port, expected) -> None:
    assert port_covers(spec, port) is expected


def _rule(**kw) -> dict:
    base = {
        "id": "/subscriptions/s1/resourceGroups/rg/providers/"
        "Microsoft.Network/networkSecurityGroups/nsg1",
        "name": "nsg1",
        "subscriptionId": SUB,
        "ruleName": "r1",
        "sourceAddressPrefix": "",
        "sourceAddressPrefixes": [],
        "destinationPortRange": "",
        "destinationPortRanges": [],
    }
    base.update(kw)
    return base


def test_nsg_rdp_from_internet() -> None:
    out = map_nsg_rules([_rule(sourceAddressPrefix="Internet", destinationPortRange="3389")])
    assert [(f.check, f.severity) for f in out] == [("nsg_internet_rdp", "high")]
    assert "Internet" in out[0].detail


def test_nsg_ssh_via_prefix_list_and_range() -> None:
    out = map_nsg_rules(
        [_rule(sourceAddressPrefixes=["10.0.0.0/8", "0.0.0.0/0"], destinationPortRanges=["20-25"])]
    )
    assert [f.check for f in out] == ["nsg_internet_ssh"]


def test_nsg_range_covering_both_mgmt_ports() -> None:
    out = map_nsg_rules([_rule(sourceAddressPrefix="*", destinationPortRange="1-4000")])
    assert sorted(f.check for f in out) == ["nsg_internet_rdp", "nsg_internet_ssh"]


def test_nsg_all_ports_reported_once() -> None:
    out = map_nsg_rules([_rule(sourceAddressPrefix="*", destinationPortRange="*")])
    assert [f.check for f in out] == ["nsg_internet_all_ports"]


def test_nsg_ignores_private_sources_and_other_ports() -> None:
    rows = [
        _rule(sourceAddressPrefix="VirtualNetwork", destinationPortRange="3389"),
        _rule(sourceAddressPrefix="Internet", destinationPortRange="443"),
    ]
    assert map_nsg_rules(rows) == []


def test_storage_checks() -> None:
    rows = [
        {
            "id": "sa-bad",
            "name": "sabad",
            "subscriptionId": SUB,
            "allowBlobPublicAccess": True,
            "minimumTlsVersion": "TLS1_0",
            "allowSharedKeyAccess": None,
        },
        {
            "id": "sa-good",
            "name": "sagood",
            "subscriptionId": SUB,
            "allowBlobPublicAccess": False,
            "minimumTlsVersion": "TLS1_2",
            "allowSharedKeyAccess": False,
        },
    ]
    out = map_storage(rows)
    assert {(f.name, f.check, f.severity) for f in out} == {
        ("sabad", "storage_public_blob_access", "medium"),
        ("sabad", "storage_min_tls_below_1_2", "medium"),
        ("sabad", "storage_shared_key_access", "low"),
    }


def test_sql_server_public_access() -> None:
    rows = [
        {"id": "a", "name": "a", "subscriptionId": SUB, "publicNetworkAccess": "Enabled"},
        {"id": "b", "name": "b", "subscriptionId": SUB, "publicNetworkAccess": "Disabled"},
        {"id": "c", "name": "c", "subscriptionId": SUB, "publicNetworkAccess": ""},
    ]
    assert sorted(f.name for f in map_sql_servers(rows)) == ["a", "c"]


def test_key_vault_purge_protection() -> None:
    rows = [
        {"id": "a", "name": "a", "subscriptionId": SUB, "enablePurgeProtection": None},
        {"id": "b", "name": "b", "subscriptionId": SUB, "enablePurgeProtection": True},
    ]
    out = map_key_vaults(rows)
    assert [(f.name, f.check) for f in out] == [("a", "keyvault_no_purge_protection")]


def test_secure_scores() -> None:
    out = map_secure_scores(
        [{"subscriptionId": SUB, "current": 31.2, "max": 52, "percentage": 0.6}]
    )
    assert out[0].percentage == 0.6
    assert out[0].max == 52.0


def test_cost_window_ends_yesterday() -> None:
    assert capture.cost_window(90, date(2026, 9, 27)) == (date(2026, 6, 29), date(2026, 9, 26))


def test_failed_queries_become_capture_errors(monkeypatch) -> None:
    """One failing ARG query is recorded and the rest of the capture continues."""
    monkeypatch.setattr("cost_risk_snapshot.auth.build_credential", lambda spec: object())

    def fake_query(credential, subs, kql):
        if "microsoft.keyvault/vaults" in kql:
            raise RuntimeError("AuthorizationFailed: no access")
        if "microsoft.compute/disks" in kql:
            return [
                {
                    "id": "d1",
                    "name": "d1",
                    "subscriptionId": SUB,
                    "resourceGroup": "rg",
                    "location": "eastus",
                    "sku": "Standard_LRS 32GiB",
                }
            ]
        return []

    monkeypatch.setattr(capture, "query_arg", fake_query)
    monkeypatch.setattr(capture, "_capture_cost", lambda *a, **k: None)

    spec = CredentialSpec(name="default", subscriptions=[SUB])
    findings, errors, subs = capture.capture_for_credential(spec, 90, date(2026, 9, 27))
    assert subs == [SUB]
    assert [e.source for e in errors] == ["arg.security.key_vaults"]
    assert [w.name for w in findings.waste] == ["d1"]


def test_no_visible_subscriptions_is_an_error(monkeypatch) -> None:
    monkeypatch.setattr("cost_risk_snapshot.auth.build_credential", lambda spec: object())
    monkeypatch.setattr(capture, "list_subscriptions", lambda cred: [])
    findings, errors, subs = capture.capture_for_credential(
        CredentialSpec(name="default"), 90, date(2026, 9, 27)
    )
    assert subs == []
    assert findings == Findings()
    assert errors and "no subscriptions" in errors[0].message


def test_map_advisor_keeps_distinct_solution() -> None:
    rows = [
        {
            "subscriptionId": SUB,
            "category": "HighAvailability",
            "impact": "High",
            "problem": "No Service Health alert",
            "solution": "Create an Azure Service Health alert",
            "impactedResourceId": "/subscriptions/s1",
        }
    ]
    out = map_advisor(rows)
    assert out[0].solution == "Create an Azure Service Health alert"
