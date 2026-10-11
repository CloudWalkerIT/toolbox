"""Tests for the parts of capture.py that don't touch Azure: the
unprotected-derivation logic and the SDK-to-model translation helpers."""

from __future__ import annotations

from types import SimpleNamespace

from backup_audit import capture
from backup_audit.capture import Inventory, _derive_unprotected, _short_policy_name
from backup_audit.models import ProtectedItem

SUB = "s"
RG = "rg"


def _vm_id(name: str) -> str:
    return (
        f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
        f"Microsoft.Compute/virtualMachines/{name}"
    )


def _sql_vm_id(name: str) -> str:
    return (
        f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
        f"Microsoft.SqlVirtualMachine/sqlVirtualMachines/{name}"
    )


def _share_id(account: str, share: str) -> str:
    return (
        f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
        f"Microsoft.Storage/storageAccounts/{account}"
        f"/fileServices/default/shares/{share}"
    )


def _item(
    bmt: str,
    wt: str,
    src: str,
    name: str = "x",
) -> ProtectedItem:
    return ProtectedItem(
        vault="rsv",
        resource_group="rg",
        subscription_id="sub",
        workload_type=wt,
        backup_management_type=bmt,
        item_name=name,
        friendly_name=name,
        container_name="c",
        source_resource_id=src,
        policy=None,
        last_backup_time=None,
        last_backup_status=None,
        protection_state=None,
        health_status=None,
        last_error_code=None,
        last_error_message=None,
    )


def test_short_policy_name_strips_resource_id() -> None:
    pid = (
        "/subscriptions/x/resourceGroups/rg/providers/"
        "Microsoft.RecoveryServices/vaults/v/backupPolicies/daily-30"
    )
    assert _short_policy_name(pid) == "daily-30"


def test_short_policy_name_empty() -> None:
    assert _short_policy_name(None) == ""
    assert _short_policy_name("") == ""


def test_unprotected_vm_is_flagged_when_no_item() -> None:
    inv = Inventory(
        vaults=[],
        vms=[
            {
                "id": _vm_id("vm-orphan"),
                "name": "vm-orphan",
                "resourceGroup": "rg",
                "subscriptionId": "s",
                "location": "eastus",
                "vmSize": "Standard_B2s",
            }
        ],
        file_shares=[],
        sql_vms=[],
    )
    out = _derive_unprotected(inv, items=[], workload_container_vm_ids=set())
    assert len(out) == 1
    assert out[0].name == "vm-orphan"
    assert out[0].resource_type == "VM"


def test_protected_vm_is_excluded() -> None:
    src = _vm_id("vm-good")
    inv = Inventory(
        vaults=[],
        vms=[
            {
                "id": src,
                "name": "vm-good",
                "resourceGroup": "rg",
                "subscriptionId": "s",
                "location": "eastus",
                "vmSize": "Standard_B2s",
            }
        ],
        file_shares=[],
        sql_vms=[],
    )
    items = [_item("AzureIaasVM", "VM", src)]
    out = _derive_unprotected(inv, items=items, workload_container_vm_ids=set())
    assert out == []


def _account_id(account: str) -> str:
    return (
        f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
        f"Microsoft.Storage/storageAccounts/{account}"
    )


def _share_row(account: str, share: str) -> dict:
    return {
        "id": _share_id(account, share),
        "name": share,
        "resourceGroup": "rg",
        "subscriptionId": "s",
        "location": "eastus",
        "storageAccountId": _account_id(account),
        "accessTier": "TransactionOptimized",
        "shareQuota": 100,
        "enabledProtocols": "SMB",
    }


def test_unprotected_file_share() -> None:
    inv = Inventory(vaults=[], vms=[], file_shares=[_share_row("sa", "share1")], sql_vms=[])
    out = _derive_unprotected(inv, items=[], workload_container_vm_ids=set())
    assert len(out) == 1
    assert out[0].resource_type == "FileShare"
    assert out[0].name == "sa/share1"
    assert out[0].location == "eastus"
    assert "tier=TransactionOptimized" in out[0].detail


def test_protected_file_share_matched_by_account_and_name() -> None:
    """Azure reports a file share item's source as the storage account and
    its friendly name as the share name. Shares with the same name in other
    accounts, and other shares in the same account, stay unprotected."""
    inv = Inventory(
        vaults=[],
        vms=[],
        file_shares=[
            _share_row("sa", "Share1"),
            _share_row("sa", "share2"),
            _share_row("other", "share1"),
        ],
        sql_vms=[],
    )
    items = [_item("AzureStorage", "AzureFileShare", _account_id("SA"), name="share1")]
    out = _derive_unprotected(inv, items=items, workload_container_vm_ids=set())
    assert sorted(u.name for u in out) == ["other/share1", "sa/share2"]


def test_protected_file_share_with_share_id_source() -> None:
    inv = Inventory(vaults=[], vms=[], file_shares=[_share_row("sa", "share1")], sql_vms=[])
    items = [_item("AzureStorage", "AzureFileShare", _share_id("sa", "share1"), name="ignored")]
    assert _derive_unprotected(inv, items=items, workload_container_vm_ids=set()) == []


def test_list_all_file_shares_maps_rows_and_records_failures(monkeypatch) -> None:
    def fake_client(credential, subscription_id):
        def list_shares(rg, account):
            if account == "denied":
                raise RuntimeError("AuthorizationFailed")
            return [
                SimpleNamespace(
                    id=_share_id(account, "share1"),
                    name="share1",
                    access_tier="Hot",
                    share_quota=5120,
                    enabled_protocols=None,
                )
            ]

        return SimpleNamespace(file_shares=SimpleNamespace(list=list_shares))

    monkeypatch.setattr(capture, "_storage_client", fake_client)
    accounts = [
        {
            "id": _account_id(a),
            "name": a,
            "resourceGroup": RG,
            "subscriptionId": SUB,
            "location": "eastus",
        }
        for a in ("sa", "denied")
    ]
    errors: list = []
    shares = capture.list_all_file_shares(object(), accounts, errors)
    assert shares == [
        {
            "id": _share_id("sa", "share1"),
            "name": "share1",
            "resourceGroup": RG,
            "subscriptionId": SUB,
            "location": "eastus",
            "storageAccountId": _account_id("sa"),
            "accessTier": "Hot",
            "shareQuota": 5120,
            "enabledProtocols": "",
        }
    ]
    assert [e.source for e in errors] == ["storage.denied.file_shares"]


def _sql_vm_inventory_row(name: str, vmid: str) -> dict:
    return {
        "id": _sql_vm_id(name),
        "name": name,
        "resourceGroup": "rg",
        "subscriptionId": "s",
        "location": "eastus",
        "vmResourceId": vmid,
    }


def test_sql_on_vm_flagged_when_no_workload_backup() -> None:
    vmid = _vm_id("sqlhost")
    inv = Inventory(
        vaults=[],
        vms=[],
        file_shares=[],
        sql_vms=[_sql_vm_inventory_row("sqlhost", vmid)],
    )
    out = _derive_unprotected(inv, items=[], workload_container_vm_ids=set())
    assert len(out) == 1
    assert out[0].resource_type == "SQLOnVM"
    assert "iaas-vm-NOT-backed-up" in out[0].detail
    assert "sql-workload-not-registered" in out[0].detail


def test_sql_on_vm_with_iaas_backup_but_no_workload_backup() -> None:
    vmid = _vm_id("sqlhost")
    inv = Inventory(
        vaults=[],
        vms=[],
        file_shares=[],
        sql_vms=[_sql_vm_inventory_row("sqlhost", vmid)],
    )
    items = [_item("AzureIaasVM", "VM", vmid)]
    out = _derive_unprotected(inv, items=items, workload_container_vm_ids={vmid.lower()})
    assert len(out) == 1
    assert "iaas-vm-backed-up" in out[0].detail
    assert "sql-workload-registered-no-protected-db" in out[0].detail


def test_sql_on_vm_excluded_when_sql_workload_backed_up() -> None:
    vmid = _vm_id("sqlhost")
    inv = Inventory(
        vaults=[],
        vms=[],
        file_shares=[],
        sql_vms=[_sql_vm_inventory_row("sqlhost", vmid)],
    )
    items = [_item("AzureWorkload", "SQLDataBase", vmid)]
    out = _derive_unprotected(inv, items=items, workload_container_vm_ids={vmid.lower()})
    assert out == []


def test_policy_use_keyed_by_full_vault_identity() -> None:
    """Vaults with the same name in different subscriptions must not mark
    each other's policies as used."""
    from backup_audit.capture import _mark_policy_use
    from backup_audit.models import Policy

    def policy(sub: str) -> Policy:
        return Policy(
            vault="rsv",
            resource_group="rg",
            subscription_id=sub,
            name="daily",
            backup_management_type="AzureIaasVM",
            workload_type="VM",
            policy_type="V2",
            schedule_frequency="Daily",
            schedule_times=[],
            schedule_days=[],
            retention={},
            instant_restore_days=None,
            timezone=None,
            sub_policies=[],
        )

    used, unused = policy("SUB"), policy("other-sub")
    item = _item("AzureIaasVM", "VM", _vm_id("vm1"))
    item.policy = "daily"
    _mark_policy_use([used, unused], [item])
    assert used.has_protected_items is True
    assert unused.has_protected_items is False


VAULT = {"name": "rsv1", "resourceGroup": "rg", "subscriptionId": "sub-a", "location": "eastus"}


class _AzureError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(f"({code}) denied")
        self.error = SimpleNamespace(code=code)


def test_fetch_vault_detail_keeps_every_error_with_codes(monkeypatch) -> None:
    def denied(*a, **k):
        raise _AzureError("AuthorizationFailed")

    client = SimpleNamespace(
        backup_policies=SimpleNamespace(list=denied),
        backup_protected_items=SimpleNamespace(list=denied),
        backup_protection_containers=SimpleNamespace(list=lambda *a, **k: []),
    )
    monkeypatch.setattr(capture, "_backup_client", lambda cred, sub: client)
    d = capture.fetch_vault_detail(object(), VAULT)
    assert [(e.source, e.code) for e in d.errors] == [
        ("vault.rsv1.policies", "AuthorizationFailed"),
        ("vault.rsv1.items", "AuthorizationFailed"),
    ]
    assert d.items_unreadable is True


def test_fetch_all_vault_details_survives_a_crashing_vault(monkeypatch) -> None:
    def fetch(credential, vault):
        if vault["name"] == "bad":
            raise KeyError("resourceGroup")
        return capture.VaultDetail(vault=vault, policies=[], items=[], workload_containers=[])

    monkeypatch.setattr(capture, "fetch_vault_detail", fetch)
    errors: list = []
    details = capture.fetch_all_vault_details(object(), [VAULT, {"name": "bad"}], errors)
    assert len(details) == 2
    assert [e.source for e in errors] == ["vault.bad"]
    assert [d.items_unreadable for d in details if d.vault["name"] == "bad"] == [True]


def test_unprotected_rows_marked_unverified_when_vault_unreadable() -> None:
    from backup_audit.models import UNVERIFIED_MARKER, Unprotected

    def row(sub: str) -> Unprotected:
        return Unprotected("VM", "vm", "rg", sub, "eastus", "", "no IaaS protected item")

    rows = [row("SUB-A"), row("sub-b")]
    unreadable = capture.VaultDetail(
        vault=VAULT, policies=[], items=[], workload_containers=[], items_unreadable=True
    )
    capture._mark_unverified(rows, [unreadable])
    assert rows[0].reason == f"no IaaS protected item; {UNVERIFIED_MARKER} vault rsv1"
    assert rows[1].reason == "no IaaS protected item"


def test_item_last_backup_time_is_iso_8601() -> None:
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from backup_audit.capture import _item_from_sdk

    props = SimpleNamespace(last_backup_time=datetime(2026, 5, 21, 12, 5, 13, tzinfo=UTC))
    vault = {"name": "rsv", "resourceGroup": "rg", "subscriptionId": "s"}
    item = _item_from_sdk(SimpleNamespace(name="vm1", properties=props), vault)
    assert item.last_backup_time == "2026-05-21T12:05:13+00:00"

    item = _item_from_sdk(SimpleNamespace(name="vm1", properties=SimpleNamespace()), vault)
    assert item.last_backup_time == ""
