"""Tests for the parts of capture.py that don't touch Azure: the
unprotected-derivation logic and the SDK-to-model translation helpers."""

from __future__ import annotations

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


def test_unprotected_file_share() -> None:
    inv = Inventory(
        vaults=[],
        vms=[],
        file_shares=[
            {
                "id": _share_id("sa", "share1"),
                "name": "share1",
                "resourceGroup": "rg",
                "subscriptionId": "s",
                "accessTier": "TransactionOptimized",
                "shareQuota": 100,
                "enabledProtocols": "SMB",
            }
        ],
        sql_vms=[],
    )
    out = _derive_unprotected(inv, items=[], workload_container_vm_ids=set())
    assert len(out) == 1
    assert out[0].resource_type == "FileShare"
    assert "tier=TransactionOptimized" in out[0].detail


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
