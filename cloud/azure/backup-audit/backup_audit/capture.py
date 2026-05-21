"""Inventory and per-vault capture against Azure.

The capture has two phases:

1. Inventory via Azure Resource Graph. One ARG query each for vaults, VMs,
   storage file shares, and SQL-on-VM resources, scoped to the subscriptions
   the credential covers. ARG transparently handles cross-subscription
   queries within a tenant.

2. Per-vault detail via the recovery services backup management SDK. For
   each vault we list backup policies, protected items, and workload
   containers (needed to map SQL DB items back to their host VM).

Per-vault calls fan out across a thread pool. Errors are captured and
surfaced as CaptureError entries rather than aborting the whole run, so a
single RBAC-denied vault doesn't suppress the rest of the report.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from backup_audit.config import CredentialSpec
from backup_audit.models import (
    CaptureError,
    Findings,
    Policy,
    ProtectedItem,
    Unprotected,
    Vault,
)

log = logging.getLogger(__name__)

# How many vaults to query in parallel per credential. Conservative default;
# Azure RP throttling kicks in well above this.
VAULT_FANOUT = 8


# --------------------------------------------------------------------------
# Resource Graph queries
# --------------------------------------------------------------------------

ARG_VAULTS = """
resources
| where type =~ 'microsoft.recoveryservices/vaults'
| project id, name, resourceGroup, subscriptionId, location
"""

ARG_VMS = """
resources
| where type =~ 'microsoft.compute/virtualmachines'
| project id, name, resourceGroup, subscriptionId, location,
          vmSize = tostring(properties.hardwareProfile.vmSize)
"""

ARG_FILE_SHARES = """
resources
| where type =~ 'microsoft.storage/storageaccounts/fileservices/shares'
| project id, name, resourceGroup, subscriptionId,
          accessTier = tostring(properties.accessTier),
          shareQuota = toint(properties.shareQuota),
          enabledProtocols = tostring(properties.enabledProtocols)
"""

ARG_SQL_VMS = """
resources
| where type =~ 'microsoft.sqlvirtualmachine/sqlvirtualmachines'
| project id, name, resourceGroup, subscriptionId, location,
          vmResourceId = tostring(properties.virtualMachineResourceId)
"""


@dataclass
class Inventory:
    vaults: list[dict]
    vms: list[dict]
    file_shares: list[dict]
    sql_vms: list[dict]


def list_subscriptions(credential: Any) -> list[str]:
    """Return all subscription IDs visible to the credential."""
    from azure.mgmt.subscription import SubscriptionClient

    client = SubscriptionClient(credential)
    return [s.subscription_id for s in client.subscriptions.list() if s.subscription_id]


def query_arg(credential: Any, subscriptions: list[str], kql: str) -> list[dict]:
    """Run a single ARG query, paginating through all results."""
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    client = ResourceGraphClient(credential)
    rows: list[dict] = []
    skip_token: str | None = None
    while True:
        options = QueryRequestOptions(top=1000, skip_token=skip_token)
        req = QueryRequest(subscriptions=subscriptions, query=kql, options=options)
        resp = client.resources(req)
        # resp.data is typed loosely by the SDK; in practice with the default
        # objectArray result format it is a list of dicts.
        data = resp.data
        if isinstance(data, list):
            rows.extend(d for d in data if isinstance(d, dict))
        skip_token = getattr(resp, "skip_token", None)
        if not skip_token:
            break
    return rows


def capture_inventory(
    credential: Any,
    subscriptions: list[str],
    errors: list[CaptureError],
) -> Inventory:
    """Run the four inventory queries, capturing any per-query failure."""
    inv = Inventory(vaults=[], vms=[], file_shares=[], sql_vms=[])

    def safe(query_name: str, kql: str) -> list[dict]:
        try:
            return query_arg(credential, subscriptions, kql)
        except Exception as e:  # noqa: BLE001
            log.warning("ARG query %s failed: %s", query_name, e)
            errors.append(CaptureError(source=f"arg.{query_name}", message=str(e)))
            return []

    inv.vaults = safe("vaults", ARG_VAULTS)
    inv.vms = safe("vms", ARG_VMS)
    inv.file_shares = safe("file_shares", ARG_FILE_SHARES)
    inv.sql_vms = safe("sql_vms", ARG_SQL_VMS)
    return inv


# --------------------------------------------------------------------------
# Per-vault detail
# --------------------------------------------------------------------------


@dataclass
class VaultDetail:
    vault: dict
    policies: list[Any]
    items: list[Any]
    workload_containers: list[Any]
    error: CaptureError | None = None


def _backup_client(credential: Any, subscription_id: str) -> Any:
    # Current SDK exposes the client at the top level. Some intermediate
    # releases split things under an activestamp/ submodule; the fallback
    # handles that layout if anyone is pinned to one of those versions.
    try:
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
    except ImportError:
        from azure.mgmt.recoveryservicesbackup.activestamp import (  # type: ignore[no-redef]
            RecoveryServicesBackupClient,
        )

    return RecoveryServicesBackupClient(credential, subscription_id)


def fetch_vault_detail(credential: Any, vault: dict) -> VaultDetail:
    """Fetch policies, protected items, and workload containers for one vault.

    Returns VaultDetail with `error` populated when any sub-call fails. The
    individual lists may be partially populated on failure.
    """
    detail = VaultDetail(vault=vault, policies=[], items=[], workload_containers=[])
    sub_id = vault["subscriptionId"]
    rg = vault["resourceGroup"]
    name = vault["name"]

    try:
        client = _backup_client(credential, sub_id)
    except Exception as e:  # noqa: BLE001
        detail.error = CaptureError(source=f"vault.{name}.client", message=str(e))
        return detail

    try:
        detail.policies = list(client.backup_policies.list(name, rg))
    except Exception as e:  # noqa: BLE001
        detail.error = CaptureError(source=f"vault.{name}.policies", message=str(e))

    try:
        detail.items = list(client.backup_protected_items.list(name, rg))
    except Exception as e:  # noqa: BLE001
        detail.error = CaptureError(source=f"vault.{name}.items", message=str(e))

    # Workload containers are filtered for AzureWorkload (SQL on VM, SAP HANA
    # etc.). Used to map SQL DB items back to their host VM.
    try:
        detail.workload_containers = list(
            client.backup_protection_containers.list(
                name, rg, filter="backupManagementType eq 'AzureWorkload'"
            )
        )
    except Exception as e:  # noqa: BLE001
        detail.error = CaptureError(source=f"vault.{name}.workload_containers", message=str(e))

    return detail


def fetch_all_vault_details(
    credential: Any,
    vaults: list[dict],
    errors: list[CaptureError],
) -> list[VaultDetail]:
    """Fan out vault detail fetches across a thread pool."""
    details: list[VaultDetail] = []
    if not vaults:
        return details

    with ThreadPoolExecutor(max_workers=VAULT_FANOUT) as pool:
        futures = {pool.submit(fetch_vault_detail, credential, v): v for v in vaults}
        for fut in as_completed(futures):
            d = fut.result()
            if d.error:
                errors.append(d.error)
            details.append(d)
    return details


# --------------------------------------------------------------------------
# Capture -> model translation
# --------------------------------------------------------------------------


def _retention_summary(retention_policy: Any) -> dict[str, str]:
    """Reduce a backup retention policy to a small dict of schedule -> duration."""
    out: dict[str, str] = {}
    if retention_policy is None:
        return out
    for key in ("daily_schedule", "weekly_schedule", "monthly_schedule", "yearly_schedule"):
        sched = getattr(retention_policy, key, None)
        if sched is None:
            continue
        rd = getattr(sched, "retention_duration", None)
        if rd is None:
            continue
        count = getattr(rd, "count", "")
        unit = getattr(rd, "duration_type", "")
        out[key] = f"{count}{unit}"
    return out


def _policy_from_sdk(p: Any, vault: dict) -> Policy:
    props = getattr(p, "properties", None)
    sched = getattr(props, "schedule_policy", None) if props else None
    retn = getattr(props, "retention_policy", None) if props else None

    times = []
    raw_times = getattr(sched, "schedule_run_times", None) if sched else None
    if raw_times:
        times = [t.isoformat() if hasattr(t, "isoformat") else str(t) for t in raw_times]

    days = []
    raw_days = getattr(sched, "schedule_run_days", None) if sched else None
    if raw_days:
        days = [str(d) for d in raw_days]

    return Policy(
        vault=vault["name"],
        resource_group=vault["resourceGroup"],
        subscription_id=vault["subscriptionId"],
        name=p.name,
        backup_management_type=getattr(props, "backup_management_type", "") or "",
        workload_type=getattr(props, "workload_type", "") or "",
        policy_type=getattr(props, "policy_type", "") or "",
        schedule_frequency=getattr(sched, "schedule_run_frequency", "") or "" if sched else "",
        schedule_times=times,
        schedule_days=days,
        retention=_retention_summary(retn),
        instant_restore_days=getattr(props, "instant_rp_retention_range_in_days", None),
        timezone=getattr(props, "time_zone", None),
        sub_policies=[],  # SQL workload sub-policies are out of scope for v0.1
    )


def _short_policy_name(policy_id: str | None) -> str:
    if not policy_id:
        return ""
    return policy_id.rstrip("/").rsplit("/", 1)[-1]


def _item_from_sdk(it: Any, vault: dict) -> ProtectedItem:
    props = getattr(it, "properties", None)
    err = getattr(props, "last_backup_error_detail", None) if props else None

    return ProtectedItem(
        vault=vault["name"],
        resource_group=vault["resourceGroup"],
        subscription_id=vault["subscriptionId"],
        workload_type=getattr(props, "workload_type", "") or "",
        backup_management_type=getattr(props, "backup_management_type", "") or "",
        item_name=it.name,
        friendly_name=getattr(props, "friendly_name", None) or it.name,
        container_name=getattr(props, "container_name", "") or "",
        source_resource_id=(
            getattr(props, "source_resource_id", None)
            or getattr(props, "virtual_machine_id", "")
            or ""
        ),
        policy=_short_policy_name(getattr(props, "policy_id", None)),
        last_backup_time=str(getattr(props, "last_backup_time", "") or ""),
        last_backup_status=getattr(props, "last_backup_status", None),
        protection_state=getattr(props, "protection_state", None)
        or getattr(props, "protection_status", None),
        health_status=getattr(props, "health_status", None),
        last_error_code=getattr(err, "code", None) if err else None,
        last_error_message=getattr(err, "message", None) if err else None,
    )


# --------------------------------------------------------------------------
# Unprotected resource derivation
# --------------------------------------------------------------------------


def _derive_unprotected(
    inv: Inventory,
    items: list[ProtectedItem],
    workload_container_vm_ids: set[str],
) -> list[Unprotected]:
    """Compute resources that exist in inventory but aren't covered by a
    protected item."""
    protected_vm: set[str] = set()
    protected_share: set[str] = set()
    sql_workload_vm: set[str] = set()

    for it in items:
        src = it.source_resource_id.lower()
        if not src:
            continue
        bmt = it.backup_management_type
        wt = it.workload_type or ""
        if bmt == "AzureIaasVM":
            protected_vm.add(src)
        elif bmt == "AzureStorage" and "FileShare" in wt:
            protected_share.add(src)
        elif bmt == "AzureWorkload" and "SQL" in wt:
            # Source on a SQL DB item is sometimes the DB and sometimes the
            # VM. The reliable mapping is via the workload container ->
            # VM resource id, which we precomputed.
            sql_workload_vm.add(src)

    out: list[Unprotected] = []

    for vm in inv.vms:
        vmid = vm["id"].lower()
        if vmid in protected_vm:
            continue
        out.append(
            Unprotected(
                resource_type="VM",
                name=vm["name"],
                resource_group=vm["resourceGroup"],
                subscription_id=vm["subscriptionId"],
                location=vm["location"],
                detail=f"vmSize={vm.get('vmSize', '')}",
                reason="no IaaS protected item references this VM",
            )
        )

    for fs in inv.file_shares:
        fsid = fs["id"].lower()
        if fsid in protected_share:
            continue
        out.append(
            Unprotected(
                resource_type="FileShare",
                name=fs["name"],
                resource_group=fs["resourceGroup"],
                subscription_id=fs["subscriptionId"],
                location="",
                detail=(
                    f"tier={fs.get('accessTier', '')}; "
                    f"quotaGiB={fs.get('shareQuota', '')}; "
                    f"proto={fs.get('enabledProtocols', '')}"
                ),
                reason="no AzureFileShare protected item references this share",
            )
        )

    for svm in inv.sql_vms:
        vmid = (svm.get("vmResourceId") or "").lower()
        if not vmid:
            continue
        sql_ok = vmid in sql_workload_vm
        if sql_ok:
            continue
        iaas_ok = vmid in protected_vm
        registered = vmid in workload_container_vm_ids
        flags = [
            "iaas-vm-backed-up" if iaas_ok else "iaas-vm-NOT-backed-up",
            "sql-workload-registered-no-protected-db"
            if registered
            else "sql-workload-not-registered",
        ]
        out.append(
            Unprotected(
                resource_type="SQLOnVM",
                name=svm["name"],
                resource_group=svm["resourceGroup"],
                subscription_id=svm["subscriptionId"],
                location=svm["location"],
                detail="; ".join(flags),
                reason="no AzureWorkload SQL protected item for any DB on this VM",
            )
        )

    return out


# --------------------------------------------------------------------------
# Top-level capture for one credential
# --------------------------------------------------------------------------


def capture_for_credential(
    spec: CredentialSpec,
) -> tuple[Findings, list[CaptureError], list[str]]:
    """Capture findings against everything the given credential can see.

    Returns (findings, errors, subscriptions_actually_used).
    """
    from backup_audit.auth import build_credential

    errors: list[CaptureError] = []
    credential = build_credential(spec)

    subs = spec.subscriptions
    if not subs:
        try:
            subs = list_subscriptions(credential)
        except Exception as e:  # noqa: BLE001
            errors.append(
                CaptureError(
                    source=f"credential.{spec.name}.list_subscriptions",
                    message=str(e),
                )
            )
            return Findings(), errors, []

    inv = capture_inventory(credential, subs, errors)
    details = fetch_all_vault_details(credential, inv.vaults, errors)

    findings = Findings()
    findings.vaults = [
        Vault(
            name=v["name"],
            resource_group=v["resourceGroup"],
            subscription_id=v["subscriptionId"],
            location=v["location"],
        )
        for v in inv.vaults
    ]

    policy_use: dict[tuple[str, str], bool] = {}
    workload_container_vm_ids: set[str] = set()

    for d in details:
        for p in d.policies:
            findings.policies.append(_policy_from_sdk(p, d.vault))
        for it in d.items:
            pi = _item_from_sdk(it, d.vault)
            findings.protected_items.append(pi)
            if pi.policy:
                policy_use[(pi.vault, pi.policy)] = True
        for c in d.workload_containers:
            src = getattr(getattr(c, "properties", None), "source_resource_id", None)
            if src:
                workload_container_vm_ids.add(src.lower())

    for p in findings.policies:
        p.has_protected_items = policy_use.get((p.vault, p.name), False)

    findings.unprotected = _derive_unprotected(
        inv, findings.protected_items, workload_container_vm_ids
    )

    return findings, errors, subs
