"""Capture against Azure for one credential.

Everything except cost comes from Azure Resource Graph, which handles
cross-subscription queries within a tenant in a single paginated call.
Cost comes from the Cost Management query API, one subscription at a time.

Each query fails independently into a CaptureError so a single denied
permission (for example, no Cost Management Reader on one subscription)
doesn't suppress the rest of the snapshot.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, timedelta
from typing import Any

from cost_risk_snapshot.config import CredentialSpec
from cost_risk_snapshot.cost import capture_cost_for_subscription, error_code
from cost_risk_snapshot.lifecycle import derive_end_of_support
from cost_risk_snapshot.models import (
    AdvisorRecommendation,
    CaptureError,
    Findings,
    InventoryCount,
    SecureScore,
    SecurityFinding,
    Waste,
)

log = logging.getLogger(__name__)

# Cost Management throttles aggressively; keep per-credential fan-out low.
COST_FANOUT = 4

SNAPSHOT_AGE_DAYS = 90

# --------------------------------------------------------------------------
# Resource Graph queries
# --------------------------------------------------------------------------

ARG_INVENTORY = """
resources
| summarize resourceCount = count() by subscriptionId, type
"""

_BASE = "id, name, subscriptionId, resourceGroup, location"

ARG_WASTE: dict[str, tuple[str, str]] = {
    # category: (query, reason)
    "unattached_disk": (
        f"""
resources
| where type =~ 'microsoft.compute/disks'
| where tostring(properties.diskState) =~ 'Unattached'
| project {_BASE}, sku = strcat(tostring(sku.name), ' ', tostring(properties.diskSizeGB), 'GiB')
""",
        "managed disk is not attached to any VM and is still billed",
    ),
    "unattached_public_ip": (
        f"""
resources
| where type =~ 'microsoft.network/publicipaddresses'
| where isnull(properties.ipConfiguration) and isnull(properties.natGateway)
| project {_BASE}, sku = tostring(sku.name)
""",
        "public IP is not associated with any resource",
    ),
    "deallocated_vm": (
        f"""
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where tostring(properties.extended.instanceView.powerState.code) =~ 'PowerState/deallocated'
| project {_BASE}, sku = tostring(properties.hardwareProfile.vmSize)
""",
        "VM is deallocated; its disks (and any static public IP) are still billed",
    ),
    "stopped_vm": (
        f"""
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where tostring(properties.extended.instanceView.powerState.code) =~ 'PowerState/stopped'
| project {_BASE}, sku = tostring(properties.hardwareProfile.vmSize)
""",
        "VM is stopped but not deallocated; compute is still billed",
    ),
    "orphaned_nic": (
        f"""
resources
| where type =~ 'microsoft.network/networkinterfaces'
| where isnull(properties.virtualMachine)
    and isnull(properties.privateEndpoint)
    and isnull(properties.privateLinkService)
    and coalesce(array_length(properties.hostedWorkloads), 0) == 0
| project {_BASE}, sku = ''
""",
        "network interface is not attached to a VM or private endpoint",
    ),
    "old_snapshot": (
        f"""
resources
| where type =~ 'microsoft.compute/snapshots'
| where todatetime(properties.timeCreated) < ago({SNAPSHOT_AGE_DAYS}d)
| project {_BASE}, sku = strcat(tostring(sku.name), ' ', tostring(properties.diskSizeGB), 'GiB')
""",
        f"snapshot is older than {SNAPSHOT_AGE_DAYS} days",
    ),
    "empty_app_service_plan": (
        f"""
resources
| where type =~ 'microsoft.web/serverfarms'
| where toint(properties.numberOfSites) == 0
| where tostring(sku.tier) !~ 'Free'
| project {_BASE}, sku = tostring(sku.name)
""",
        "App Service plan hosts no apps but is still billed",
    ),
    "empty_load_balancer": (
        f"""
resources
| where type =~ 'microsoft.network/loadbalancers'
| extend pools = properties.backendAddressPools
| mv-expand pool = iif(coalesce(array_length(pools), 0) == 0, dynamic([null]), pools)
| extend members = coalesce(array_length(pool.properties.backendIPConfigurations), 0)
    + coalesce(array_length(pool.properties.loadBalancerBackendAddresses), 0)
| summarize members = sum(members) by {_BASE}, sku = tostring(sku.name)
| where members == 0
| project {_BASE}, sku
""",
        "load balancer has no backend pool members",
    ),
}

ARG_ADVISOR = """
advisorresources
| where type =~ 'microsoft.advisor/recommendations'
| project id, subscriptionId,
    category = tostring(properties.category),
    impact = tostring(properties.impact),
    problem = tostring(properties.shortDescription.problem),
    solution = tostring(properties.shortDescription.solution),
    impactedResourceId = tostring(properties.resourceMetadata.resourceId),
    annualSavingsAmount = properties.extendedProperties.annualSavingsAmount,
    savingsCurrency = tostring(properties.extendedProperties.savingsCurrency)
"""

ARG_VMS = f"""
resources
| where type =~ 'microsoft.compute/virtualmachines'
| project {_BASE},
    offer = tostring(properties.storageProfile.imageReference.offer),
    sku = tostring(properties.storageProfile.imageReference.sku),
    osName = tostring(properties.extended.instanceView.osName),
    osVersion = tostring(properties.extended.instanceView.osVersion)
"""

ARG_SQL_VMS = f"""
resources
| where type =~ 'microsoft.sqlvirtualmachine/sqlvirtualmachines'
| project {_BASE},
    sqlImageOffer = tostring(properties.sqlImageOffer),
    vmResourceId = tostring(properties.virtualMachineResourceId)
"""

ARG_ARC_MACHINES = f"""
resources
| where type =~ 'microsoft.hybridcompute/machines'
| project {_BASE},
    osName = tostring(properties.osName),
    osSku = tostring(properties.osSku),
    osVersion = tostring(properties.osVersion)
"""

ARG_ARC_SQL = f"""
resources
| where type =~ 'microsoft.azurearcdata/sqlserverinstances'
| project {_BASE}, version = tostring(properties.version)
"""

ARG_NSG_RULES = """
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| where tostring(rule.properties.access) =~ 'Allow'
    and tostring(rule.properties.direction) =~ 'Inbound'
| project id, name, subscriptionId,
    ruleName = tostring(rule.name),
    sourceAddressPrefix = tostring(rule.properties.sourceAddressPrefix),
    sourceAddressPrefixes = rule.properties.sourceAddressPrefixes,
    destinationPortRange = tostring(rule.properties.destinationPortRange),
    destinationPortRanges = rule.properties.destinationPortRanges
"""

ARG_STORAGE = """
resources
| where type =~ 'microsoft.storage/storageaccounts'
| project id, name, subscriptionId,
    allowBlobPublicAccess = properties.allowBlobPublicAccess,
    minimumTlsVersion = tostring(properties.minimumTlsVersion),
    allowSharedKeyAccess = properties.allowSharedKeyAccess
"""

ARG_SQL_SERVERS = """
resources
| where type =~ 'microsoft.sql/servers'
| project id, name, subscriptionId,
    publicNetworkAccess = tostring(properties.publicNetworkAccess)
"""

ARG_KEY_VAULTS = """
resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, subscriptionId,
    enablePurgeProtection = properties.enablePurgeProtection
"""

ARG_SECURE_SCORES = """
securityresources
| where type =~ 'microsoft.security/securescores'
| project subscriptionId,
    current = todouble(properties.score.current),
    max = todouble(properties.score.max),
    percentage = todouble(properties.score.percentage)
"""


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
        data = resp.data
        if isinstance(data, list):
            rows.extend(d for d in data if isinstance(d, dict))
        skip_token = getattr(resp, "skip_token", None)
        if not skip_token:
            break
    return rows


# --------------------------------------------------------------------------
# Row mapping (pure functions, unit tested)
# --------------------------------------------------------------------------


def map_inventory(rows: list[dict]) -> list[InventoryCount]:
    out = [
        InventoryCount(
            subscription_id=r.get("subscriptionId", ""),
            resource_type=(r.get("type") or "").lower(),
            count=int(r.get("resourceCount") or 0),
        )
        for r in rows
    ]
    return sorted(out, key=lambda x: (x.subscription_id, -x.count, x.resource_type))


def map_waste(category: str, reason: str, rows: list[dict]) -> list[Waste]:
    return [
        Waste(
            category=category,
            resource_id=r.get("id", ""),
            name=r.get("name", ""),
            subscription_id=r.get("subscriptionId", ""),
            resource_group=r.get("resourceGroup", ""),
            location=r.get("location", ""),
            sku=(r.get("sku") or "").strip() or None,
            reason=reason,
        )
        for r in rows
    ]


def _float_or_none(v: Any) -> float | None:
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def map_advisor(rows: list[dict]) -> list[AdvisorRecommendation]:
    out = []
    for r in rows:
        savings = _float_or_none(r.get("annualSavingsAmount"))
        currency = (r.get("savingsCurrency") or None) if savings is not None else None
        out.append(
            AdvisorRecommendation(
                category=r.get("category") or "",
                impact=r.get("impact") or "",
                problem=r.get("problem") or "",
                solution=r.get("solution") or "",
                impacted_resource_id=r.get("impactedResourceId") or "",
                subscription_id=r.get("subscriptionId", ""),
                annual_savings=savings,
                savings_currency=currency,
            )
        )
    return out


# NSG checks ---------------------------------------------------------------

INTERNET_SOURCES = {"*", "internet", "any", "0.0.0.0/0", "::/0"}
MGMT_PORTS = {22: "nsg_internet_ssh", 3389: "nsg_internet_rdp"}


def _as_list(single: Any, many: Any) -> list[str]:
    out = [str(x) for x in (many or []) if x]
    if single:
        out.append(str(single))
    return out


def port_covers(port_spec: str, port: int) -> bool:
    s = port_spec.strip()
    if s == "*":
        return True
    if "-" in s:
        lo, _, hi = s.partition("-")
        try:
            return int(lo) <= port <= int(hi)
        except ValueError:
            return False
    try:
        return int(s) == port
    except ValueError:
        return False


def _all_ports(port_spec: str) -> bool:
    s = port_spec.strip()
    return s == "*" or s == "0-65535" or s == "1-65535"


def map_nsg_rules(rows: list[dict]) -> list[SecurityFinding]:
    """Flag Allow/Inbound rules from an internet-wide source to all ports,
    SSH, or RDP. All are high severity."""
    out: list[SecurityFinding] = []
    for r in rows:
        sources = _as_list(r.get("sourceAddressPrefix"), r.get("sourceAddressPrefixes"))
        open_src = [s for s in sources if s.strip().lower() in INTERNET_SOURCES]
        if not open_src:
            continue
        ports = _as_list(r.get("destinationPortRange"), r.get("destinationPortRanges"))
        base = f"rule {r.get('ruleName', '')} allows inbound from {open_src[0]}"

        def add(check: str, detail: str, row: dict = r) -> None:
            out.append(
                SecurityFinding(
                    check=check,
                    severity="high",
                    resource_id=row.get("id", ""),
                    name=row.get("name", ""),
                    subscription_id=row.get("subscriptionId", ""),
                    detail=detail,
                )
            )

        if any(_all_ports(p) for p in ports):
            add("nsg_internet_all_ports", f"{base} to all ports")
            continue
        for port, check in MGMT_PORTS.items():
            if any(port_covers(p, port) for p in ports):
                add(check, f"{base} to port {port} ({', '.join(ports)})")
    return out


# Storage / SQL / Key Vault checks -----------------------------------------

_WEAK_TLS = {"TLS1_0", "TLS1_1"}


def map_storage(rows: list[dict]) -> list[SecurityFinding]:
    out: list[SecurityFinding] = []
    for r in rows:

        def add(check: str, severity: str, detail: str, row: dict = r) -> None:
            out.append(
                SecurityFinding(
                    check=check,
                    severity=severity,
                    resource_id=row.get("id", ""),
                    name=row.get("name", ""),
                    subscription_id=row.get("subscriptionId", ""),
                    detail=detail,
                )
            )

        if r.get("allowBlobPublicAccess") is True:
            add(
                "storage_public_blob_access",
                "medium",
                "allowBlobPublicAccess is true; containers can be made anonymously readable",
            )
        tls = (r.get("minimumTlsVersion") or "").strip()
        if tls in _WEAK_TLS or not tls:
            add(
                "storage_min_tls_below_1_2",
                "medium",
                f"minimumTlsVersion is {tls or 'not set (legacy default TLS1_0)'}",
            )
        # Microsoft documents a null allowSharedKeyAccess as equivalent to true.
        if r.get("allowSharedKeyAccess") is not False:
            add(
                "storage_shared_key_access",
                "low",
                "shared key (account key) authorization is enabled",
            )
    return out


def map_sql_servers(rows: list[dict]) -> list[SecurityFinding]:
    out = []
    for r in rows:
        pna = (r.get("publicNetworkAccess") or "").strip()
        # Empty means the property predates the setting; public access is on.
        if pna.lower() in ("enabled", ""):
            out.append(
                SecurityFinding(
                    check="sql_public_network_access",
                    severity="medium",
                    resource_id=r.get("id", ""),
                    name=r.get("name", ""),
                    subscription_id=r.get("subscriptionId", ""),
                    detail=f"publicNetworkAccess is {pna or 'not set (enabled)'}; "
                    "exposure depends on server firewall rules",
                )
            )
    return out


def map_key_vaults(rows: list[dict]) -> list[SecurityFinding]:
    return [
        SecurityFinding(
            check="keyvault_no_purge_protection",
            severity="medium",
            resource_id=r.get("id", ""),
            name=r.get("name", ""),
            subscription_id=r.get("subscriptionId", ""),
            detail="purge protection is not enabled; deleted vaults and secrets can be purged",
        )
        for r in rows
        if r.get("enablePurgeProtection") is not True
    ]


def map_secure_scores(rows: list[dict]) -> list[SecureScore]:
    return [
        SecureScore(
            subscription_id=r.get("subscriptionId", ""),
            current=_float_or_none(r.get("current")),
            max=_float_or_none(r.get("max")),
            percentage=_float_or_none(r.get("percentage")),
        )
        for r in rows
    ]


# --------------------------------------------------------------------------
# Top-level capture for one credential
# --------------------------------------------------------------------------


def cost_window(days: int, today: date) -> tuple[date, date]:
    """Full days only: from `today - days` through yesterday."""
    return today - timedelta(days=days), today - timedelta(days=1)


def _capture_cost(
    credential: Any,
    subs: list[str],
    start: date,
    end: date,
    findings: Findings,
    errors: list[CaptureError],
) -> None:
    try:
        from azure.mgmt.costmanagement import CostManagementClient

        client = CostManagementClient(credential)
    except Exception as e:  # noqa: BLE001
        errors.append(CaptureError(source="cost.client", message=str(e)))
        return

    with ThreadPoolExecutor(max_workers=COST_FANOUT) as pool:
        futures = [pool.submit(capture_cost_for_subscription, client, s, start, end) for s in subs]
        for fut in as_completed(futures):
            f, errs = fut.result()
            findings.extend(f)
            errors.extend(errs)


def capture_for_credential(
    spec: CredentialSpec, days: int, today: date
) -> tuple[Findings, list[CaptureError], list[str]]:
    """Capture findings against everything the given credential can see.

    Returns (findings, errors, subscriptions_actually_used).
    """
    from cost_risk_snapshot.auth import build_credential

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
                    code=error_code(e),
                )
            )
            return Findings(), errors, []
    if not subs:
        errors.append(
            CaptureError(
                source=f"credential.{spec.name}.list_subscriptions",
                message="no subscriptions visible to this credential",
            )
        )
        return Findings(), errors, []

    def safe(query_name: str, kql: str) -> list[dict]:
        try:
            return query_arg(credential, subs, kql)
        except Exception as e:  # noqa: BLE001
            log.warning("ARG query %s failed: %s", query_name, e)
            errors.append(
                CaptureError(source=f"arg.{query_name}", message=str(e), code=error_code(e))
            )
            return []

    findings = Findings()
    findings.inventory_counts = map_inventory(safe("inventory", ARG_INVENTORY))

    for category, (kql, reason) in ARG_WASTE.items():
        findings.waste.extend(map_waste(category, reason, safe(f"waste.{category}", kql)))

    findings.advisor = map_advisor(safe("advisor", ARG_ADVISOR))

    findings.end_of_support = derive_end_of_support(
        vms=safe("vms", ARG_VMS),
        sql_vms=safe("sql_vms", ARG_SQL_VMS),
        arc_machines=safe("arc_machines", ARG_ARC_MACHINES),
        arc_sql=safe("arc_sql_instances", ARG_ARC_SQL),
        today=today,
    )

    findings.security.extend(map_nsg_rules(safe("security.nsg_rules", ARG_NSG_RULES)))
    findings.security.extend(map_storage(safe("security.storage", ARG_STORAGE)))
    findings.security.extend(map_sql_servers(safe("security.sql_servers", ARG_SQL_SERVERS)))
    findings.security.extend(map_key_vaults(safe("security.key_vaults", ARG_KEY_VAULTS)))
    findings.secure_scores = map_secure_scores(safe("secure_scores", ARG_SECURE_SCORES))

    start, end = cost_window(days, today)
    _capture_cost(credential, subs, start, end, findings, errors)

    return findings, errors, subs
