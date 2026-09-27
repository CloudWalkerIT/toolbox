"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from cost_risk_snapshot.models import (
    AdvisorRecommendation,
    CaptureError,
    CostByMonth,
    CostByResourceGroup,
    CostByService,
    EndOfSupport,
    Findings,
    InventoryCount,
    RunResult,
    Scope,
    SecureScore,
    SecurityFinding,
    Waste,
)

SUB = "11111111-1111-1111-1111-111111111111"
RG_ID = f"/subscriptions/{SUB}/resourceGroups/rg-prod/providers"


@pytest.fixture
def clean_result() -> RunResult:
    """Cost and inventory only; nothing concerning, no errors. Run date is
    2026-09-27 (cost window ends the day before)."""
    return RunResult(
        schema_version=1,
        tool="azure-cost-risk-snapshot",
        tool_version="0.1.0",
        generated_at="2026-09-27T12:00:00Z",
        scope=Scope(
            subscriptions=[SUB],
            credentials=["default"],
            cost_days=90,
            cost_from="2026-06-29",
            cost_to="2026-09-26",
        ),
        findings=Findings(
            inventory_counts=[
                InventoryCount(SUB, "microsoft.compute/virtualmachines", 3),
            ],
            cost_by_month=[
                CostByMonth(SUB, "2026-06", 50.0, "USD"),
                CostByMonth(SUB, "2026-07", 1000.0, "USD"),
                CostByMonth(SUB, "2026-08", 1200.0, "USD"),
                CostByMonth(SUB, "2026-09", 1040.0, "USD"),
            ],
            cost_by_service=[
                CostByService(SUB, "Virtual Machines", 2000.0, "USD"),
                CostByService(SUB, "Storage", 800.0, "USD"),
                CostByService(SUB, "Bandwidth", 10.0, "USD"),
            ],
            cost_by_resource_group=[
                CostByResourceGroup(SUB, "rg-prod", 2500.0, "USD"),
            ],
            advisor=[
                AdvisorRecommendation(
                    category="Cost",
                    impact="Medium",
                    problem="Right-size or shutdown underutilized virtual machines",
                    solution="Right-size or shutdown underutilized virtual machines",
                    impacted_resource_id=f"{RG_ID}/Microsoft.Compute/virtualMachines/vm1",
                    subscription_id=SUB,
                    annual_savings=1234.5,
                    savings_currency="USD",
                ),
            ],
            end_of_support=[
                EndOfSupport(
                    resource_id=f"{RG_ID}/Microsoft.Compute/virtualMachines/vm2",
                    name="vm2",
                    subscription_id=SUB,
                    kind="vm",
                    product="Windows Server",
                    version="2022",
                    end_of_support="2031-10-14",
                    status="supported",
                    days_remaining=1843,
                    source="imageReference WindowsServer/2022-datacenter",
                ),
            ],
            security=[
                SecurityFinding(
                    check="storage_shared_key_access",
                    severity="low",
                    resource_id=f"{RG_ID}/Microsoft.Storage/storageAccounts/sa1",
                    name="sa1",
                    subscription_id=SUB,
                    detail="shared key (account key) authorization is enabled",
                ),
            ],
            secure_scores=[SecureScore(SUB, 30.0, 50.0, 0.6)],
        ),
        errors=[],
    )


@pytest.fixture
def concerning_result(clean_result) -> RunResult:
    f = clean_result.findings
    f.waste.append(
        Waste(
            category="unattached_disk",
            resource_id=f"{RG_ID}/Microsoft.Compute/disks/d1",
            name="d1",
            subscription_id=SUB,
            resource_group="rg-prod",
            location="eastus",
            sku="Premium_LRS 128GiB",
            reason="managed disk is not attached to any VM and is still billed",
        )
    )
    f.end_of_support.append(
        EndOfSupport(
            resource_id=f"{RG_ID}/Microsoft.Compute/virtualMachines/old",
            name="old",
            subscription_id=SUB,
            kind="vm",
            product="Windows Server",
            version="2012 R2",
            end_of_support="2023-10-10",
            status="ended",
            days_remaining=-1083,
            source="imageReference WindowsServer/2012-R2-Datacenter",
        )
    )
    f.security.append(
        SecurityFinding(
            check="nsg_internet_rdp",
            severity="high",
            resource_id=f"{RG_ID}/Microsoft.Network/networkSecurityGroups/nsg1",
            name="nsg1",
            subscription_id=SUB,
            detail="rule allow-rdp allows inbound from * to port 3389 (3389)",
        )
    )
    return clean_result


@pytest.fixture
def errored_result(clean_result) -> RunResult:
    clean_result.errors.append(
        CaptureError(
            source=f"cost.{SUB}.by_month",
            message="The client does not have authorization to perform action ...",
            code="AuthorizationFailed",
        )
    )
    return clean_result
