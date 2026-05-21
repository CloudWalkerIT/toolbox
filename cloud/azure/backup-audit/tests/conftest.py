"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from backup_audit.models import (
    CaptureError,
    Findings,
    Policy,
    ProtectedItem,
    RunResult,
    Scope,
    Unprotected,
    Vault,
)


@pytest.fixture
def sample_result() -> RunResult:
    """A small synthetic RunResult with one vault, two policies, three items,
    and a mix of unprotected resources and capture errors."""
    vaults = [
        Vault(
            name="rsv-a",
            resource_group="rg-backups",
            subscription_id="11111111-1111-1111-1111-111111111111",
            location="eastus",
        )
    ]
    policies = [
        Policy(
            vault="rsv-a",
            resource_group="rg-backups",
            subscription_id="11111111-1111-1111-1111-111111111111",
            name="daily-30",
            backup_management_type="AzureIaasVM",
            workload_type="VM",
            policy_type="V2",
            schedule_frequency="Daily",
            schedule_times=["2024-01-01T02:00:00"],
            schedule_days=[],
            retention={"daily_schedule": "30Days"},
            instant_restore_days=2,
            timezone="UTC",
            sub_policies=[],
        ),
        Policy(
            vault="rsv-a",
            resource_group="rg-backups",
            subscription_id="11111111-1111-1111-1111-111111111111",
            name="orphan-policy",
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
        ),
    ]
    items = [
        ProtectedItem(
            vault="rsv-a",
            resource_group="rg-backups",
            subscription_id="11111111-1111-1111-1111-111111111111",
            workload_type="VM",
            backup_management_type="AzureIaasVM",
            item_name="iaasvmcontainerv2;rg-prod;vm-good",
            friendly_name="vm-good",
            container_name="iaasvmcontainerv2;rg-prod;vm-good",
            source_resource_id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-good",
            policy="daily-30",
            last_backup_time="2026-05-19T02:00:00Z",
            last_backup_status="Completed",
            protection_state="Protected",
            health_status="Passed",
            last_error_code=None,
            last_error_message=None,
        ),
        ProtectedItem(
            vault="rsv-a",
            resource_group="rg-backups",
            subscription_id="11111111-1111-1111-1111-111111111111",
            workload_type="VM",
            backup_management_type="AzureIaasVM",
            item_name="iaasvmcontainerv2;rg-prod;vm-failing",
            friendly_name="vm-failing",
            container_name="iaasvmcontainerv2;rg-prod;vm-failing",
            source_resource_id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-failing",
            policy="daily-30",
            last_backup_time="2026-05-18T02:00:00Z",
            last_backup_status="Failed",
            protection_state="Protected",
            health_status="ActionRequired",
            last_error_code="UserErrorVmNotInRunningState",
            last_error_message="VM was deallocated during the backup attempt.",
        ),
        ProtectedItem(
            vault="rsv-a",
            resource_group="rg-backups",
            subscription_id="11111111-1111-1111-1111-111111111111",
            workload_type="VM",
            backup_management_type="AzureIaasVM",
            item_name="iaasvmcontainerv2;rg-prod;vm-warning",
            friendly_name="vm-warning",
            container_name="iaasvmcontainerv2;rg-prod;vm-warning",
            source_resource_id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-warning",
            policy="daily-30",
            last_backup_time="2026-05-19T02:00:00Z",
            last_backup_status="CompletedWithWarnings",
            protection_state="Protected",
            health_status="Passed",
            last_error_code=None,
            last_error_message=None,
        ),
    ]
    unprotected = [
        Unprotected(
            resource_type="VM",
            name="vm-orphan",
            resource_group="rg-prod",
            subscription_id="11111111-1111-1111-1111-111111111111",
            location="eastus",
            detail="vmSize=Standard_B2s",
            reason="no IaaS protected item references this VM",
        ),
    ]
    policies[0].has_protected_items = True
    policies[1].has_protected_items = False

    return RunResult(
        schema_version=1,
        tool="azure-backup-audit",
        tool_version="0.1.0",
        generated_at="2026-05-20T19:30:00Z",
        scope=Scope(
            subscriptions=["11111111-1111-1111-1111-111111111111"],
            credentials=["default"],
        ),
        findings=Findings(
            vaults=vaults,
            policies=policies,
            protected_items=items,
            unprotected=unprotected,
        ),
        errors=[],
    )


@pytest.fixture
def sample_result_with_errors(sample_result) -> RunResult:
    """Same as sample_result but with a non-empty errors list."""
    sample_result.errors.append(
        CaptureError(
            source="vault.rsv-b.items",
            message="The client 'foo' does not have authorization to perform action ...",
            code="AuthorizationFailed",
        )
    )
    return sample_result
