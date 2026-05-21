"""Data model for capture results.

These dataclasses serialise to the `data.json` shape described in
`docs/output-contract.md`. Field names match the JSON field names exactly so
that `dataclasses.asdict` produces the canonical output.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Vault:
    name: str
    resource_group: str
    subscription_id: str
    location: str


@dataclass
class Policy:
    vault: str
    resource_group: str
    subscription_id: str
    name: str
    backup_management_type: str
    workload_type: str
    policy_type: str
    schedule_frequency: str
    schedule_times: list[str]
    schedule_days: list[str]
    retention: dict[str, str]
    instant_restore_days: int | None
    timezone: str | None
    sub_policies: list[dict]
    has_protected_items: bool = False


@dataclass
class ProtectedItem:
    vault: str
    resource_group: str
    subscription_id: str
    workload_type: str
    backup_management_type: str
    item_name: str
    friendly_name: str
    container_name: str
    source_resource_id: str
    policy: str | None
    last_backup_time: str | None
    last_backup_status: str | None
    protection_state: str | None
    health_status: str | None
    last_error_code: str | None
    last_error_message: str | None


@dataclass
class Unprotected:
    resource_type: str
    name: str
    resource_group: str
    subscription_id: str
    location: str
    detail: str
    reason: str


@dataclass
class CaptureError:
    source: str
    message: str
    code: str | None = None


@dataclass
class Scope:
    subscriptions: list[str]
    credentials: list[str]


@dataclass
class Findings:
    vaults: list[Vault] = field(default_factory=list)
    policies: list[Policy] = field(default_factory=list)
    protected_items: list[ProtectedItem] = field(default_factory=list)
    unprotected: list[Unprotected] = field(default_factory=list)


@dataclass
class RunResult:
    schema_version: int
    tool: str
    tool_version: str
    generated_at: str
    scope: Scope
    findings: Findings
    errors: list[CaptureError] = field(default_factory=list)
