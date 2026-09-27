"""Data model for capture results.

These dataclasses serialise to the `data.json` shape described in
`docs/output-contract.md`. Field names match the JSON field names exactly so
that `dataclasses.asdict` produces the canonical output, and each list in
`Findings` is written out as its own CSV.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class InventoryCount:
    subscription_id: str
    resource_type: str
    count: int


@dataclass
class CostByMonth:
    subscription_id: str
    month: str  # YYYY-MM
    cost: float
    currency: str


@dataclass
class CostByService:
    subscription_id: str
    service_name: str
    cost: float
    currency: str


@dataclass
class CostByResourceGroup:
    subscription_id: str
    resource_group: str
    cost: float
    currency: str


@dataclass
class Waste:
    category: str
    resource_id: str
    name: str
    subscription_id: str
    resource_group: str
    location: str
    sku: str | None
    reason: str
    est_monthly_cost: float | None = None


@dataclass
class AdvisorRecommendation:
    category: str
    impact: str
    problem: str
    solution: str
    impacted_resource_id: str
    subscription_id: str
    annual_savings: float | None
    savings_currency: str | None


@dataclass
class EndOfSupport:
    resource_id: str
    name: str
    subscription_id: str
    kind: str  # vm | sql_vm | arc_machine | arc_sql_instance
    product: str  # "Windows Server" | "SQL Server"
    version: str
    end_of_support: str | None  # ISO date, None when the version is not in the table
    status: str  # ended | ends_within_12_months | supported | unknown
    days_remaining: int | None
    source: str  # which property the version was read from


@dataclass
class SecurityFinding:
    check: str
    severity: str  # high | medium | low
    resource_id: str
    name: str
    subscription_id: str
    detail: str


@dataclass
class SecureScore:
    subscription_id: str
    current: float | None
    max: float | None
    percentage: float | None


@dataclass
class CaptureError:
    source: str
    message: str
    code: str | None = None


@dataclass
class Scope:
    subscriptions: list[str]
    credentials: list[str]
    cost_days: int
    cost_from: str  # ISO date, inclusive
    cost_to: str  # ISO date, inclusive


@dataclass
class Findings:
    inventory_counts: list[InventoryCount] = field(default_factory=list)
    cost_by_month: list[CostByMonth] = field(default_factory=list)
    cost_by_service: list[CostByService] = field(default_factory=list)
    cost_by_resource_group: list[CostByResourceGroup] = field(default_factory=list)
    waste: list[Waste] = field(default_factory=list)
    advisor: list[AdvisorRecommendation] = field(default_factory=list)
    end_of_support: list[EndOfSupport] = field(default_factory=list)
    security: list[SecurityFinding] = field(default_factory=list)
    secure_scores: list[SecureScore] = field(default_factory=list)

    def extend(self, other: Findings) -> None:
        for name in self.__dataclass_fields__:
            getattr(self, name).extend(getattr(other, name))


@dataclass
class RunResult:
    schema_version: int
    tool: str
    tool_version: str
    generated_at: str
    scope: Scope
    findings: Findings
    errors: list[CaptureError] = field(default_factory=list)
