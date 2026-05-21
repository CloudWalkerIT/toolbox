"""Report emitters: data.json, CSVs, summary.md.

The contract is documented in toolbox/docs/output-contract.md. Exit-code
classification (clean / findings / errors) is decided here and returned to
the caller.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path

from backup_audit.models import RunResult

# Last-backup-status classification.
SUCCESS_LBS = {"Completed", "Healthy", "Passed", "InProgress"}
WARNING_LBS = {"CompletedWithWarnings"}
BAD_LBS = {"Failed", "Unhealthy"}

# Protection-state classification. "Suspended", "Disabled", and
# "BackupsSuspended" represent a paused state; the protected item is
# intentionally not being backed up. Those need human review (was it
# intentional?) but they are not the same as a hard failure.
# "IRPending" means initial replication pending: normal during onboarding,
# stuck if it lingers. Treat as warn.
WARN_PROTECTION_STATES = {"Suspended", "Disabled", "BackupsSuspended", "IRPending"}
BAD_PROTECTION_STATES = {"Invalid", "Error"}

# Health-status classification.
HEALTHY_HEALTH = {"Passed", "Healthy", "", None}
WARN_HEALTH = {"ActionSuggested"}
BAD_HEALTH = {"ActionRequired"}


class ExitCode(IntEnum):
    CLEAN = 0
    FINDINGS = 1
    CAPTURE_INCOMPLETE = 2


class Severity(IntEnum):
    """Per-item severity with explicit precedence. An item with both a bad
    signal and a warn signal is BAD; the bad signal dominates."""

    CLEAN = 0
    WARN = 1
    BAD = 2


def write_run(result: RunResult, run_dir: Path) -> ExitCode:
    """Write data.json, CSVs, and summary.md to run_dir. Returns the exit
    code classification for this run."""
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_data_json(result, run_dir / "data.json")
    _write_vaults_policies_csv(result, run_dir / "vaults_policies.csv")
    _write_protected_items_csv(result, run_dir / "protected_items.csv")
    _write_unprotected_csv(result, run_dir / "unprotected.csv")
    _write_summary_md(result, run_dir / "summary.md")
    return classify(result)


def classify(result: RunResult) -> ExitCode:
    if result.errors:
        return ExitCode.CAPTURE_INCOMPLETE
    if result.findings.unprotected:
        return ExitCode.FINDINGS
    if any(severity(it) >= Severity.WARN for it in result.findings.protected_items):
        return ExitCode.FINDINGS
    return ExitCode.CLEAN


def severity(item) -> Severity:
    """Single-source-of-truth classifier with explicit precedence.

    An item that trips a BAD signal is BAD even if it also trips WARN
    signals. Only items with WARN signals and no BAD signals are WARN.
    Everything else is CLEAN.
    """
    lbs = item.last_backup_status or ""
    ps = item.protection_state or ""
    hs = item.health_status or ""

    if lbs in BAD_LBS or ps in BAD_PROTECTION_STATES or hs in BAD_HEALTH:
        return Severity.BAD
    if lbs in WARNING_LBS or ps in WARN_PROTECTION_STATES or hs in WARN_HEALTH:
        return Severity.WARN
    return Severity.CLEAN


def _item_is_bad(item) -> bool:
    """Kept for backwards-compatibility in tests. Returns True iff
    severity(item) == BAD."""
    return severity(item) == Severity.BAD


def _item_is_warning(item) -> bool:
    """Kept for backwards-compatibility in tests. Returns True iff
    severity(item) == WARN. Note: an item with a bad signal AND a warn
    signal is BAD, not WARN."""
    return severity(item) == Severity.WARN


# --------------------------------------------------------------------------
# data.json
# --------------------------------------------------------------------------


def _write_data_json(result: RunResult, path: Path) -> None:
    path.write_text(json.dumps(asdict(result), indent=2, default=str), encoding="utf-8")


# --------------------------------------------------------------------------
# CSV emitters
# --------------------------------------------------------------------------


VAULTS_POLICIES_HEADERS = [
    "subscription_id",
    "vault",
    "resource_group",
    "policy_name",
    "backup_management_type",
    "workload_type",
    "policy_type",
    "schedule_frequency",
    "schedule_times",
    "schedule_days",
    "retention_daily",
    "retention_weekly",
    "retention_monthly",
    "retention_yearly",
    "instant_restore_days",
    "timezone",
    "has_protected_items",
]

PROTECTED_ITEMS_HEADERS = [
    "subscription_id",
    "vault",
    "resource_group",
    "workload_type",
    "backup_management_type",
    "item_name",
    "friendly_name",
    "container_name",
    "source_resource_id",
    "policy",
    "last_backup_time",
    "last_backup_status",
    "protection_state",
    "health_status",
    "last_error_code",
    "last_error_message",
]

UNPROTECTED_HEADERS = [
    "subscription_id",
    "resource_type",
    "name",
    "resource_group",
    "location",
    "detail",
    "reason",
]


def _write_vaults_policies_csv(result: RunResult, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow(VAULTS_POLICIES_HEADERS)
        for p in result.findings.policies:
            r = p.retention or {}
            w.writerow(
                [
                    p.subscription_id,
                    p.vault,
                    p.resource_group,
                    p.name,
                    p.backup_management_type,
                    p.workload_type,
                    p.policy_type,
                    p.schedule_frequency,
                    "|".join(p.schedule_times),
                    "|".join(p.schedule_days),
                    r.get("daily_schedule", ""),
                    r.get("weekly_schedule", ""),
                    r.get("monthly_schedule", ""),
                    r.get("yearly_schedule", ""),
                    p.instant_restore_days if p.instant_restore_days is not None else "",
                    p.timezone or "",
                    "yes" if p.has_protected_items else "no",
                ]
            )


def _write_protected_items_csv(result: RunResult, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow(PROTECTED_ITEMS_HEADERS)
        for it in result.findings.protected_items:
            w.writerow(
                [
                    it.subscription_id,
                    it.vault,
                    it.resource_group,
                    it.workload_type,
                    it.backup_management_type,
                    it.item_name,
                    it.friendly_name,
                    it.container_name,
                    it.source_resource_id,
                    it.policy or "",
                    it.last_backup_time or "",
                    it.last_backup_status or "",
                    it.protection_state or "",
                    it.health_status or "",
                    it.last_error_code or "",
                    it.last_error_message or "",
                ]
            )


def _write_unprotected_csv(result: RunResult, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow(UNPROTECTED_HEADERS)
        for u in result.findings.unprotected:
            w.writerow(
                [
                    u.subscription_id,
                    u.resource_type,
                    u.name,
                    u.resource_group,
                    u.location,
                    u.detail,
                    u.reason,
                ]
            )


# --------------------------------------------------------------------------
# summary.md
# --------------------------------------------------------------------------


def _write_summary_md(result: RunResult, path: Path) -> None:
    lines: list[str] = []
    lines.append("# Azure Backup Audit\n")
    lines.append(f"- Tool: `{result.tool}` v{result.tool_version}")
    lines.append(f"- Generated: {result.generated_at}")
    lines.append(f"- Subscriptions audited: {len(result.scope.subscriptions)}")
    lines.append(f"- Credentials used: {', '.join(result.scope.credentials) or '(none)'}")
    lines.append("")

    f = result.findings
    bad_items = [i for i in f.protected_items if _item_is_bad(i)]
    warn_items = [i for i in f.protected_items if _item_is_warning(i)]
    unused_policies = [p for p in f.policies if not p.has_protected_items]

    lines.append("## Totals\n")
    lines.append("| Resource | Count | Concerning |")
    lines.append("|---|---:|---:|")
    lines.append(f"| Recovery Services Vaults | {len(f.vaults)} | - |")
    lines.append(f"| Backup policies | {len(f.policies)} | {len(unused_policies)} unused |")
    items_concerning = f"{len(bad_items)} bad, {len(warn_items)} warn"
    lines.append(f"| Protected items | {len(f.protected_items)} | {items_concerning} |")
    by_type: Counter = Counter(u.resource_type for u in f.unprotected)
    for t in sorted(by_type):
        lines.append(f"| Unprotected {t} | {by_type[t]} | {by_type[t]} |")
    lines.append("")

    if result.errors:
        lines.append("## Capture errors\n")
        lines.append("Capture was incomplete. Findings may understate coverage gaps.\n")
        by_code: Counter = Counter(e.code or "" for e in result.errors)
        for e in result.errors[:20]:
            lines.append(f"- `{e.source}` - {e.message}")
        if len(result.errors) > 20:
            lines.append(f"- ...and {len(result.errors) - 20} more")
        if any(by_code):
            lines.append("")
            lines.append("Error code rollup:")
            for code, count in by_code.most_common():
                if code:
                    lines.append(f"- `{code}` x {count}")
        lines.append("")

    if bad_items:
        lines.append("## Items with failed backups\n")
        lines.append(
            "Definite failures: last backup did not succeed, the protected "
            "item is in an invalid/error state, or Azure has flagged the "
            "item as `ActionRequired`. Investigate each.\n"
        )
        _render_item_section(lines, bad_items)
        lines.append("")

    if warn_items:
        lines.append("## Items requiring human review\n")
        lines.append(
            "These items are not failing right now but their state warrants "
            "review: backups completed with warnings, items intentionally "
            "suspended or disabled, initial replication pending, or health "
            "is flagged as `ActionSuggested`. Confirm the state matches "
            "what's expected.\n"
        )
        _render_item_section(lines, warn_items)
        lines.append("")

    if unused_policies:
        lines.append("## Policies with no protected items\n")
        for p in unused_policies[:50]:
            lines.append(f"- `{p.vault}` / `{p.name}` ({p.backup_management_type})")
        if len(unused_policies) > 50:
            lines.append(f"- ...and {len(unused_policies) - 50} more")
        lines.append("")

    lines.append("## Unprotected resources\n")
    if not f.unprotected:
        lines.append("_(none)_")
    else:
        lines.append("See `unprotected.csv` for the full list.\n")
        for t, count in by_type.most_common():
            lines.append(f"- {t}: **{count}**")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

ITEM_SECTION_HARD_CAP = 20


def _render_item_section(lines: list[str], items: list) -> None:
    """Render a section of protected items: error-code rollup first (most
    useful), then a per-vault state count, then a short tail of individual
    items capped at ITEM_SECTION_HARD_CAP. The full list lives in
    protected_items.csv."""
    err_by_code: Counter = Counter(i.last_error_code or "" for i in items if i.last_error_code)
    if err_by_code:
        lines.append("Error code rollup:")
        for code, count in err_by_code.most_common():
            lines.append(f"- `{code}` x {count}")
        lines.append("")

    by_vault_state: Counter = Counter(
        (i.vault, f"lbs={i.last_backup_status or '-'} state={i.protection_state or '-'}")
        for i in items
    )
    if len(by_vault_state) > 1 or len(items) > ITEM_SECTION_HARD_CAP:
        lines.append("By vault and state:")
        for (vault, state), count in by_vault_state.most_common():
            lines.append(f"- `{vault}` - {state} x {count}")
        lines.append("")

    cap = ITEM_SECTION_HARD_CAP
    lines.append(f"Sample items (up to {cap}; see `protected_items.csv` for the full list):")
    for it in items[:cap]:
        brief = (it.last_error_code or it.last_error_message or "").strip()
        if brief and len(brief) > 140:
            brief = brief[:140]
        lines.append(
            f"- {it.vault} / {it.friendly_name} - "
            f"lbs={it.last_backup_status or ''}, "
            f"state={it.protection_state or ''}, "
            f"health={it.health_status or ''}" + (f" - _{brief}_" if brief else "")
        )
    if len(items) > cap:
        lines.append(f"- ...and {len(items) - cap} more in `protected_items.csv`")


def now_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
