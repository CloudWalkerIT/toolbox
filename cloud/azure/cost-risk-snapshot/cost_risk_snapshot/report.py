"""Report emitters: data.json, CSVs, summary.md.

The contract is documented in toolbox/docs/output-contract.md. Exit-code
classification (clean / findings / errors) is decided here and returned to
the caller.
"""

from __future__ import annotations

import calendar
import csv
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, fields
from datetime import UTC, date, datetime, timedelta
from enum import IntEnum
from pathlib import Path

from cost_risk_snapshot.lifecycle import ENDED, ENDS_SOON, SUPPORTED, UNKNOWN
from cost_risk_snapshot.models import (
    AdvisorRecommendation,
    CostByMonth,
    CostByResourceGroup,
    CostByService,
    EndOfSupport,
    InventoryCount,
    RunResult,
    SecureScore,
    SecurityFinding,
    Waste,
)


class ExitCode(IntEnum):
    CLEAN = 0
    FINDINGS = 1
    CAPTURE_INCOMPLETE = 2


CONCERNING_EOS = {ENDED, ENDS_SOON}


def write_run(result: RunResult, run_dir: Path) -> ExitCode:
    """Write data.json, one CSV per findings array, and summary.md to
    run_dir. Returns the exit code classification for this run."""
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "data.json").write_text(
        json.dumps(asdict(result), indent=2, default=str), encoding="utf-8"
    )
    for name, row_cls in CSV_ROW_TYPES.items():
        _write_csv(getattr(result.findings, name), run_dir / f"{name}.csv", row_cls)
    (run_dir / "summary.md").write_text(render_summary(result), encoding="utf-8")
    return classify(result)


def concerning_counts(result: RunResult) -> dict[str, int]:
    f = result.findings
    return {
        "waste": len(f.waste),
        "end_of_support": sum(1 for e in f.end_of_support if e.status in CONCERNING_EOS),
        "advisor_high_impact": sum(1 for a in f.advisor if a.impact.lower() == "high"),
        "security_high": sum(1 for s in f.security if s.severity == "high"),
    }


def classify(result: RunResult) -> ExitCode:
    if result.errors:
        return ExitCode.CAPTURE_INCOMPLETE
    if any(concerning_counts(result).values()):
        return ExitCode.FINDINGS
    return ExitCode.CLEAN


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------


# One CSV per findings array, named after the array.
CSV_ROW_TYPES: dict[str, type] = {
    "inventory_counts": InventoryCount,
    "cost_by_month": CostByMonth,
    "cost_by_service": CostByService,
    "cost_by_resource_group": CostByResourceGroup,
    "waste": Waste,
    "advisor": AdvisorRecommendation,
    "end_of_support": EndOfSupport,
    "security": SecurityFinding,
    "secure_scores": SecureScore,
}


def _write_csv(rows: list, path: Path, row_cls: type) -> None:
    headers = [f.name for f in fields(row_cls)]
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        w.writerow(headers)
        for r in rows:
            d = asdict(r)
            w.writerow(["" if d[h] is None else d[h] for h in headers])


# --------------------------------------------------------------------------
# Cost headline
# --------------------------------------------------------------------------


@dataclass
class CostHeadline:
    currency: str
    last_full_month: str
    last_full_month_cost: float | None  # None if the window didn't cover it
    month_to_date: float
    run_rate: float | None  # None on the 1st of the month


def _prev_month(d: date) -> date:
    return date(d.year - 1, 12, 1) if d.month == 1 else date(d.year, d.month - 1, 1)


def cost_headlines(result: RunResult, today: date) -> list[CostHeadline]:
    """Per-currency last full month total and a naive current-month run-rate.

    The cost window ends yesterday, so month-to-date covers `today.day - 1`
    full days; run-rate extrapolates that to the whole month.
    """
    last = _prev_month(today)
    last_key = last.strftime("%Y-%m")
    cur_key = today.strftime("%Y-%m")
    covered = result.scope.cost_from <= last.isoformat()

    by_cur: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for r in result.findings.cost_by_month:
        by_cur[r.currency][r.month] += r.cost

    elapsed = today.day - 1
    days_in_month = calendar.monthrange(today.year, today.month)[1]
    out = []
    for cur in sorted(by_cur):
        months = by_cur[cur]
        mtd = months.get(cur_key, 0.0)
        out.append(
            CostHeadline(
                currency=cur,
                last_full_month=last_key,
                last_full_month_cost=round(months.get(last_key, 0.0), 2) if covered else None,
                month_to_date=round(mtd, 2),
                run_rate=round(mtd / elapsed * days_in_month, 2) if elapsed > 0 else None,
            )
        )
    return out


def top_services(result: RunResult, n: int = 5) -> list[tuple[str, str, float]]:
    totals: dict[tuple[str, str], float] = defaultdict(float)
    for r in result.findings.cost_by_service:
        totals[(r.service_name, r.currency)] += r.cost
    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return [(svc, cur, round(c, 2)) for (svc, cur), c in ranked]


def advisor_savings(result: RunResult) -> dict[str, float]:
    out: dict[str, float] = defaultdict(float)
    for a in result.findings.advisor:
        if a.annual_savings is not None:
            out[a.savings_currency or "?"] += a.annual_savings
    return {k: round(v, 2) for k, v in sorted(out.items())}


# --------------------------------------------------------------------------
# summary.md
# --------------------------------------------------------------------------


def _money(amount: float | None, currency: str) -> str:
    return "n/a" if amount is None else f"{amount:,.2f} {currency}"


def render_summary(result: RunResult) -> str:
    # The cost window ends yesterday, so "today" for the run is cost_to + 1.
    today = date.fromisoformat(result.scope.cost_to) + timedelta(days=1)
    f = result.findings
    lines: list[str] = []
    lines.append("# Azure Cost & Risk Snapshot\n")
    lines.append(f"- Tool: `{result.tool}` v{result.tool_version}")
    lines.append(f"- Generated: {result.generated_at}")
    lines.append(f"- Subscriptions: {len(result.scope.subscriptions)}")
    lines.append(f"- Credentials used: {', '.join(result.scope.credentials) or '(none)'}")
    lines.append(
        f"- Cost window: {result.scope.cost_from} to {result.scope.cost_to} "
        f"({result.scope.cost_days} days, ActualCost)"
    )
    lines.append(f"- Capture errors: {len(result.errors)}")
    lines.append("")

    # Headline ---------------------------------------------------------
    lines.append("## Headline\n")
    heads = cost_headlines(result, today)
    if not heads:
        lines.append("- Cost: no cost data captured")
    for h in heads:
        lines.append(
            f"- Last full month ({h.last_full_month}): "
            f"{_money(h.last_full_month_cost, h.currency)}"
        )
        lines.append(
            f"- Current run-rate ({today.strftime('%Y-%m')}, month-to-date extrapolated): "
            f"{_money(h.run_rate, h.currency)}"
        )
    savings = advisor_savings(result)
    if savings:
        for cur, amt in savings.items():
            lines.append(f"- Advisor annual savings (as reported): {_money(amt, cur)}")
    else:
        lines.append("- Advisor annual savings: none reported")
    counts = concerning_counts(result)
    lines.append(f"- Waste candidates: {counts['waste']}")
    lines.append(f"- End-of-support: {counts['end_of_support']} ended or ending within 12 months")
    lines.append(f"- High-severity security findings: {counts['security_high']}")
    lines.append(f"- High-impact Advisor recommendations: {counts['advisor_high_impact']}")
    lines.append("")

    # Cost -------------------------------------------------------------
    lines.append("## Top services\n")
    svcs = top_services(result)
    if not svcs:
        lines.append("_(no data)_")
    else:
        lines.append("| Service | Cost |")
        lines.append("|---|---:|")
        for svc, cur, c in svcs:
            lines.append(f"| {svc} | {_money(c, cur)} |")
    lines.append("")

    # Waste ------------------------------------------------------------
    lines.append("## Waste candidates\n")
    waste_by_cat = Counter(w.category for w in f.waste)
    if not waste_by_cat:
        lines.append("_(none)_")
    else:
        lines.append("| Category | Count |")
        lines.append("|---|---:|")
        for cat, n in waste_by_cat.most_common():
            lines.append(f"| {cat} | {n} |")
        lines.append("\nSee `waste.csv` for the full list.")
    lines.append("")

    # End of support ---------------------------------------------------
    lines.append("## End of support\n")
    eos_by_status = Counter(e.status for e in f.end_of_support)
    if not f.end_of_support:
        lines.append("_(no Windows Server or SQL Server versions detected)_")
    else:
        lines.append("| Status | Count |")
        lines.append("|---|---:|")
        for status in (ENDED, ENDS_SOON, SUPPORTED, UNKNOWN):
            if eos_by_status.get(status):
                lines.append(f"| {status} | {eos_by_status[status]} |")
        by_product = Counter(
            (e.product, e.version, e.status) for e in f.end_of_support if e.status in CONCERNING_EOS
        )
        if by_product:
            lines.append("")
            for (product, version, status), n in sorted(by_product.items()):
                lines.append(f"- {product} {version} ({status}): {n}")
        lines.append(
            "\nDates are end of extended support. Extended Security Updates are not checked."
        )
    lines.append("")

    # Security ---------------------------------------------------------
    lines.append("## Security\n")
    sec = Counter((s.severity, s.check) for s in f.security)
    if not sec:
        lines.append("_(no findings)_")
    else:
        lines.append("| Severity | Check | Count |")
        lines.append("|---|---|---:|")
        order = {"high": 0, "medium": 1, "low": 2}
        ranked = sorted(sec.items(), key=lambda kv: (order.get(kv[0][0], 9), kv[0][1]))
        for (sev, check), n in ranked:
            lines.append(f"| {sev} | {check} | {n} |")
    if f.secure_scores:
        lines.append("")
        lines.append("Secure score by subscription:")
        for s in f.secure_scores:
            pct = "n/a" if s.percentage is None else f"{s.percentage * 100:.0f}%"
            lines.append(f"- `{s.subscription_id}`: {pct}")
    lines.append("")

    # Advisor ----------------------------------------------------------
    lines.append("## Advisor\n")
    adv = Counter((a.category, a.impact) for a in f.advisor)
    if not adv:
        lines.append("_(no recommendations)_")
    else:
        lines.append("| Category | Impact | Count |")
        lines.append("|---|---|---:|")
        for (cat, impact), n in sorted(adv.items()):
            lines.append(f"| {cat} | {impact} | {n} |")
        lines.append(
            "\nSavings are as reported by Advisor and can overlap between recommendations."
        )
    lines.append("")

    # Errors -----------------------------------------------------------
    if result.errors:
        lines.append("## Capture errors\n")
        lines.append("Capture was incomplete. Findings may understate cost or risk.\n")
        for e in result.errors[:20]:
            code = f" ({e.code})" if e.code else ""
            lines.append(f"- `{e.source}`{code} - {e.message[:300]}")
        if len(result.errors) > 20:
            lines.append(f"- ...and {len(result.errors) - 20} more")
        lines.append("")

    return "\n".join(lines)


def now_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
