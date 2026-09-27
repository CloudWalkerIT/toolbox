# azure-cost-risk-snapshot

Read-only snapshot of Azure spend, likely waste, end-of-support exposure,
and basic security posture across one or many subscriptions.

CloudWalkerIT uses this tool as the data-collection step of its Cost & Risk
Snapshot.

## What it covers

- **Inventory**: resource counts by type and subscription.
- **Cost** (Cost Management, ActualCost, last `--days` days): monthly
  totals, cost by service (`ServiceName`), and the top 25 resource groups
  per subscription. Currency is carried on every row.
- **Waste candidates**: unattached managed disks, unattached public IPs,
  deallocated VMs (disks still billed), stopped-but-not-deallocated VMs
  (compute still billed), orphaned NICs, snapshots older than 90 days,
  non-free App Service plans with no apps, and load balancers with no
  backend pool members. `est_monthly_cost` is left empty; the tool does
  not guess prices.
- **Azure Advisor** recommendations in every category, with annual savings
  and currency where Advisor reports them.
- **End of support** for Windows Server and SQL Server on:
  - Azure VMs (image reference offer/sku, falling back to the OS name the
    guest agent reports),
  - SQL IaaS extension resources (`sqlImageOffer`),
  - Azure Arc-enabled servers (`osSku`/`osName`) and Arc-enabled SQL Server
    instances, which surface on-premises exposure.
- **Security checks**:

  | Check | Severity |
  |---|---|
  | `nsg_internet_all_ports`: NSG allows inbound from `*`/`Internet`/`0.0.0.0/0` to all ports | high |
  | `nsg_internet_ssh`: same, to a range covering 22 | high |
  | `nsg_internet_rdp`: same, to a range covering 3389 | high |
  | `storage_public_blob_access`: `allowBlobPublicAccess` is true | medium |
  | `storage_min_tls_below_1_2`: minimum TLS is 1.0/1.1 or not set | medium |
  | `sql_public_network_access`: SQL server public network access enabled | medium |
  | `keyvault_no_purge_protection`: Key Vault without purge protection | medium |
  | `storage_shared_key_access`: shared key authorization enabled (or unset, which means enabled) | low |

  High means a management surface or everything is reachable from the
  internet. Medium means a configuration that widens exposure or weakens
  recovery but needs another condition to be exploited. Low is hygiene.
- **Secure score** per subscription from Microsoft Defender for Cloud, when
  readable.

Out of scope for v0.1:

- Reservation and savings plan coverage or utilisation.
- Backup coverage. Use [`azure-backup-audit`](../backup-audit/) for that.
- AKS internals (node pools, workloads, cluster configuration).
- Extended Security Update enrolment. End-of-support dates are end of
  extended support; a workload may still be covered by ESUs.

## How it works

1. Subscriptions come from `-s`, the config file, or everything the
   credential can see.
2. Inventory, waste, Advisor, end-of-support, and security data come from
   Azure Resource Graph (`resources`, `advisorresources`,
   `securityresources`). ARG handles cross-subscription queries within a
   tenant in a single paginated call.
3. Cost comes from the Cost Management query API: three queries per
   subscription (monthly, by service, by resource group) over a window
   that ends yesterday (UTC) so every day in it is complete.
4. Lifecycle status is computed against a table of end-of-support dates in
   `cost_risk_snapshot/lifecycle.py`, with the Microsoft lifecycle pages
   cited next to it.

Every query fails independently. A denied or throttled query produces a
`CaptureError` entry rather than a silent gap, and the summary shows the
error count up front.

## Required RBAC

Per subscription:

- `Reader`: Resource Graph, Advisor, and resource properties.
- `Cost Management Reader`: cost queries.
- `Security Reader` (optional): secure score. `Reader` is usually enough to
  read it too; if neither works you get a `CaptureError` for
  `arg.secure_scores` and the rest of the snapshot is unaffected.

Missing access on any subscription produces `CaptureError` entries, not a
crash. Cost Management is not available for every offer type (for example
some sponsorship or CSP arrangements); those show up the same way.

## Install

In the devcontainer (or any Python 3.11+ environment):

```
cd toolbox/cloud/azure/cost-risk-snapshot
pip install -e .
```

For development with tests:

```
pip install -e ".[test]"
pytest
```

## Run

Default credential (uses `az login` cache, env vars, or managed identity),
all subscriptions the principal can see, 90 days of cost:

```
azure-cost-risk-snapshot
```

Specific subscriptions and a shorter cost window:

```
azure-cost-risk-snapshot -s 11111111-... -s 22222222-... --days 60
```

Multi-credential run from a TOML config:

```
azure-cost-risk-snapshot -c ./snapshot.toml
```

Example `snapshot.toml`:

```toml
[[credentials]]
name = "tenant-a-prod"
tenant_id = "11111111-1111-1111-1111-111111111111"
client_id = "22222222-2222-2222-2222-222222222222"
client_secret_env = "TENANT_A_CLIENT_SECRET"
subscriptions = ["aaaaaaaa-...", "bbbbbbbb-..."]

[[credentials]]
name = "tenant-b"
tenant_id = "33333333-3333-3333-3333-333333333333"
client_id = "44444444-4444-4444-4444-444444444444"
client_secret_env = "TENANT_B_CLIENT_SECRET"
# subscriptions omitted -> all subs this SP can see
```

`client_secret_env` is the name of an environment variable holding the
secret. Inline `client_secret = "..."` is also supported for ad hoc use
but you should prefer env vars in any committed config.

Options:

```
-c, --config PATH        TOML credentials config
-s, --subscription ID    limit the default-credential run (repeatable)
-o, --output-dir PATH    parent dir for run output (default ./outputs)
--days N                 cost lookback, 1-365 (default 90)
--no-output              capture only, write no files
--exit-zero              always exit 0
-v / -vv                 INFO / DEBUG logging
```

## Output

Outputs follow the toolbox output contract (see
`toolbox/docs/output-contract.md`). Each run produces a timestamped
directory under `--output-dir` containing:

```
data.json                    canonical structured output
inventory_counts.csv         resource count per type and subscription
cost_by_month.csv            monthly ActualCost per subscription
cost_by_service.csv          cost per ServiceName per subscription
cost_by_resource_group.csv   top 25 resource groups per subscription
waste.csv                    one row per waste candidate
advisor.csv                  one row per Advisor recommendation
end_of_support.csv           one row per detected Windows Server / SQL Server install
security.csv                 one row per failed security check
secure_scores.csv            secure score per subscription
summary.md                   short human-readable summary
```

`summary.md` leads with last full month cost, current month run-rate
(month-to-date extrapolated to the full month), top 5 services, total
Advisor annual savings, waste count by category, end-of-support counts by
status, the high-severity security count, and the capture error count.
Advisor savings are summed as reported and can overlap between
recommendations.

The output directory contains resource IDs and cost data. Treat it as
confidential and keep it out of version control (`outputs/` is ignored).

## Exit codes

- `0`: capture clean, nothing concerning
- `1`: capture clean, concerning findings present
- `2`: capture incomplete (errors non-empty) or the run aborted

A snapshot is **concerning** when any of these hold:

- any waste candidate exists;
- any end-of-support row has status `ended` or `ends_within_12_months`;
- any Advisor recommendation has `High` impact;
- any security finding has `high` severity.

Pass `--exit-zero` to suppress non-zero exits when running from a pipeline
that prefers to read `data.json` for status.

## Safety

The tool is read-only. It only issues Resource Graph queries, Cost
Management queries, and a subscription list. It makes no changes, needs no
write permissions, and should be run with a principal that holds only the
roles listed above.

## Library use

```python
from cost_risk_snapshot import run
from cost_risk_snapshot.config import Config

result = run(Config.default(), days=90)
# result is a RunResult dataclass; dataclasses.asdict(result) matches the
# data.json shape.
```
