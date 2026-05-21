# azure-backup-audit

Audit Azure backup coverage across one or many subscriptions.

## What it covers

- Azure Recovery Services Vaults: backup policies, protected items,
  workload containers
- Inventory of resources that can be backed up: Azure VMs, Azure file
  shares, SQL on Azure VM (MSSQL workload)
- Cross-referencing inventory against protected items to derive
  unprotected resources

Out of scope for v0.1:

- Azure Backup Vaults (the newer ARM model used for blob, disk,
  PostgreSQL-flexible, AKS, etc.). If you need that coverage, this tool
  will not report on it. Open an issue.
- Sub-protection policies on SQL workload (logs/diffs/fulls breakdown).
  Captured but not summarised.

## How it works

1. Inventory via Azure Resource Graph. One ARG query each for vaults,
   VMs, file shares, and SQL-on-VM resources. ARG handles cross-subscription
   queries within a tenant in a single call, so a single credential covers
   everything it can see.
2. Per-vault detail via the recovery services backup management SDK. For
   each vault we list policies, protected items, and workload containers
   in parallel.
3. Unprotected resources are derived by comparing the inventory against
   the protected items.

## Required RBAC

The credential needs at minimum:

- `Reader` on each subscription audited (covers ARG, VM list, storage
  account list, SQL VM list)
- `Reader` or `Backup Reader` on each Recovery Services Vault (covers
  policies, protected items, containers)

`Reader` at the subscription level satisfies both in most tenants.

Lack of access on a specific vault or subscription produces a
`CaptureError` entry rather than a silent gap. The summary surfaces error
counts so you know when findings are incomplete.

## Install

In the devcontainer (or any Python 3.11+ environment):

```
cd toolbox/cloud/azure/backup-audit
pip install -e .
```

For development with tests:

```
pip install -e ".[test]"
```

## Run

Default credential (uses `az login` cache, env vars, or managed identity),
all subscriptions the principal can see:

```
azure-backup-audit
```

Narrow to specific subscriptions with the default credential:

```
azure-backup-audit -s 11111111-... -s 22222222-...
```

Multi-credential run from a TOML config:

```
azure-backup-audit -c ./audit.toml
```

Example `audit.toml`:

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

## Output

Outputs follow the toolbox output contract (see
`toolbox/docs/output-contract.md`). Each run produces a timestamped
directory under `--output-dir` (default `./outputs/`) containing:

```
data.json              canonical structured output
vaults_policies.csv    one row per policy
protected_items.csv    one row per protected item
unprotected.csv        one row per resource with no protected item
summary.md             short human-readable summary
```

`data.json` is the source of truth for downstream tooling. CSVs are
flat projections and may omit fields.

## Classification

Protected items fall into three buckets:

- **Clean**: last backup succeeded, protection state is normal, health is
  passed. Nothing to action.
- **Warn (needs human review)**: backups completed with warnings, items
  intentionally suspended or disabled, initial replication still pending,
  or Azure has flagged the item as `ActionSuggested`. Could be intentional,
  could be a problem. An auditor must check.
- **Bad (definite failure)**: last backup failed or is reported unhealthy,
  the item is in an `Invalid`/`Error` state, or Azure has flagged it as
  `ActionRequired`. Investigate.

Both warn and bad cause the audit to report findings (non-zero exit).
The summary renders them in separate sections so the distinction is
visible.

## Exit codes

- `0` — capture clean, no concerning findings
- `1` — capture clean, concerning findings present (unprotected resources,
  warn items, or bad items)
- `2` — capture incomplete (one or more errors during enumeration)

Pass `--exit-zero` to suppress non-zero exits when running from a pipeline
that prefers to read `data.json` for status.

## Library use

The tool exposes a Python entry point for in-process use by meta tools:

```python
from backup_audit import run
from backup_audit.config import Config

result = run(Config.default())
# result is a RunResult dataclass; result.findings is a Findings object;
# dataclasses.asdict(result) matches the data.json shape.
```
