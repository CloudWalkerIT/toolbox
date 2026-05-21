# Toolbox output contract

Every toolbox tool that produces structured findings writes its output in the
shape described here. The goal is that a later "meta" tool can crawl a
collection of runs and aggregate findings without knowing tool-specific
details, and that downstream report generators can consume the same data
without screen-scraping markdown.

## Run directory

Each run writes to a directory named for a UTC timestamp:

```
<output-dir>/<run-id>/
  data.json
  summary.md
  *.csv            (one or more, derived from data.json)
  raw/             (optional, unprocessed API responses)
```

`<run-id>` is `YYYYMMDDTHHMMSSZ`. The directory is created fresh for every
run; tools must not overwrite or merge into existing run directories.

## data.json

This is the canonical structured output. CSVs are flat views derived from it
and may omit fields. Markdown is for humans and is not contractually stable.

Top-level shape:

```json
{
  "schema_version": 1,
  "tool": "azure-backup-audit",
  "tool_version": "0.1.0",
  "generated_at": "2026-05-20T19:30:00Z",
  "scope": { },
  "findings": { },
  "errors": []
}
```

Field semantics:

- `schema_version` is the contract version, not the tool version. It
  increments only when this document changes in a breaking way.
- `tool` is the package distribution name, stable across versions.
- `tool_version` is the tool's own semver.
- `generated_at` is an ISO 8601 UTC timestamp.
- `scope` is tool-specific and describes what the tool was asked to audit
  (subscriptions, regions, namespaces, etc.).
- `findings` is tool-specific and contains the actual results, organised as
  the tool sees fit. Use named arrays of objects rather than nested
  positional structures so the meta tool can address fields by name.
- `errors` is an array of non-fatal capture errors: things the tool tried
  to read but couldn't due to RBAC, throttling, or transient failure.
  Each entry is `{ "source": "...", "message": "...", "code": "..." }`
  where `code` is optional. An empty array means a clean capture.

A tool that aborts before producing usable findings should exit non-zero
and may write no `data.json` at all. A tool that produces partial findings
should still write `data.json` with the partial results and populate
`errors`.

## CSV views

Each CSV file is a flat tabular projection of part of `data.json`. CSVs use
UTF-8 with no BOM, RFC 4180 quoting, and `\n` line endings. Column headers
are snake_case and match the JSON field names where possible.

## Exit codes

- `0` — capture clean, no concerning findings.
- `1` — capture clean, concerning findings present (unprotected resources,
  failed backups, drift, etc.). What "concerning" means is the tool's
  decision and must be documented in its README.
- `2` — capture incomplete (errors array non-empty) or the tool aborted.
- Other non-zero — reserved.

Tools should accept a `--exit-zero` flag that forces exit `0` regardless of
findings, for use in pipelines that prefer side-channel reporting.

## Library API

Each tool that participates in the contract exposes a Python entry point
suitable for in-process invocation:

```python
from <tool_package> import run

result = run(config_or_args)
# result is a dict matching the data.json shape, or a typed dataclass that
# serialises to it.
```

The CLI must be a thin wrapper around this entry point.
