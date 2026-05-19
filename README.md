# CloudWalkerIT Toolbox

A public collection of cloud operations and audit tools, maintained by
CloudWalkerIT.

## Overview

This repository contains small, self-contained tools for assessing,
diagnosing, and reporting on cloud infrastructure. Each tool addresses one
practical problem and can be read, run, and adapted independently.

## Scope

These tools are open source and free to use. CloudWalkerIT's services focus
on what surrounds them: interpreting results, reviewing findings against your
environment, implementing changes, and remediating the issues they surface.
The code is where that work starts.

## Repository layout

```
.
├── cloud/         Provider-specific assessments and remediation (aws/azure/gcp)
├── diagnostics/   Health checks and troubleshooting tools
├── reporting/     Turning findings into customer-facing reports
├── scripts/       Repo-level helper scripts (bootstrap, maintenance)
└── docs/          Documentation index and conventions
```

`cloud/`, `diagnostics/`, and `reporting/` contain customer-facing tools.
`scripts/` contains cross-cutting helpers for working on this repository
itself, rather than tools intended for customer delivery.

## Adding a tool (polyglot convention)

This repository is intentionally polyglot. There is no shared top-level
dependency manifest and no required language. Each tool is self-contained:

- It lives in its own subdirectory under the relevant category, e.g.
  `cloud/aws/<tool>/`, `diagnostics/<tool>/`, `reporting/<tool>/`.
- It carries its own `README.md` explaining what it does, what access it
  needs, and exactly how to run it.
- It declares its own dependencies next to the code, never at the repo root,
  using a `requirements.txt`, `package.json`, `go.mod`, or a documented
  script header.
- It is runnable from its own directory using only what that directory and
  its README describe.

## Usage and safety

These tools inspect, and in some cases modify, live cloud infrastructure.

- Read a tool's source and its README before running it.
- Run with least-privilege, read-only credentials by default. Only run a tool
  with write access if it explicitly documents that it makes changes, and only
  when you intend those changes.
- Never commit credentials, state files, or environment files. The
  `.gitignore` is deliberately strict about secrets; keep it that way.

## Contributing

Work on a feature branch. Add one self-contained tool per directory, with its
own `README.md` and its own dependency manifest, following the convention
above. Keep changes scoped and the tool runnable on its own.

## License

MIT. See [LICENSE](LICENSE). The tools are provided as-is, with no warranty.
Analysis, review, implementation, and remediation engagements are available
through CloudWalkerIT.
