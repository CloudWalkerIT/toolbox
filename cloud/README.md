# cloud/

Provider-specific assessment and remediation tools.

What belongs here: tools that talk to a specific cloud provider's APIs to
audit configuration, surface risk, or apply fixes.

Suggested layout: `cloud/<provider>/<tool>/`, where `<provider>` is `aws`,
`azure`, or `gcp`. Provider directories are created on demand — add one when
the first tool for it lands.

Each tool is self-contained: its own directory, its own `README.md`, and its
own dependency manifest. See the repository [README](../README.md#adding-a-tool-polyglot-convention)
for the full convention.
