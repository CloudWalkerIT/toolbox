"""Top-level orchestration. Library entry point: `backup_audit.run`.

Fans out capture across credentials in parallel, merges findings into a
single RunResult, writes outputs, and returns the result.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

from backup_audit.capture import capture_for_credential
from backup_audit.config import Config
from backup_audit.models import CaptureError, Findings, RunResult, Scope
from backup_audit.report import ExitCode, now_run_id, write_run

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
TOOL_NAME = "azure-backup-audit"


def _tool_version() -> str:
    # Import locally to avoid circular imports at module load.
    from backup_audit import __version__

    return __version__


def run(config: Config | None = None, output_dir: Path | str | None = None) -> RunResult:
    """Run a full capture and write outputs.

    Args:
        config: Multi-credential configuration. None falls back to a single
            DefaultAzureCredential ("default" credential).
        output_dir: Parent directory under which a timestamped run dir is
            created. None means "do not write outputs, just return the
            RunResult". Useful for embedded use by a meta tool.

    Returns:
        RunResult populated with findings and any non-fatal capture errors.
    """
    cfg = config or Config.default()

    all_findings = Findings()
    all_errors: list[CaptureError] = []
    all_subscriptions: list[str] = []

    with ThreadPoolExecutor(max_workers=max(1, len(cfg.credentials))) as pool:
        futures = {pool.submit(capture_for_credential, spec): spec for spec in cfg.credentials}
        for fut in as_completed(futures):
            spec = futures[fut]
            try:
                findings, errors, subs = fut.result()
            except Exception as e:  # noqa: BLE001
                log.exception("credential %s capture failed wholesale", spec.name)
                all_errors.append(
                    CaptureError(
                        source=f"credential.{spec.name}",
                        message=f"capture failed: {e}",
                    )
                )
                continue
            all_findings.vaults.extend(findings.vaults)
            all_findings.policies.extend(findings.policies)
            all_findings.protected_items.extend(findings.protected_items)
            all_findings.unprotected.extend(findings.unprotected)
            all_errors.extend(errors)
            all_subscriptions.extend(subs)

    # De-dupe subscription IDs while preserving order
    seen: set[str] = set()
    deduped_subs: list[str] = []
    for s in all_subscriptions:
        if s not in seen:
            seen.add(s)
            deduped_subs.append(s)

    result = RunResult(
        schema_version=SCHEMA_VERSION,
        tool=TOOL_NAME,
        tool_version=_tool_version(),
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        scope=Scope(
            subscriptions=deduped_subs,
            credentials=[c.name for c in cfg.credentials],
        ),
        findings=all_findings,
        errors=all_errors,
    )

    if output_dir is not None:
        run_dir = Path(output_dir) / now_run_id()
        write_run(result, run_dir)
        log.info("wrote run to %s", run_dir)

    return result


def run_and_classify(
    config: Config | None = None, output_dir: Path | str | None = None
) -> tuple[RunResult, ExitCode]:
    """Convenience: run() plus exit-code classification."""
    from backup_audit.report import classify

    result = run(config, output_dir)
    return result, classify(result)
