"""Thin CLI wrapper over backup_audit.run."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from backup_audit import __version__
from backup_audit.config import Config, CredentialSpec
from backup_audit.report import classify

PROG = "azure-backup-audit"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Audit Azure backup coverage across one or many subscriptions. "
            "Outputs follow the toolbox output contract: data.json, CSVs, "
            "and a markdown summary in a timestamped directory."
        ),
    )
    p.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    p.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to a TOML config declaring credentials and their scope. "
        "When omitted, DefaultAzureCredential is used against all "
        "subscriptions the running principal can see.",
    )
    p.add_argument(
        "-s",
        "--subscription",
        action="append",
        default=[],
        metavar="SUB_ID",
        help="Limit the default-credential run to these subscription IDs. "
        "Repeatable. Ignored when --config is supplied.",
    )
    p.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("outputs"),
        help="Parent directory under which a timestamped run dir is created. " "Default: ./outputs",
    )
    p.add_argument(
        "--no-output",
        action="store_true",
        help="Run the capture but write no files. Useful for embedded "
        "use or for piping data.json from stdout (not yet implemented).",
    )
    p.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always exit 0 regardless of findings. Use in pipelines that "
        "prefer side-channel reporting over exit codes.",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity. -v for INFO, -vv for DEBUG.",
    )
    return p


def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _build_config(args: argparse.Namespace) -> Config:
    if args.config:
        from backup_audit.config import load as load_config

        return load_config(args.config)
    return Config(
        credentials=[CredentialSpec(name="default", subscriptions=args.subscription or None)]
    )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    try:
        cfg = _build_config(args)
    except (ValueError, OSError) as e:
        parser.error(str(e))
        return 2  # unreachable; parser.error exits

    from backup_audit.run import run

    output_dir = None if args.no_output else args.output_dir
    result = run(cfg, output_dir=output_dir)

    code = classify(result)
    summary = (
        f"vaults={len(result.findings.vaults)} "
        f"policies={len(result.findings.policies)} "
        f"items={len(result.findings.protected_items)} "
        f"unprotected={len(result.findings.unprotected)} "
        f"errors={len(result.errors)}"
    )
    print(summary, file=sys.stderr)

    if args.exit_zero:
        return 0
    return int(code)


if __name__ == "__main__":
    raise SystemExit(main())
