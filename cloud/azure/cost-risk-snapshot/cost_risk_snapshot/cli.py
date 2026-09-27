"""Thin CLI wrapper over cost_risk_snapshot.run."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from cost_risk_snapshot import __version__
from cost_risk_snapshot.config import Config, CredentialSpec
from cost_risk_snapshot.report import classify
from cost_risk_snapshot.run import DEFAULT_DAYS

PROG = "azure-cost-risk-snapshot"


def _days(value: str) -> int:
    n = int(value)
    if not 1 <= n <= 365:
        raise argparse.ArgumentTypeError("must be between 1 and 365")
    return n


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Read-only snapshot of Azure cost, waste, end-of-support, and "
            "security posture across one or many subscriptions. Outputs follow "
            "the toolbox output contract: data.json, CSVs, and a markdown "
            "summary in a timestamped directory."
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
        help="Parent directory under which a timestamped run dir is created. Default: ./outputs",
    )
    p.add_argument(
        "--days",
        type=_days,
        default=DEFAULT_DAYS,
        help=f"Cost lookback in days, ending yesterday (UTC). 1-365. Default: {DEFAULT_DAYS}",
    )
    p.add_argument(
        "--no-output",
        action="store_true",
        help="Run the capture but write no files.",
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
        from cost_risk_snapshot.config import load as load_config

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

    from cost_risk_snapshot.run import run

    output_dir = None if args.no_output else args.output_dir
    result = run(cfg, output_dir=output_dir, days=args.days)

    code = classify(result)
    f = result.findings
    summary = (
        f"subscriptions={len(result.scope.subscriptions)} "
        f"waste={len(f.waste)} "
        f"advisor={len(f.advisor)} "
        f"end_of_support={len(f.end_of_support)} "
        f"security={len(f.security)} "
        f"errors={len(result.errors)}"
    )
    print(summary, file=sys.stderr)

    if args.exit_zero:
        return 0
    return int(code)


if __name__ == "__main__":
    raise SystemExit(main())
