"""Tests for CLI argument handling and exit codes. run() is patched."""

from __future__ import annotations

import sys

import pytest
from cost_risk_snapshot import cli


@pytest.fixture
def fake_run(monkeypatch):
    captured = {}

    def install(result):
        def _run(cfg, output_dir=None, days=90):
            captured.update(cfg=cfg, output_dir=output_dir, days=days)
            return result

        # The package re-exports run(), which shadows the submodule name.
        monkeypatch.setattr(sys.modules["cost_risk_snapshot.run"], "run", _run)
        return captured

    return install


def test_exit_clean(fake_run, clean_result) -> None:
    fake_run(clean_result)
    assert cli.main(["--no-output"]) == 0


def test_exit_findings_and_exit_zero(fake_run, concerning_result) -> None:
    fake_run(concerning_result)
    assert cli.main(["--no-output"]) == 1
    assert cli.main(["--no-output", "--exit-zero"]) == 0


def test_exit_errors(fake_run, errored_result) -> None:
    fake_run(errored_result)
    assert cli.main(["--no-output"]) == 2


def test_days_and_subscriptions_passed_through(fake_run, clean_result, tmp_path) -> None:
    captured = fake_run(clean_result)
    cli.main(["--days", "30", "-s", "sub-a", "-s", "sub-b", "-o", str(tmp_path)])
    assert captured["days"] == 30
    assert captured["output_dir"] == tmp_path
    assert captured["cfg"].credentials[0].subscriptions == ["sub-a", "sub-b"]


@pytest.mark.parametrize("bad", ["0", "366", "abc"])
def test_days_validation(bad) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--days", bad])
    assert exc.value.code == 2
