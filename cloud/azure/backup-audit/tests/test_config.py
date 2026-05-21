"""Tests for the TOML config loader."""

from __future__ import annotations

from pathlib import Path

import pytest
from backup_audit.config import Config, load


def test_default_config_has_one_default_credential() -> None:
    cfg = Config.default()
    assert len(cfg.credentials) == 1
    assert cfg.credentials[0].name == "default"
    assert cfg.credentials[0].is_service_principal is False


def test_load_minimal(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text(
        """
[[credentials]]
name = "first"
""",
        encoding="utf-8",
    )
    cfg = load(p)
    assert len(cfg.credentials) == 1
    assert cfg.credentials[0].name == "first"
    assert cfg.credentials[0].is_service_principal is False


def test_load_sp_with_inline_secret(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text(
        """
[[credentials]]
name = "sp-a"
tenant_id = "t"
client_id = "c"
client_secret = "s"
subscriptions = ["sub1", "sub2"]
""",
        encoding="utf-8",
    )
    cfg = load(p)
    assert cfg.credentials[0].is_service_principal is True
    assert cfg.credentials[0].subscriptions == ["sub1", "sub2"]


def test_load_sp_with_env_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_SECRET", "shhh")
    p = tmp_path / "c.toml"
    p.write_text(
        """
[[credentials]]
name = "sp-b"
tenant_id = "t"
client_id = "c"
client_secret_env = "MY_SECRET"
""",
        encoding="utf-8",
    )
    cfg = load(p)
    assert cfg.credentials[0].client_secret == "shhh"


def test_load_rejects_unset_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MY_MISSING_SECRET", raising=False)
    p = tmp_path / "c.toml"
    p.write_text(
        """
[[credentials]]
name = "sp"
tenant_id = "t"
client_id = "c"
client_secret_env = "MY_MISSING_SECRET"
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="MY_MISSING_SECRET"):
        load(p)


def test_load_rejects_empty_credentials(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="at least one"):
        load(p)


def test_load_rejects_duplicate_names(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text(
        """
[[credentials]]
name = "same"

[[credentials]]
name = "same"
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load(p)
