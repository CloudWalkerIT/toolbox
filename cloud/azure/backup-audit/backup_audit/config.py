"""TOML configuration loader for multi-credential runs.

The config file declares one or more credentials, each scoped to a list of
subscription IDs. When no config is supplied the tool falls back to
DefaultAzureCredential covering whatever the running principal can see.

Example::

    [[credentials]]
    name = "tenant-a-prod"
    tenant_id = "11111111-1111-1111-1111-111111111111"
    client_id = "22222222-2222-2222-2222-222222222222"
    client_secret_env = "TENANT_A_CLIENT_SECRET"
    subscriptions = ["aaaaaaaa-...", "bbbbbbbb-..."]

    [[credentials]]
    name = "tenant-b"
    tenant_id = "..."
    client_id = "..."
    client_secret_env = "TENANT_B_CLIENT_SECRET"
    # subscriptions omitted -> all subs this SP can see
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CredentialSpec:
    name: str
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    subscriptions: list[str] | None = None  # None = all visible

    @property
    def is_service_principal(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)


@dataclass
class Config:
    credentials: list[CredentialSpec]

    @classmethod
    def default(cls) -> Config:
        return cls(credentials=[CredentialSpec(name="default")])


def load(path: str | Path) -> Config:
    """Load a TOML config and resolve secrets from env vars.

    Raises ValueError on malformed config (missing fields, unresolved env
    var, etc.).
    """
    raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    creds_in = raw.get("credentials", [])
    if not isinstance(creds_in, list) or not creds_in:
        raise ValueError(f"{path}: must contain at least one [[credentials]] block")

    creds = []
    seen_names: set[str] = set()
    for i, c in enumerate(creds_in):
        name = c.get("name") or f"cred-{i}"
        if name in seen_names:
            raise ValueError(f"{path}: duplicate credential name {name!r}")
        seen_names.add(name)

        tenant_id = c.get("tenant_id")
        client_id = c.get("client_id")
        secret = c.get("client_secret")
        secret_env = c.get("client_secret_env")
        if secret_env:
            secret = os.environ.get(secret_env)
            if not secret:
                raise ValueError(
                    f"{path}: credential {name!r} references env var "
                    f"{secret_env!r} which is unset or empty"
                )

        subs = c.get("subscriptions")
        if subs is not None and not isinstance(subs, list):
            raise ValueError(
                f"{path}: credential {name!r}: subscriptions must be a list of strings"
            )

        creds.append(
            CredentialSpec(
                name=name,
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=secret,
                subscriptions=subs,
            )
        )

    return Config(credentials=creds)
