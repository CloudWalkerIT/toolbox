"""Credential construction from CredentialSpec entries.

Imports of azure.identity are deferred so the module can be loaded for tests
without the SDK installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backup_audit.config import CredentialSpec

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential


def build_credential(spec: CredentialSpec) -> TokenCredential:
    """Return a TokenCredential for the given spec.

    For SP-style specs (tenant + client + secret) returns a
    ClientSecretCredential. Otherwise returns DefaultAzureCredential, which
    works for `az login`, env vars, managed identity, and similar.
    """
    if spec.tenant_id and spec.client_id and spec.client_secret:
        from azure.identity import ClientSecretCredential

        return ClientSecretCredential(
            tenant_id=spec.tenant_id,
            client_id=spec.client_id,
            client_secret=spec.client_secret,
        )

    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential()
