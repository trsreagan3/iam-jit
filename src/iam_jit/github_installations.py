"""GitHub App installation registry — the GitHub analog of the AWS accounts
store (see docs/design/github-jit-tokens.md).

Deliberately SEPARATE from `accounts_store` (AWS accounts are 12-digit IDs with
IAM-ARN provisioner roles; GitHub installations are an org + App + numeric
installation id). Keeping them apart avoids polluting the strict AWS account
schema and keeps the GitHub feature modular + standalone (no bouncer dep).

The App private key is referenced by PATH (a 0600 PEM file), never inlined in
the registry YAML — keys don't belong in config.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
from collections.abc import Callable
from typing import Any

import httpx
from ruamel.yaml import YAML

from .github_provisioner import GitHubAppConfig, GitHubAppProvisioner

_yaml = YAML(typ="safe")

_API_VERSION = "iam-jit.dev/v1alpha1"
_KIND = "GitHubInstallationList"


class GitHubInstallationError(Exception):
    """Registry load / lookup / key-read failure."""


class GitHubInstallationNotFound(GitHubInstallationError):
    pass


@dataclasses.dataclass(frozen=True)
class GitHubInstallation:
    """One installed iam-jit GitHub App (the bootstrap an org admin sets up
    once — the GitHub analog of the AWS provisioner role)."""

    org: str
    app_id: str
    installation_id: str
    private_key_path: str  # path to the App PEM (0600); NOT inlined
    alias: str | None = None
    enabled: bool = True
    api_base: str = "https://api.github.com"

    @property
    def id(self) -> str:
        return self.org


def _from_dict(d: dict[str, Any]) -> GitHubInstallation:
    missing = [k for k in ("org", "app_id", "installation_id", "private_key_path") if not d.get(k)]
    if missing:
        raise GitHubInstallationError(f"installation entry missing required field(s): {missing}")
    return GitHubInstallation(
        org=str(d["org"]),
        app_id=str(d["app_id"]),
        installation_id=str(d["installation_id"]),
        private_key_path=str(d["private_key_path"]),
        alias=d.get("alias"),
        enabled=bool(d.get("enabled", True)),
        api_base=str(d.get("api_base") or "https://api.github.com"),
    )


def default_registry_path() -> str:
    """$IAM_JIT_GITHUB_INSTALLATIONS, else ~/.iam-jit/github-installations.yaml."""
    env = os.getenv("IAM_JIT_GITHUB_INSTALLATIONS")
    if env:
        return env
    return str(pathlib.Path.home() / ".iam-jit" / "github-installations.yaml")


def load_installations(path: str | os.PathLike[str]) -> list[GitHubInstallation]:
    """Load the installation registry. A missing file is an empty registry
    (not an error) — same shape as the users/accounts stores on first run."""
    p = pathlib.Path(path)
    if not p.exists():
        return []
    data = _yaml.load(p.read_text()) or {}
    if data.get("apiVersion") != _API_VERSION or data.get("kind") != _KIND:
        raise GitHubInstallationError(
            f"{path}: expected apiVersion={_API_VERSION} kind={_KIND}; "
            f"got apiVersion={data.get('apiVersion')!r} kind={data.get('kind')!r}"
        )
    return [_from_dict(e) for e in (data.get("installations") or [])]


def _to_dict(inst: GitHubInstallation) -> dict[str, Any]:
    d: dict[str, Any] = {
        "org": inst.org,
        "app_id": inst.app_id,
        "installation_id": inst.installation_id,
        "private_key_path": inst.private_key_path,
        "enabled": inst.enabled,
    }
    if inst.alias:
        d["alias"] = inst.alias
    if inst.api_base and inst.api_base != "https://api.github.com":
        d["api_base"] = inst.api_base
    return d


def write_installations(
    path: str | os.PathLike[str], installations: list[GitHubInstallation]
) -> None:
    """Atomically write the registry (temp file + rename, 0600 — it references
    key paths, so keep it owner-only)."""
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "apiVersion": _API_VERSION,
        "kind": _KIND,
        "installations": [_to_dict(i) for i in installations],
    }
    import io

    buf = io.StringIO()
    _yaml.dump(doc, buf)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(buf.getvalue())
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def add_installation(path: str | os.PathLike[str], inst: GitHubInstallation) -> None:
    """Upsert an installation by org (replaces an existing same-org entry)."""
    existing = [i for i in load_installations(path) if i.org.lower() != inst.org.lower()]
    write_installations(path, [*existing, inst])


def get_installation(path: str | os.PathLike[str], org_or_alias: str) -> GitHubInstallation:
    """Resolve an installation by org or alias (case-insensitive on org)."""
    want = org_or_alias.strip().lower()
    for inst in load_installations(path):
        if inst.org.lower() == want or (inst.alias and inst.alias.lower() == want):
            return inst
    raise GitHubInstallationNotFound(f"no GitHub installation for {org_or_alias!r} in {path}")


def _read_private_key(inst: GitHubInstallation) -> str:
    p = pathlib.Path(inst.private_key_path).expanduser()
    if not p.exists():
        raise GitHubInstallationError(
            f"App private key not found at {inst.private_key_path} (for org {inst.org})"
        )
    return p.read_text()


def provisioner_for(
    inst: GitHubInstallation,
    *,
    http: httpx.Client | None = None,
    now: Callable[[], int] | None = None,
) -> GitHubAppProvisioner:
    """Build a GitHubAppProvisioner for this installation, loading the PEM from
    its `private_key_path`."""
    if not inst.enabled:
        raise GitHubInstallationError(f"GitHub installation for {inst.org} is disabled")
    cfg = GitHubAppConfig(
        app_id=inst.app_id,
        private_key_pem=_read_private_key(inst),
        installation_id=inst.installation_id,
        api_base=inst.api_base,
    )
    return GitHubAppProvisioner(cfg, http=http, now=now)
