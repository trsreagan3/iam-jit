"""#491 LAUNCH-BLOCKER §A91 — ``iam-jit org-policy {sign,verify}`` IT-side
CLI for corp-managed deployment.

Per ``[[enterprise-profile-distribution]]`` IT curates ``org-policy.yaml``,
Ed25519-signs it, and publishes it to a static HTTPS endpoint. Engineers
then run ``iam-jit init --managed --org-policy URL`` (#490 §A90) which
fetches, verifies, and applies the policy.

This module is the IT-side counterpart: two subcommands that give the
IT operator a first-class sign/verify surface without requiring them to
wrangle ``openssl`` or ``cryptography`` Python APIs directly.

  ``iam-jit org-policy sign  --in YAML --key PRIV --out SIG``
    Ed25519-sign an ``org-policy.yaml`` using a private key generated
    via ``openssl genpkey -algorithm ED25519`` (or via
    ``iam-jit-feed-publish init`` keypair tooling from #409). Writes a
    base64-encoded raw Ed25519 signature to ``--out`` (the ``.sig``
    companion file). This is the ONLY artifact that gets published
    alongside the YAML; private key NEVER leaves the IT machine.

  ``iam-jit org-policy verify --policy YAML --sig SIG --pubkey PUB``
    Companion dry-run verifier. IT calls this BEFORE publishing to
    confirm the ``.sig`` file will pass ``init --managed`` verification.
    Exits 0 on success, 1 on failure (exact semantics the ``init
    --managed`` pipeline uses so there is no surprise at engineer
    rollout time).

Signing primitive:
  Reuses ``threat_feed.signing._load_ed25519_private`` (from #409) so
  there is exactly ONE Ed25519 private-key loader in the codebase.

Verify primitive:
  Reuses ``cli_init._verify_ed25519_signature`` (from #490) — the same
  function the ``init --managed`` pipeline calls so a passing local
  verify GUARANTEES a passing engineer-side rollout.

Per ``[[creates-never-mutates]]`` the ``sign`` command writes a NEW .sig
file and refuses to overwrite without ``--overwrite``.

Per ``[[push-policy-public-repo]]`` private key material NEVER appears
in CLI output; the ``sign`` command only reads and uses the key.
"""

from __future__ import annotations

import base64
import pathlib
import sys

import click


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_private_key_pem(private_key_path: pathlib.Path) -> str:
    """Read the private key PEM from disk. Raises :class:`click.ClickException`
    on any read failure (missing file, permission error, empty)."""
    try:
        pem = private_key_path.read_text(encoding="ascii").strip()
    except OSError as e:
        raise click.ClickException(
            f"could not read private key at {private_key_path}: {e}"
        ) from e
    if not pem:
        raise click.ClickException(
            f"private key file {private_key_path} is empty."
        )
    return pem


def _sign_policy_bytes(
    policy_bytes: bytes,
    private_key_pem: str,
    *,
    key_path: pathlib.Path,
) -> bytes:
    """Sign ``policy_bytes`` with an Ed25519 private key.

    Returns the raw 64-byte Ed25519 signature (NOT base64 — caller
    decides encoding). Reuses ``threat_feed.signing._load_ed25519_private``
    per the task spec so there is one key-loader in the codebase.

    Raises :class:`click.ClickException` on failure (bad key, sign op
    failure).
    """
    try:
        from .threat_feed.signing import SigningError, _load_ed25519_private
    except ImportError as e:
        raise click.ClickException(
            f"cryptography library required for Ed25519 signing: {e}"
        ) from e

    try:
        private_key = _load_ed25519_private(private_key_pem)
    except Exception as e:
        raise click.ClickException(
            f"failed to parse private key at {key_path}: {e}"
        ) from e

    try:
        return private_key.sign(policy_bytes)  # type: ignore[return-value]
    except Exception as e:
        raise click.ClickException(
            f"Ed25519 sign operation failed: {e}"
        ) from e


# ---------------------------------------------------------------------------
# CLI group + subcommands
# ---------------------------------------------------------------------------


def register_org_policy_group(main_group: click.Group) -> click.Group:
    """Attach ``iam-jit org-policy`` to the top-level click group.

    Returns the group so tests can invoke subcommands directly via
    ``CliRunner.invoke(group.commands['sign'], [...])`` without
    importing private helpers.
    """

    @main_group.group("org-policy")
    def org_policy_group() -> None:
        """IT-side tooling for corp-managed deployment (#491 §A91).

        Sign an org-policy.yaml + publish it to a static HTTPS endpoint
        so engineers can onboard via ``iam-jit init --managed --org-policy URL``.

        See docs/CORP-MANAGED-DEPLOYMENT.md for the full recipe.
        """

    @org_policy_group.command("sign")
    @click.option(
        "--in",
        "policy_yaml_path",
        required=True,
        type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
        help="Path to the org-policy YAML to sign.",
    )
    @click.option(
        "--key",
        "private_key_path",
        required=True,
        type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
        help="Path to the Ed25519 private key PEM file (0600, never published).",
    )
    @click.option(
        "--out",
        "signature_out_path",
        required=True,
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        help="Path to write the base64-encoded Ed25519 signature (.sig file).",
    )
    @click.option(
        "--overwrite",
        is_flag=True,
        default=False,
        help="Overwrite an existing .sig file. Per [[creates-never-mutates]] "
             "default is to refuse if the .sig already exists.",
    )
    def sign_org_policy(
        policy_yaml_path: pathlib.Path,
        private_key_path: pathlib.Path,
        signature_out_path: pathlib.Path,
        overwrite: bool,
    ) -> None:
        """Ed25519-sign an org-policy YAML for corp-managed distribution.

        Reads the policy YAML as raw bytes, signs with the Ed25519
        private key, and writes a base64-encoded signature to --out
        (the companion .sig file you publish alongside the YAML).

        The private key NEVER appears in output. Publish the YAML +
        .sig to your HTTPS endpoint; give engineers the public key via
        $IAM_JIT_ORG_PUBLIC_KEY or ~/.iam-jit/org.pub.

        Example:

        \\b
            # Generate a keypair (once, on the IT machine):
            openssl genpkey -algorithm ED25519 -out org.priv
            openssl pkey -in org.priv -pubout -out org.pub

            # Sign the policy:
            iam-jit org-policy sign \\\\
                --in org-policy.yaml \\\\
                --key org.priv \\\\
                --out org-policy.yaml.sig

            # Verify before publishing:
            iam-jit org-policy verify \\\\
                --policy org-policy.yaml \\\\
                --sig org-policy.yaml.sig \\\\
                --pubkey org.pub

        See docs/CORP-MANAGED-DEPLOYMENT.md for the full step-by-step.
        """
        # Per [[creates-never-mutates]]: refuse to clobber without --overwrite.
        if signature_out_path.exists() and not overwrite:
            raise click.ClickException(
                f"refusing to overwrite existing {signature_out_path} "
                "(per [[creates-never-mutates]]). Pass --overwrite to replace."
            )

        # 1. Read policy bytes.
        try:
            policy_bytes = policy_yaml_path.read_bytes()
        except OSError as e:
            raise click.ClickException(
                f"could not read policy YAML at {policy_yaml_path}: {e}"
            ) from e

        if not policy_bytes:
            raise click.ClickException(
                f"policy YAML at {policy_yaml_path} is empty."
            )

        # 2. Read + parse private key.
        private_pem = _load_private_key_pem(private_key_path)

        # 3. Sign.
        raw_sig = _sign_policy_bytes(
            policy_bytes, private_pem, key_path=private_key_path,
        )

        # 4. Write base64-encoded signature to --out (matches the convention
        #    _fetch_managed_policy expects: base64-encoded raw bytes in the
        #    .sig companion URL — per #490 §A90).
        sig_b64 = base64.b64encode(raw_sig).decode("ascii")

        try:
            signature_out_path.parent.mkdir(parents=True, exist_ok=True)
            signature_out_path.write_text(sig_b64, encoding="ascii")
            try:
                signature_out_path.chmod(0o644)
            except Exception:
                pass
        except OSError as e:
            raise click.ClickException(
                f"could not write signature to {signature_out_path}: {e}"
            ) from e

        click.secho(
            f"OK  signature written to {signature_out_path}",
            fg="green",
        )
        click.echo(
            f"    policy:    {policy_yaml_path}  "
            f"({len(policy_bytes)} bytes)"
        )
        click.echo(
            f"    sig file:  {signature_out_path}"
        )
        click.echo(
            "    next:      run `iam-jit org-policy verify` to confirm, "
            "then publish both files to your HTTPS endpoint."
        )

    @org_policy_group.command("verify")
    @click.option(
        "--policy",
        "policy_path",
        required=True,
        type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
        help="Path to the org-policy YAML to verify.",
    )
    @click.option(
        "--sig",
        "sig_path",
        required=True,
        type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
        help="Path to the .sig file (base64-encoded raw Ed25519 signature).",
    )
    @click.option(
        "--pubkey",
        "pubkey_path",
        required=True,
        type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
        help="Path to the Ed25519 public key PEM or base64 file.",
    )
    def verify_org_policy(
        policy_path: pathlib.Path,
        sig_path: pathlib.Path,
        pubkey_path: pathlib.Path,
    ) -> None:
        """Verify an Ed25519-signed org-policy. Exits 0 if valid, 1 if not.

        Uses the same ``_verify_ed25519_signature`` helper that
        ``iam-jit init --managed`` uses (#490 §A90) — a passing local
        verify guarantees a passing engineer rollout. Run this before
        publishing the YAML + .sig to your HTTPS endpoint.

        Example:

        \\b
            iam-jit org-policy verify \\\\
                --policy org-policy.yaml \\\\
                --sig org-policy.yaml.sig \\\\
                --pubkey org.pub

        Exits 0 on success; 1 on signature mismatch or bad key.
        """
        # 1. Read policy bytes.
        try:
            policy_bytes = policy_path.read_bytes()
        except OSError as e:
            raise click.ClickException(
                f"could not read policy YAML at {policy_path}: {e}"
            ) from e

        # 2. Read + decode signature.
        try:
            sig_raw = sig_path.read_bytes()
        except OSError as e:
            raise click.ClickException(
                f"could not read .sig file at {sig_path}: {e}"
            ) from e

        try:
            sig_bytes = base64.b64decode(sig_raw.strip(), validate=True)
        except Exception as e:
            click.secho(
                f"INVALID  .sig file at {sig_path} is not valid base64: {e}",
                fg="red",
                err=True,
            )
            sys.exit(1)

        # 3. Read public key.
        try:
            pubkey_material = pubkey_path.read_text(encoding="ascii").strip()
        except OSError as e:
            raise click.ClickException(
                f"could not read public key at {pubkey_path}: {e}"
            ) from e

        if not pubkey_material:
            click.secho(
                f"INVALID  public key file at {pubkey_path} is empty.",
                fg="red",
                err=True,
            )
            sys.exit(1)

        # 4. Verify — reuse _verify_ed25519_signature from #490 so the
        #    local verify and the engineer-side init --managed pipeline
        #    share the same implementation.
        try:
            from .cli_init import ManagedPolicyError, _verify_ed25519_signature
        except ImportError as e:
            raise click.ClickException(
                f"internal import error: {e}"
            ) from e

        try:
            _verify_ed25519_signature(policy_bytes, sig_bytes, pubkey_material)
        except ManagedPolicyError as e:
            click.secho(
                f"INVALID  {e}",
                fg="red",
                err=True,
            )
            sys.exit(1)
        except Exception as e:
            click.secho(
                f"INVALID  unexpected error during verification: {e}",
                fg="red",
                err=True,
            )
            sys.exit(1)

        click.secho(
            f"OK  signature valid",
            fg="green",
        )
        click.echo(
            f"    policy:  {policy_path}  ({len(policy_bytes)} bytes)"
        )
        click.echo(
            f"    sig:     {sig_path}"
        )
        click.echo(
            f"    pubkey:  {pubkey_path}"
        )
        click.echo(
            "    Safe to publish both files to your HTTPS endpoint."
        )

    return org_policy_group


__all__ = ["register_org_policy_group"]
