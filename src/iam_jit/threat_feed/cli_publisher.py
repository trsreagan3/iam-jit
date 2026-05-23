"""#409 / §A53 — ``iam-jit-feed-publish`` publisher CLI.

A separate entry point from the main ``iam-jit`` binary so the
publisher tooling doesn't accidentally surface in operator-only
deployments. Operators (verify side) use ``iam-jit updates ...``;
publishers (sign side) use ``iam-jit-feed-publish ...``.

Per [[push-policy-public-repo]] the CLI:

  * defaults the private-key path to
    ``~/.iam-jit/threat_feed/publisher.ed25519.pem``
  * REFUSES to print the private key in any subcommand output
  * writes the private key 0600
  * the SHORT-FORM PUBKEY (the only thing operators paste into
    their config) is printed to stdout on ``init`` so the publisher
    can copy-paste it

Per [[no-hosted-saas]] the tool never POSTs anywhere — the publisher
hosts their bundle.json wherever they like (S3, GitHub, internal
HTTP).
"""

from __future__ import annotations

import json
import pathlib
import sys

import click

from .publisher import (
    PublisherError,
    bundle_entries,
    publisher_init,
    sign_rule_file,
    verify_bundle,
    write_bundle,
)


_DEFAULT_KEY_DIR = pathlib.Path.home() / ".iam-jit" / "threat_feed"


@click.group(
    help=(
        "Publisher tooling for iam-jit threat-feed bundles. Sign + "
        "bundle + verify rule files. Operators consume the bundle via "
        "`iam-jit updates pin <url>`."
    ),
)
def main() -> None:
    """iam-jit-feed-publish — publisher tooling."""


@main.command("init")
@click.option(
    "--out-dir",
    type=click.Path(path_type=pathlib.Path),
    default=_DEFAULT_KEY_DIR,
    show_default=True,
    help="Directory to write keypair files into.",
)
@click.option(
    "--publisher",
    type=str,
    required=True,
    help="Publisher name (e.g. 'iam-jit-official'). Surfaces in "
         "every signed entry's signature.publisher field.",
)
@click.option(
    "--overwrite",
    is_flag=True,
    default=False,
    help="Overwrite an existing private key (rotation).",
)
@click.option("--json", "as_json", is_flag=True, default=False)
def init_cmd(
    out_dir: pathlib.Path,
    publisher: str,
    overwrite: bool,
    as_json: bool,
) -> None:
    """Generate a fresh Ed25519 publisher keypair."""
    try:
        res = publisher_init(
            out_dir=out_dir,
            publisher=publisher,
            overwrite=overwrite,
        )
    except PublisherError as e:
        click.secho(f"init failed: {e}", fg="red", err=True)
        sys.exit(2)
    if as_json:
        click.echo(json.dumps(res.as_dict(), indent=2))
        return
    click.secho("OK  publisher keypair created", fg="green")
    click.echo(f"  publisher:       {res.publisher}")
    click.echo(f"  private (0600):  {res.private_pem_path}")
    click.echo(f"  public PEM:      {res.public_pem_path}")
    click.echo(f"  short form:      {res.public_short_path}")
    click.echo("")
    click.echo("  Distribute the SHORT-FORM PUBKEY below to operators")
    click.echo("  (they paste it into .iam-jit.yaml threat_feed.feeds[].publisher_pubkey):")
    click.echo("")
    click.echo(f"    {res.short_form_pubkey}")


@main.command("sign")
@click.argument(
    "rule_file",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
@click.option(
    "--key",
    "private_key_path",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
    default=_DEFAULT_KEY_DIR / "publisher.ed25519.pem",
    show_default=True,
    help="Path to publisher private key PEM.",
)
@click.option(
    "--publisher",
    type=str,
    required=True,
    help="Publisher name embedded in the signature block.",
)
@click.option(
    "--key-id",
    type=str,
    default="",
    help="Optional opaque key identifier (for multi-key publishers).",
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(path_type=pathlib.Path),
    default=None,
    help="Write signed entry JSON here. Default: stdout.",
)
def sign_cmd(
    rule_file: pathlib.Path,
    private_key_path: pathlib.Path,
    publisher: str,
    key_id: str,
    out_path: pathlib.Path | None,
) -> None:
    """Sign one rule file (JSON or YAML) → signed entry JSON."""
    try:
        private_pem = private_key_path.read_text(encoding="utf-8")
        signed = sign_rule_file(
            rule_file,
            private_key_pem=private_pem,
            publisher=publisher,
            key_id=key_id,
        )
    except (PublisherError, OSError) as e:
        click.secho(f"sign failed: {e}", fg="red", err=True)
        sys.exit(2)
    rendered = json.dumps(signed.as_dict(), indent=2, sort_keys=True)
    if out_path:
        out_path.write_text(rendered)
        click.secho(f"OK  signed entry written to {out_path}", fg="green")
    else:
        click.echo(rendered)


@main.command("bundle")
@click.argument(
    "entry_files",
    nargs=-1,
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
@click.option(
    "--feed-id",
    type=str,
    required=True,
    help="Stable id for the bundle (e.g. 'iam-jit-official-v1').",
)
@click.option(
    "--publisher",
    type=str,
    required=True,
    help="Publisher name (matches what each entry was signed with).",
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(path_type=pathlib.Path),
    required=True,
    help="Path to write the feed bundle JSON.",
)
def bundle_cmd(
    entry_files: tuple[pathlib.Path, ...],
    feed_id: str,
    publisher: str,
    out_path: pathlib.Path,
) -> None:
    """Bundle N signed-entry JSON files into one feed.json."""
    if not entry_files:
        click.secho("bundle: at least one entry file required", fg="red", err=True)
        sys.exit(2)
    entries = []
    for ef in entry_files:
        try:
            from .models import parse_feed_entry
            raw = json.loads(ef.read_text(encoding="utf-8"))
            entries.append(parse_feed_entry(raw))
        except Exception as e:
            click.secho(f"bundle: failed to parse {ef}: {e}", fg="red", err=True)
            sys.exit(2)
    feed = bundle_entries(
        entries,
        feed_id=feed_id,
        publisher=publisher,
    )
    path = write_bundle(feed, out_path)
    click.secho(
        f"OK  bundle written: {path}  "
        f"({len(feed.entries)} entries, "
        f"sha256={feed.manifest_sha256[:12]}...)",
        fg="green",
    )


@main.command("verify")
@click.argument(
    "bundle_file",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
@click.option(
    "--pubkey",
    type=str,
    required=True,
    help="Publisher pubkey (ed25519:<b64> short-form OR PEM path "
         "OR raw PEM contents).",
)
@click.option("--json", "as_json", is_flag=True, default=False)
def verify_cmd(
    bundle_file: pathlib.Path,
    pubkey: str,
    as_json: bool,
) -> None:
    """Verify every entry in a bundle against a pinned pubkey."""
    # Allow --pubkey to be a path to a PEM.
    pk = pubkey
    pkp = pathlib.Path(pubkey).expanduser()
    if pkp.exists() and pkp.is_file():
        try:
            pk = pkp.read_text(encoding="utf-8")
        except OSError:
            pass
    result = verify_bundle(bundle_file, pubkey=pk)
    if as_json:
        click.echo(json.dumps(result.as_dict(), indent=2))
        sys.exit(0 if result.all_verified else 1)
    if result.all_verified:
        click.secho(
            f"OK  all {result.verified} entries verified "
            f"(feed_id={result.feed_id}, publisher={result.publisher})",
            fg="green",
        )
        sys.exit(0)
    click.secho(
        f"FAIL  {result.failed}/{result.entry_count} entries failed "
        f"verification:",
        fg="red",
        err=True,
    )
    for rid, reason in result.failures:
        click.echo(f"  - {rid}: {reason}", err=True)
    sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
