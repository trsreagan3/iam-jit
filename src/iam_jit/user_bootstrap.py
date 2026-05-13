"""First-admin bootstrap.

The chicken-and-egg problem: every write endpoint that adds a user
requires `Depends(require_admin)`, which requires being an admin user,
which requires already existing in the store. A fresh DynamoDB-backed
deployment is therefore unreachable until somebody seeds the first
admin. This module is that seeding step.

Behavior:
  - Reads `IAM_JIT_ADMIN_BOOTSTRAP_EMAIL` (or an explicit arg).
  - If the user already exists in the store, do nothing — the bootstrap
    has already happened. Operators can leave the env var in place
    forever; it never overrides an existing user record.
  - If the user does NOT exist, write them with `roles=[admin]`,
    `enabled=True`, and a `notes` field marking them as the
    bootstrap admin so it's auditable later.
  - All operations are best-effort: a transient DynamoDB error is
    logged and re-raised by the caller's choice. The Lambda startup
    path swallows so a bootstrap failure doesn't tip the entire
    function over.

Idempotency contract: calling `seed_bootstrap_admin` on the same store
twice with the same email is a no-op the second time. The bootstrap
email can also be safely changed mid-life — the previous bootstrap
record stays put with its existing role(s); the new email gets seeded
only if missing.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any

from .users_store import User, UserNotFound, UserStore


logger = logging.getLogger("iam_jit.bootstrap")


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


@dataclass(frozen=True)
class BootstrapResult:
    """Outcome of a single bootstrap call. Useful for one-line logs +
    audit emit."""

    seeded: bool
    user_id: str | None
    reason: str
    """One of: 'no_email_configured', 'invalid_email',
    'user_already_exists', 'seeded_admin', 'store_write_failed'."""


def _normalize_email(raw: str) -> str | None:
    if not isinstance(raw, str):
        return None
    candidate = raw.strip().lower()
    if not candidate or len(candidate) > 254:
        return None
    if "\n" in candidate or "\r" in candidate or "\x00" in candidate:
        return None
    if not _EMAIL_RE.match(candidate):
        return None
    return candidate


def seed_bootstrap_admin(
    store: UserStore,
    *,
    email: str | None = None,
    display_name: str | None = None,
) -> BootstrapResult:
    """Idempotently insert the first admin if missing.

    `email`: explicit override; defaults to `IAM_JIT_ADMIN_BOOTSTRAP_EMAIL`.
    `display_name`: optional friendly name; defaults to "Bootstrap Admin".

    Never raises — all errors collapse into a `BootstrapResult` with
    a non-success reason so the caller (Lambda startup, CLI) can log
    one line and move on.
    """
    raw_email = email if email is not None else os.environ.get(
        "IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", ""
    )
    safe = _normalize_email(raw_email or "")
    if not safe:
        if not raw_email:
            return BootstrapResult(
                seeded=False, user_id=None, reason="no_email_configured"
            )
        return BootstrapResult(
            seeded=False, user_id=None, reason="invalid_email"
        )

    user_id = f"email:{safe}"
    try:
        store.get(user_id)
        return BootstrapResult(
            seeded=False, user_id=user_id, reason="user_already_exists"
        )
    except UserNotFound:
        pass
    except Exception as e:
        logger.warning("bootstrap admin lookup failed: %s", e)
        return BootstrapResult(
            seeded=False, user_id=user_id, reason="store_read_failed"
        )

    record = User(
        id=user_id,
        roles=("admin",),
        enabled=True,
        display_name=display_name or "Bootstrap Admin",
        notes="seeded by IAM_JIT_ADMIN_BOOTSTRAP_EMAIL on first deploy",
    )
    try:
        store.put(record)
    except Exception as e:
        logger.warning("bootstrap admin write failed: %s", e)
        return BootstrapResult(
            seeded=False, user_id=user_id, reason="store_write_failed"
        )

    logger.info("bootstrap admin seeded: %s", user_id)
    return BootstrapResult(
        seeded=True, user_id=user_id, reason="seeded_admin"
    )


def maybe_seed_at_startup(store: UserStore | None) -> BootstrapResult:
    """Call from app startup. No-op when store is None or the env var
    isn't set. Designed to be safe to call on every cold-start of the
    Lambda — DynamoDB conditional writes would be even safer but a
    plain put_item is fine since we already check for existence."""
    if store is None:
        return BootstrapResult(
            seeded=False, user_id=None, reason="no_store_configured"
        )
    return seed_bootstrap_admin(store)


# ---------------------------------------------------------------------------
# Random-fallback bootstrap
# ---------------------------------------------------------------------------
#
# When the operator can't (or won't) configure an email — e.g. they're
# trying iam-jit out on a laptop and don't want to wire up SES — we
# generate a random admin user plus a one-time magic-link URL and
# write the URL to a state file the operator can `cat`. The operator
# opens the URL, gets a session cookie, adds real users via the UI,
# and (ideally) deletes the random bootstrap admin.
#
# This path is OFF by default. Three conditions must hold:
#   1. `IAM_JIT_ALLOW_RANDOM_BOOTSTRAP=1` is set (explicit opt-in).
#   2. `IAM_JIT_ADMIN_BOOTSTRAP_EMAIL` is unset (otherwise the email
#      path takes priority).
#   3. The user store is currently empty (so we don't trample an
#      existing deployment).
#
# Production-deployed (SAM) installs hit the CFN Rule's hard-stop
# before this path is reachable. The fallback only matters for local
# `iam-jit serve` users, who can opt in with one env var.


_RANDOM_FALLBACK_DOMAIN = "iam-jit.local"


@dataclass(frozen=True)
class RandomBootstrapResult:
    seeded: bool
    user_id: str | None
    sign_in_url: str | None
    written_to: str | None
    reason: str


def _store_has_any_user(store: UserStore) -> bool:
    try:
        return bool(store.list(include_disabled=True))
    except Exception:
        return False


def maybe_seed_random_at_startup(
    store: UserStore | None,
    *,
    public_url: str,
    secret: str,
    state_dir: str | None = None,
) -> RandomBootstrapResult:
    """If everything points at random-fallback, seed a random admin
    and write the sign-in URL to a state file.

    `public_url`  - base URL the operator will hit (`http://127.0.0.1:8000`
                    in dev). The magic-link is `<public_url>/auth/magic-callback?token=…`.
    `secret`      - the deployment's `IAM_JIT_MAGIC_LINK_SECRET`. Must
                    match what the running app verifies with.
    `state_dir`   - where to write `bootstrap-link.txt`. Defaults to
                    `$IAM_JIT_BOOTSTRAP_STATE_DIR`, then `/tmp`.
    """
    if os.environ.get("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP") not in {"1", "true", "yes"}:
        return RandomBootstrapResult(
            seeded=False, user_id=None, sign_in_url=None,
            written_to=None, reason="not_opted_in",
        )
    if os.environ.get("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL"):
        return RandomBootstrapResult(
            seeded=False, user_id=None, sign_in_url=None,
            written_to=None, reason="email_bootstrap_takes_precedence",
        )
    if store is None:
        return RandomBootstrapResult(
            seeded=False, user_id=None, sign_in_url=None,
            written_to=None, reason="no_store_configured",
        )
    if _store_has_any_user(store):
        return RandomBootstrapResult(
            seeded=False, user_id=None, sign_in_url=None,
            written_to=None, reason="store_already_has_users",
        )

    import pathlib
    import secrets as _secrets

    suffix = _secrets.token_hex(6)
    user_id = f"email:bootstrap-{suffix}@{_RANDOM_FALLBACK_DOMAIN}"
    record = User(
        id=user_id,
        roles=("admin",),
        enabled=True,
        display_name=f"Random Bootstrap Admin (delete after use)",
        notes=(
            "auto-generated random-fallback admin. After signing in, "
            "add a real admin via /admin/users and delete this record."
        ),
    )
    try:
        store.put(record)
    except Exception as e:
        logger.warning("random-bootstrap put failed: %s", e)
        return RandomBootstrapResult(
            seeded=False, user_id=user_id, sign_in_url=None,
            written_to=None, reason="store_write_failed",
        )

    # Mint the magic-link with the deployment's actual secret so the
    # callback verifies cleanly.
    from . import auth as auth_mod

    token = auth_mod.sign_magic_link(secret, user_id)
    sign_in_url = (
        f"{public_url.rstrip('/')}/auth/magic-callback?token={token}"
    )

    target_dir = pathlib.Path(
        state_dir
        or os.environ.get("IAM_JIT_BOOTSTRAP_STATE_DIR")
        or "/tmp"
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / "iam-jit-bootstrap-link.txt"
    body = (
        f"# iam-jit random-bootstrap link\n"
        f"# user: {user_id}\n"
        f"# valid for: 15 minutes (single-use)\n"
        f"#\n"
        f"# Open this URL in your browser to sign in as the\n"
        f"# auto-generated bootstrap admin. After signing in:\n"
        f"#   1. /admin/users — add a real admin (your email)\n"
        f"#   2. sign out, sign in as that real admin\n"
        f"#   3. /admin/users — delete this random bootstrap user\n"
        f"#\n"
        f"{sign_in_url}\n"
    )
    try:
        target_path.write_text(body)
        try:
            os.chmod(target_path, 0o600)
        except OSError:
            pass
    except Exception as e:
        logger.warning("random-bootstrap link-write failed: %s", e)
        # Fall back to logging it — operator can grep CloudWatch / stderr.
        logger.warning(
            "random-bootstrap sign-in URL (recover from logs): %s",
            sign_in_url,
        )
        return RandomBootstrapResult(
            seeded=True, user_id=user_id, sign_in_url=sign_in_url,
            written_to=None, reason="seeded_admin_link_in_logs_only",
        )

    return RandomBootstrapResult(
        seeded=True, user_id=user_id, sign_in_url=sign_in_url,
        written_to=str(target_path), reason="seeded_admin",
    )
