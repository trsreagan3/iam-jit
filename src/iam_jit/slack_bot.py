"""Slack interactive approval bot.

This module is iam-jit's Slack integration for approvals:
  - post approval-request messages to a configurable channel
  - verify interactive-component callbacks come from Slack
  - resolve the clicking Slack user → iam-jit User
  - hand the action off to the existing lifecycle.apply_transition
    (so the state machine + audit + idempotency stay single-sourced)

Configuration (env):
  IAM_JIT_SLACK_BOT_TOKEN          xoxb-... (required for posting + users.info)
  IAM_JIT_SLACK_SIGNING_SECRET     32-char secret from the Slack App config
  IAM_JIT_SLACK_APPROVAL_CHANNEL   default channel ID (e.g. C01234ABCDE)

The bot is the EXISTING notifications.SlackBackend's replacement for
interactive flows. Webhook-based one-way notifications still work
unchanged; the bot is added on top for approvals.

Security:
  - Signature verification per Slack spec
    (HMAC-SHA256 of `v0:<timestamp>:<body>` with the signing secret)
  - Timestamp replay window: 300s (Slack's recommended max)
  - The bot NEVER trusts the payload's `user.id` claim without
    verifying the signature first
  - Approver resolution: Slack user → email → iam-jit User. The
    iam-jit User's `approver` role is checked the same way as a
    web-API call.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Protocol

logger = logging.getLogger("iam_jit.slack_bot")


_REPLAY_WINDOW_SECONDS = 300  # Slack's documented max
_SLACK_API_BASE = "https://slack.com/api"


class SlackError(Exception):
    """Raised for any Slack-side failure (HTTP error, API error
    response, malformed payload). Always carries enough context for
    the audit log."""


class SignatureMismatch(SlackError):
    pass


class TimestampOutOfWindow(SlackError):
    pass


class UserNotApprover(SlackError):
    pass


class SlackUserUnresolvable(SlackError):
    """The Slack user clicking the button can't be mapped to any
    iam-jit User. Either the email isn't on the iam-jit user
    roster or Slack didn't surface the email."""


class WorkspaceMismatch(SlackError):
    """The interactive payload's `team.id` doesn't match the
    configured `IAM_JIT_SLACK_TEAM_ID`. WB8-03 closure: refuses
    cross-workspace forgery even with valid signature."""


class ChannelMismatch(SlackError):
    """The interactive payload's `channel.id` doesn't match the
    configured approval channel. WB8-04 closure: defense-in-depth
    against bot installed in additional channels."""


# ---------------------------------------------------------------------------
# Configuration.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SlackConfig:
    bot_token: str
    signing_secret: str
    approval_channel: str | None = None  # may be overridden per request
    # WB8-03 closure: optional workspace pin. When set, every
    # interactive callback must include `team.id == expected_team_id`
    # or it's rejected. Defends against a leaked signing secret
    # being used to forge clicks from a different Slack workspace.
    expected_team_id: str | None = None
    # WB8-04 closure: optional channel pin. When set, interactive
    # callbacks must come from this channel or the configured
    # approval_channel. Defense-in-depth; not directly exploitable
    # (approver-role check still runs) but reduces attack surface
    # if a bot is somehow added to other channels.
    expected_channel_id: str | None = None

    @classmethod
    def from_env(cls) -> SlackConfig | None:
        token = os.environ.get("IAM_JIT_SLACK_BOT_TOKEN", "").strip()
        secret = os.environ.get("IAM_JIT_SLACK_SIGNING_SECRET", "").strip()
        channel = os.environ.get("IAM_JIT_SLACK_APPROVAL_CHANNEL", "").strip() or None
        team_id = os.environ.get("IAM_JIT_SLACK_TEAM_ID", "").strip() or None
        if not token or not secret:
            return None
        return cls(
            bot_token=token,
            signing_secret=secret,
            approval_channel=channel,
            expected_team_id=team_id,
            # expected_channel_id defaults to approval_channel when set
            expected_channel_id=channel,
        )


# ---------------------------------------------------------------------------
# Signature verification.
# ---------------------------------------------------------------------------


def verify_signature(
    *,
    body: bytes,
    timestamp: str | None,
    signature: str | None,
    signing_secret: str,
    now: float | None = None,
    replay_window_seconds: int = _REPLAY_WINDOW_SECONDS,
) -> None:
    """Verify a Slack interactive-callback HMAC signature.

    Raises `SignatureMismatch` if the signature is missing or wrong;
    `TimestampOutOfWindow` if the request is too old (replay
    protection).

    Slack signs as `v0:<timestamp>:<raw-body>` with HMAC-SHA256 of
    the signing secret. The header `X-Slack-Signature` is
    `v0=<hex-digest>`.
    """
    if not signature or not timestamp:
        raise SignatureMismatch("missing X-Slack-Signature or X-Slack-Request-Timestamp")

    try:
        ts_int = int(timestamp)
    except ValueError as e:
        raise SignatureMismatch(f"non-integer timestamp: {timestamp!r}") from e

    current = now if now is not None else time.time()
    if abs(current - ts_int) > replay_window_seconds:
        raise TimestampOutOfWindow(
            f"timestamp {ts_int} outside replay window ({replay_window_seconds}s) of {int(current)}"
        )

    base = f"v0:{timestamp}:".encode("utf-8") + body
    expected = "v0=" + hmac.new(
        signing_secret.encode("utf-8"), base, hashlib.sha256
    ).hexdigest()
    # Constant-time compare — defeats timing oracles.
    if not hmac.compare_digest(expected, signature):
        raise SignatureMismatch("signature does not match")


# ---------------------------------------------------------------------------
# Block Kit message rendering.
# ---------------------------------------------------------------------------


def _escape_mrkdwn(s: str) -> str:
    """Escape user-influenced text per Slack's documented mrkdwn rules.

    Closes WB8-01 (HIGH) — Block Kit / mrkdwn injection via
    `spec.description` and other requester-influenced fields. Without
    this escape, an attacker requester could inject:

      <@USLACKBOT>                       → fake user mention
      <!channel>, <!here>                → channel-wide ping
      <!subteam^TEAMID>                  → group ping
      <https://attacker.example/|Approve> → fake link-text masquerading
                                            as the iam-jit "Approve" UI

    Slack's documented sanitization
    (https://api.slack.com/reference/surfaces/formatting#escaping):
      & → &amp;
      < → &lt;
      > → &gt;

    Order matters: `&` MUST be replaced first or we'd double-escape
    the entity references we just emitted.
    """
    if not isinstance(s, str):
        s = str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_approval_message(
    request: dict[str, Any],
    *,
    deployment_url: str | None = None,
) -> dict[str, Any]:
    """Render the iam-jit approval-request notification as a Slack
    Block Kit message body. Returns the `blocks` JSON ready to POST
    to chat.postMessage (with `channel` added by the caller).

    Buttons carry `value` strings of the form `<verb>:<request_id>`
    so the interactive callback can route on a single field.
    """
    request_id = request.get("id") or request.get("request_id") or "(unknown)"
    spec = request.get("spec") or {}
    status = request.get("status") or {}
    review = request.get("review") or {}

    requester = status.get("owner") or "(unknown)"
    description = spec.get("description") or "(no description)"
    access_type = spec.get("access_type") or "?"
    duration_hours = (spec.get("duration") or {}).get("duration_hours") or "?"
    accounts = spec.get("accounts") or []
    accounts_text = ", ".join(str(a) for a in accounts) if accounts else "(none)"

    risk_score = review.get("risk_score")
    risk_factors = review.get("risk_factors") or []
    score_text = f"{risk_score}/10" if risk_score is not None else "(not scored)"

    title_text = f":closed_lock_with_key: iam-jit approval needed — `{request_id}`"

    fields = [
        {"type": "mrkdwn", "text": f"*Requester*\n{requester}"},
        {"type": "mrkdwn", "text": f"*Score*\n{score_text}"},
        {"type": "mrkdwn", "text": f"*Access type*\n{access_type}"},
        {"type": "mrkdwn", "text": f"*Duration*\n{duration_hours}h"},
        {"type": "mrkdwn", "text": f"*Accounts*\n{accounts_text}"},
    ]

    # Requester-influenced fields go through _escape_mrkdwn to defuse
    # Block Kit / mrkdwn injection (WB8-01). Server-controlled fields
    # (request_id, score_text, access_type, duration_hours, accounts)
    # don't need escaping but it's cheap insurance — apply uniformly.
    safe_description = _escape_mrkdwn(description)

    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": "iam-jit approval needed"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": title_text}},
        {"type": "section", "fields": fields},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Reason*\n{safe_description}"}},
    ]

    if risk_factors:
        # Risk factors are scorer-generated today but the scorer
        # interpolates user-influenced policy text into some factor
        # strings (action names, resource ARNs, condition keys). Escape.
        safe_factors = [_escape_mrkdwn(str(f)) for f in risk_factors[:5]]
        factor_lines = "\n".join(f"• {f}" for f in safe_factors)
        if len(risk_factors) > 5:
            factor_lines += f"\n• … (+{len(risk_factors) - 5} more)"
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Risk factors*\n{factor_lines}"},
            }
        )

    actions: list[dict[str, Any]] = [
        {
            "type": "button",
            "style": "primary",
            "text": {"type": "plain_text", "text": "Approve"},
            "value": f"approve:{request_id}",
            "action_id": "iamjit_approve",
        },
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "Request changes"},
            "value": f"request_changes:{request_id}",
            "action_id": "iamjit_request_changes",
        },
        {
            "type": "button",
            "style": "danger",
            "text": {"type": "plain_text", "text": "Reject"},
            "value": f"reject:{request_id}",
            "action_id": "iamjit_reject",
        },
    ]
    if deployment_url:
        actions.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View in iam-jit"},
                "url": f"{deployment_url.rstrip('/')}/requests/{request_id}",
                "action_id": "iamjit_view",
            }
        )

    blocks.append({"type": "actions", "elements": actions})
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        ":information_source: Approve/Reject is gated by your "
                        "iam-jit `approver` role; clicks from non-approvers are rejected."
                    ),
                }
            ],
        }
    )

    return {"blocks": blocks, "text": f"iam-jit approval needed for {request_id}"}


# ---------------------------------------------------------------------------
# Interactive callback payload parsing.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class InteractiveAction:
    """One parsed interactive-component click."""

    verb: str  # "approve" | "reject"
    request_id: str
    clicker_slack_user_id: str
    clicker_slack_username: str | None
    response_url: str | None
    trigger_id: str | None


def validate_workspace_and_channel(
    payload_json: str,
    *,
    config: SlackConfig,
) -> None:
    """WB8-03 + WB8-04 closures.

    Verify the interactive callback's workspace (team.id) and
    channel.id match the configured deployment. Raises
    WorkspaceMismatch / ChannelMismatch on mismatch.

    Called AFTER signature verification but BEFORE parsing the
    action. A leaked signing secret would let an attacker forge a
    valid signature; team_id + channel_id checks bound the
    attacker to the configured Slack workspace + channel.

    When the corresponding env vars aren't set, the check is
    skipped (backward-compatible with single-workspace single-channel
    deployments that haven't opted in).
    """
    try:
        payload = json.loads(payload_json)
    except Exception as e:
        raise SlackError(f"interactive payload is not valid JSON: {e}") from e
    if not isinstance(payload, dict):
        raise SlackError("interactive payload is not a JSON object")

    if config.expected_team_id:
        team_id = ((payload.get("team") or {}).get("id") or "").strip()
        if team_id != config.expected_team_id:
            raise WorkspaceMismatch(
                f"team.id {team_id!r} does not match configured "
                f"IAM_JIT_SLACK_TEAM_ID"
            )

    if config.expected_channel_id:
        # block_actions has channel.id at top level; view_submission
        # may not include channel at all (modal submissions). Only
        # enforce when channel info is present in the payload.
        channel = payload.get("channel")
        if isinstance(channel, dict):
            channel_id = (channel.get("id") or "").strip()
            if channel_id and channel_id != config.expected_channel_id:
                raise ChannelMismatch(
                    f"channel.id {channel_id!r} does not match configured "
                    f"approval channel"
                )


def parse_interactive_payload(payload_json: str) -> InteractiveAction:
    """Parse the JSON Slack puts under the `payload` form field.

    Raises SlackError on any malformation. Pinned to the fields we
    actually use so an attacker who slipped past signature
    verification (e.g. via a leaked signing secret) can't smuggle
    surprises in unused fields."""
    try:
        payload = json.loads(payload_json)
    except Exception as e:
        raise SlackError(f"interactive payload is not valid JSON: {e}") from e

    if not isinstance(payload, dict):
        raise SlackError("interactive payload is not a JSON object")

    actions = payload.get("actions") or []
    if not actions:
        raise SlackError("interactive payload has no actions")

    action = actions[0]
    value = action.get("value") or ""
    if ":" not in value:
        raise SlackError(f"action value missing colon delimiter: {value!r}")
    verb, _, request_id = value.partition(":")
    verb = verb.strip().lower()
    request_id = request_id.strip()
    if verb not in {"approve", "reject", "request_changes"}:
        raise SlackError(f"unknown action verb: {verb!r}")
    if not request_id:
        raise SlackError("action value has no request_id")

    user = payload.get("user") or {}
    user_id = (user.get("id") or "").strip()
    if not user_id:
        raise SlackError("interactive payload has no user.id")
    username = user.get("username") or user.get("name") or None

    return InteractiveAction(
        verb=verb,
        request_id=request_id,
        clicker_slack_user_id=user_id,
        clicker_slack_username=username,
        response_url=payload.get("response_url"),
        trigger_id=payload.get("trigger_id"),
    )


# ---------------------------------------------------------------------------
# View-submission ("Request changes" modal) parsing.
# ---------------------------------------------------------------------------


_MAX_MODAL_TEXT_LEN = 2000
_MIN_MODAL_TEXT_LEN = 5


@dataclasses.dataclass(frozen=True)
class ViewSubmission:
    """One parsed `view_submission` from a Slack modal."""

    callback_id: str
    request_id: str
    submitter_slack_user_id: str
    submitter_slack_username: str | None
    text: str  # the approver's typed message (sanitized length)


def parse_view_submission(payload_json: str) -> ViewSubmission:
    """Parse a Slack `view_submission` payload from the modal.

    The modal is opened with `private_metadata=<request_id>` and a
    single plain-text input named `context_text`. Validation here
    rejects anything that doesn't fit that schema.
    """
    try:
        payload = json.loads(payload_json)
    except Exception as e:
        raise SlackError(f"view_submission payload invalid JSON: {e}") from e
    if not isinstance(payload, dict):
        raise SlackError("view_submission payload is not a JSON object")
    if payload.get("type") != "view_submission":
        raise SlackError(
            f"expected view_submission, got {payload.get('type')!r}"
        )

    view = payload.get("view") or {}
    if not isinstance(view, dict):
        raise SlackError("view_submission missing `view`")

    callback_id = view.get("callback_id") or ""
    if callback_id != "iamjit_request_changes_modal":
        raise SlackError(f"unexpected callback_id: {callback_id!r}")

    request_id = (view.get("private_metadata") or "").strip()
    if not request_id:
        raise SlackError("view_submission missing private_metadata (request_id)")

    user = payload.get("user") or {}
    user_id = (user.get("id") or "").strip()
    if not user_id:
        raise SlackError("view_submission missing user.id")
    username = user.get("username") or user.get("name") or None

    state_values = (view.get("state") or {}).get("values") or {}
    raw_text = ""
    for _block_id, block_state in state_values.items():
        elem = block_state.get("context_text") if isinstance(block_state, dict) else None
        if isinstance(elem, dict) and elem.get("type") == "plain_text_input":
            raw_text = elem.get("value") or ""
            break

    text = raw_text.strip()
    if len(text) < _MIN_MODAL_TEXT_LEN:
        raise SlackError(
            f"context text too short ({len(text)} chars; min {_MIN_MODAL_TEXT_LEN})"
        )
    if len(text) > _MAX_MODAL_TEXT_LEN:
        text = text[:_MAX_MODAL_TEXT_LEN]

    return ViewSubmission(
        callback_id=callback_id,
        request_id=request_id,
        submitter_slack_user_id=user_id,
        submitter_slack_username=username,
        text=text,
    )


def render_request_changes_modal(request_id: str) -> dict[str, Any]:
    """Build the Slack modal definition opened by 'Request changes'.

    The `private_metadata` carries the request_id so we know which
    request the modal applies to when the user submits. The
    `callback_id` is pinned in `parse_view_submission`.
    """
    return {
        "type": "modal",
        "callback_id": "iamjit_request_changes_modal",
        "private_metadata": request_id,
        "title": {"type": "plain_text", "text": "Request changes"},
        "submit": {"type": "plain_text", "text": "Send back"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"Asking the requester to refine `{request_id}` and resubmit.\n"
                        "Your message will be visible to them in iam-jit; keep it specific."
                    ),
                },
            },
            {
                "type": "input",
                "block_id": "context_block",
                "label": {
                    "type": "plain_text",
                    "text": "What needs to change?",
                },
                "element": {
                    "type": "plain_text_input",
                    "action_id": "context_text",
                    "multiline": True,
                    "max_length": _MAX_MODAL_TEXT_LEN,
                    "min_length": _MIN_MODAL_TEXT_LEN,
                    "placeholder": {
                        "type": "plain_text",
                        "text": (
                            "e.g. \"Scope to a single bucket\" / "
                            "\"Reduce duration to 1h\" / \"Add Condition for SourceVpce\""
                        ),
                    },
                },
            },
        ],
    }


def open_modal(
    *,
    trigger_id: str,
    view: dict[str, Any],
    config: SlackConfig,
    client: SlackHTTPClient | None = None,
) -> dict[str, Any]:
    """POST views.open to display a modal in response to a button click.

    Slack requires this within ~3 seconds of the triggering action.
    """
    cli = client or HttpxSlackClient()
    resp = cli.post_json(
        f"{_SLACK_API_BASE}/views.open",
        headers={
            "Authorization": f"Bearer {config.bot_token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        json_body={"trigger_id": trigger_id, "view": view},
    )
    if not resp.get("ok"):
        raise SlackError(f"views.open failed: {resp.get('error', resp)}")
    return resp


# ---------------------------------------------------------------------------
# Slack HTTP client (thin wrapper; designed to be mocked in tests).
# ---------------------------------------------------------------------------


class SlackHTTPClient(Protocol):
    """The methods we use. Lets tests inject a stub without monkeypatching httpx."""

    def post_json(self, url: str, *, headers: dict[str, str], json_body: dict[str, Any]) -> dict[str, Any]: ...

    def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]: ...


class HttpxSlackClient:
    """Production client backed by httpx."""

    name = "httpx"

    def post_json(
        self, url: str, *, headers: dict[str, str], json_body: dict[str, Any]
    ) -> dict[str, Any]:
        import httpx

        resp = httpx.post(url, headers=headers, json=json_body, timeout=10.0)
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            return {"ok": True, "raw": resp.text}

    def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]:
        import httpx

        resp = httpx.get(
            f"{_SLACK_API_BASE}/users.info",
            params={"user": user_id},
            headers={"Authorization": f"Bearer {bot_token}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Posting + user resolution.
# ---------------------------------------------------------------------------


def post_approval_message(
    *,
    request: dict[str, Any],
    config: SlackConfig,
    channel: str | None = None,
    client: SlackHTTPClient | None = None,
    deployment_url: str | None = None,
) -> dict[str, Any]:
    """Post the rendered approval-request message to Slack.

    Returns the Slack API response body. Raises SlackError on
    failure. Caller decides whether to swallow or propagate — a
    failing Slack post should NOT fail the underlying iam-jit
    request submission.
    """
    target_channel = channel or config.approval_channel
    if not target_channel:
        raise SlackError("no channel configured (set IAM_JIT_SLACK_APPROVAL_CHANNEL)")

    body = render_approval_message(request, deployment_url=deployment_url)
    body["channel"] = target_channel
    body["unfurl_links"] = False
    body["unfurl_media"] = False

    cli = client or HttpxSlackClient()
    resp = cli.post_json(
        f"{_SLACK_API_BASE}/chat.postMessage",
        headers={
            "Authorization": f"Bearer {config.bot_token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        json_body=body,
    )
    if not resp.get("ok"):
        raise SlackError(f"chat.postMessage failed: {resp.get('error', resp)}")
    return resp


def resolve_slack_user_to_email(
    slack_user_id: str,
    *,
    config: SlackConfig,
    client: SlackHTTPClient | None = None,
) -> str | None:
    """Look up the email of a Slack user. Returns None if Slack
    didn't surface an email (workspace policy, restricted user).

    The bot needs the `users:read.email` scope for this to work.
    """
    cli = client or HttpxSlackClient()
    try:
        resp = cli.get_user_info(slack_user_id, bot_token=config.bot_token)
    except Exception as e:
        logger.warning("users.info failed for %s: %s", slack_user_id, e)
        return None

    if not resp.get("ok"):
        logger.warning("users.info returned not-ok for %s: %s", slack_user_id, resp.get("error"))
        return None
    profile = (resp.get("user") or {}).get("profile") or {}
    email = profile.get("email")
    if not email:
        return None
    return str(email).strip().lower() or None


# ---------------------------------------------------------------------------
# Approver resolution (Slack click → iam-jit User).
# ---------------------------------------------------------------------------


class ApproverResolver:
    """Resolve a Slack user_id to an iam-jit User with `approver` role.

    Strategy:
      1. If the User store records a `slack_user_id` (custom field),
         match by that — deterministic, no Slack API call. NOT
         required; the customer can run without it.
      2. Otherwise call Slack `users.info` to get the email, look up
         the iam-jit User by that email.
      3. Verify the resolved User has the `approver` role AND is
         enabled.
    """

    def __init__(
        self,
        users_store: Any,  # UserStore protocol from users_store.py
        config: SlackConfig,
        client: SlackHTTPClient | None = None,
    ) -> None:
        self.users_store = users_store
        self.config = config
        self.client = client or HttpxSlackClient()

    def resolve(self, slack_user_id: str) -> Any:  # returns User
        # Try explicit mapping first (if the User model carries it).
        user = self._try_explicit_mapping(slack_user_id)
        if user is None:
            user = self._resolve_via_email(slack_user_id)
        if user is None:
            raise SlackUserUnresolvable(
                f"could not map Slack user {slack_user_id} to an iam-jit User "
                "(no explicit slack_user_id mapping found; no matching email)"
            )
        if not getattr(user, "enabled", True):
            raise UserNotApprover(f"iam-jit user {user.id} is disabled")
        roles = tuple(getattr(user, "roles", ()))
        if "approver" not in roles and "admin" not in roles:
            raise UserNotApprover(
                f"iam-jit user {user.id} has roles {roles!r}; approver role required"
            )
        return user

    def _try_explicit_mapping(self, slack_user_id: str) -> Any:
        """Look for a User whose record carries `slack_user_id == X`.

        We don't require the User model to have this field — most
        deployments won't. If `list()` or attribute access fails,
        fall back to email resolution.

        WB8-02 closure: collect ALL matching users and refuse if
        multiple match. Previously this returned the first match,
        which is storage-backend-ordering-dependent — two users
        accidentally configured with the same slack_user_id would
        result in a silent identity hijack (one wins; the other
        unknowingly can't act via Slack). Now we raise
        SlackUserUnresolvable explicitly so the admin notices.
        """
        try:
            matches = [
                u for u in self.users_store.list()  # type: ignore[union-attr]
                if getattr(u, "slack_user_id", None) == slack_user_id
            ]
        except Exception:
            return None
        if len(matches) > 1:
            ids = sorted(m.id for m in matches)
            raise SlackUserUnresolvable(
                f"ambiguous slack_user_id {slack_user_id!r}: "
                f"matches {len(matches)} iam-jit users ({', '.join(ids)}). "
                "Admin must ensure each Slack user maps to at most one "
                "iam-jit user. WB8-02 closure."
            )
        if matches:
            return matches[0]
        return None

    def _resolve_via_email(self, slack_user_id: str) -> Any:
        email = resolve_slack_user_to_email(
            slack_user_id, config=self.config, client=self.client
        )
        if not email:
            return None
        user_id = f"email:{email}"
        try:
            return self.users_store.get(user_id)
        except Exception:
            return None
