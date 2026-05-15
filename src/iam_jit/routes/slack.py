"""Slack interactive-callback route.

POST /api/v1/slack/interactive

Slack POSTs application/x-www-form-urlencoded with a single field
`payload` containing JSON. The flow:

  1. Verify the request actually came from Slack (HMAC over raw body
     using the signing secret + replay-window check).
  2. Parse the payload.
  3. Resolve the clicking Slack user → iam-jit User; check they have
     the `approver` (or `admin`) role.
  4. Apply the state transition via the shared
     `lifecycle.apply_transition` — same path the web API uses, so
     state-machine rules + audit are single-sourced.
  5. Return an updated message body that Slack uses to replace the
     in-channel message (showing who approved/rejected).

Anything that fails — signature mismatch, expired timestamp, user
not an approver, request not in pending — returns a 4xx with a
short reason. We do NOT echo internal IDs or error stacks to the
caller (which is Slack, which displays them to channel members).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from .. import lifecycle, slack_bot
from ..users_store import User

logger = logging.getLogger("iam_jit.routes.slack")

router = APIRouter(prefix="/api/v1/slack", tags=["slack"])


def _slack_config_or_503() -> slack_bot.SlackConfig:
    cfg = slack_bot.SlackConfig.from_env()
    if cfg is None:
        # The route is enabled but the deployment isn't configured.
        # Return 503 so the operator sees a clear "feature off" rather
        # than a confusing 401/500.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Slack integration not configured on this deployment.",
        )
    return cfg


@router.post(
    "/interactive",
    # We DO NOT use FastAPI's automatic body parsing — we need the
    # raw bytes for signature verification BEFORE parsing.
)
async def slack_interactive(request: Request) -> dict[str, Any]:
    config = _slack_config_or_503()

    raw_body = await request.body()
    timestamp = request.headers.get("x-slack-request-timestamp")
    signature = request.headers.get("x-slack-signature")

    try:
        slack_bot.verify_signature(
            body=raw_body,
            timestamp=timestamp,
            signature=signature,
            signing_secret=config.signing_secret,
        )
    except slack_bot.TimestampOutOfWindow as e:
        logger.warning("slack interactive: timestamp out of window: %s", e)
        raise HTTPException(status_code=401, detail="request expired")
    except slack_bot.SignatureMismatch as e:
        logger.warning("slack interactive: signature mismatch: %s", e)
        raise HTTPException(status_code=401, detail="invalid signature")

    # Slack sends form-urlencoded with a single `payload` field.
    try:
        form = await _parse_form_urlencoded(raw_body)
    except Exception as e:
        logger.warning("slack interactive: malformed form body: %s", e)
        raise HTTPException(status_code=400, detail="malformed body")

    payload_json = form.get("payload")
    if not payload_json:
        raise HTTPException(status_code=400, detail="missing payload field")

    # Workspace + channel pinning. WB8-03 + WB8-04 closures. When
    # the corresponding env vars are configured, the callback's
    # team.id and channel.id are verified. Defends against a leaked
    # signing secret being used to forge clicks from a different
    # Slack workspace or channel.
    try:
        slack_bot.validate_workspace_and_channel(payload_json, config=config)
    except slack_bot.WorkspaceMismatch as e:
        logger.warning("slack interactive: workspace mismatch: %s", e)
        raise HTTPException(status_code=401, detail="workspace mismatch")
    except slack_bot.ChannelMismatch as e:
        logger.warning("slack interactive: channel mismatch: %s", e)
        raise HTTPException(status_code=403, detail="channel not allowed")
    except slack_bot.SlackError as e:
        logger.warning("slack interactive: malformed payload during validation: %s", e)
        raise HTTPException(status_code=400, detail="malformed payload")

    # Detect view_submission vs block_actions BEFORE strict parsing
    # so we can route to the modal-submission handler.
    try:
        _peek = json.loads(payload_json)
        payload_type = _peek.get("type") if isinstance(_peek, dict) else None
    except Exception:
        raise HTTPException(status_code=400, detail="malformed payload")

    if payload_type == "view_submission":
        return await _handle_view_submission(
            payload_json=payload_json, request=request, config=config,
        )

    try:
        action = slack_bot.parse_interactive_payload(payload_json)
    except slack_bot.SlackError as e:
        logger.warning("slack interactive: bad payload: %s", e)
        raise HTTPException(status_code=400, detail="malformed payload")

    # Handle the "Request changes" button click by opening a modal.
    # We still verify the clicker is an approver BEFORE opening the
    # modal — otherwise anyone in the channel could open it.
    if action.verb == "request_changes":
        return await _handle_request_changes_button(
            action=action, request=request, config=config,
        )

    # Resolve Slack user → iam-jit User (must be approver/admin).
    user_store = getattr(request.app.state, "user_store", None)
    if user_store is None:
        logger.error("slack interactive: user_store not on app.state")
        raise HTTPException(status_code=500, detail="server misconfigured")

    resolver = slack_bot.ApproverResolver(user_store, config)
    try:
        actor = resolver.resolve(action.clicker_slack_user_id)
    except slack_bot.UserNotApprover as e:
        logger.info(
            "slack interactive: clicker %s is not an approver: %s",
            action.clicker_slack_user_id,
            e,
        )
        return _ephemeral_reply(
            f"You don't have the `approver` role in iam-jit, so this "
            f"action was rejected. Talk to an admin if you think this "
            f"is wrong. (request `{action.request_id}` is unchanged)"
        )
    except slack_bot.SlackUserUnresolvable as e:
        logger.info(
            "slack interactive: could not resolve Slack user %s: %s",
            action.clicker_slack_user_id,
            e,
        )
        return _ephemeral_reply(
            "Your Slack account isn't mapped to an iam-jit user. Have an admin "
            "register you in iam-jit using your work email."
        )

    # Look up the request + apply the transition.
    request_store = getattr(request.app.state, "request_store", None)
    if request_store is None:
        logger.error("slack interactive: request_store not on app.state")
        raise HTTPException(status_code=500, detail="server misconfigured")

    try:
        req = request_store.get(action.request_id)
    except Exception:
        return _ephemeral_reply(
            f"Request `{action.request_id}` not found. It may have been "
            "cancelled or expired before you clicked."
        )

    # Map verb → lifecycle action. `request_changes` already handled
    # above; remaining verbs are approve / reject.
    verb_to_action = {"approve": "approve", "reject": "reject"}
    try:
        result = lifecycle.apply_transition(
            req,
            action=verb_to_action[action.verb],
            actor=actor,
            reason=(
                f"via Slack by {action.clicker_slack_username or actor.id}"
            ),
            extra={
                "channel": "slack",
                "slack_user_id": action.clicker_slack_user_id,
                "slack_username": action.clicker_slack_username,
            },
        )
    except lifecycle.IllegalTransition as e:
        # E.g. someone clicked Approve after another approver already
        # acted. Common race; return a clean message.
        return _ephemeral_reply(
            f"Couldn't {action.verb} `{action.request_id}`: {e}. "
            "(Likely someone else already acted on it.)"
        )
    except lifecycle.NotAuthorized as e:
        logger.warning("slack interactive: apply_transition NotAuthorized: %s", e)
        return _ephemeral_reply(
            "iam-jit refused this action — you do not have the role "
            "required for this transition."
        )

    # Persist the mutated request.
    try:
        request_store.put(action.request_id, req)
    except Exception as e:
        logger.exception("slack interactive: failed to persist request: %s", e)
        raise HTTPException(status_code=500, detail="failed to persist transition")

    # Return a message that Slack will use to UPDATE the original
    # in-channel message (replaces buttons with a completion status).
    return _completion_message(
        request_id=action.request_id,
        verb=action.verb,
        actor=actor,
        slack_user_id=action.clicker_slack_user_id,
        slack_username=action.clicker_slack_username,
        result_state=result.new_state,
    )


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


async def _parse_form_urlencoded(raw: bytes) -> dict[str, str]:
    """Parse form-urlencoded body. We can't use FastAPI's Form()
    here because we've already consumed the body for signature
    verification."""
    from urllib.parse import parse_qs

    decoded = raw.decode("utf-8", errors="replace")
    parsed = parse_qs(decoded, keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items() if v}


def _ephemeral_reply(text: str) -> dict[str, Any]:
    """Build a payload Slack interprets as an ephemeral reply
    (visible only to the clicker, doesn't update the channel
    message). Used for "you can't do that" responses where we don't
    want to broadcast the rejection to everyone in the channel.
    """
    return {
        "response_type": "ephemeral",
        "replace_original": False,
        "text": text,
    }


async def _handle_request_changes_button(
    *,
    action: slack_bot.InteractiveAction,
    request: Request,
    config: slack_bot.SlackConfig,
) -> dict[str, Any]:
    """Open the modal that collects the approver's "what needs to change" message."""
    # Authorization: only approvers/admins can ask for changes.
    user_store = getattr(request.app.state, "user_store", None)
    if user_store is None:
        logger.error("slack interactive: user_store not on app.state")
        raise HTTPException(status_code=500, detail="server misconfigured")

    resolver = slack_bot.ApproverResolver(user_store, config)
    try:
        resolver.resolve(action.clicker_slack_user_id)
    except slack_bot.UserNotApprover:
        return _ephemeral_reply(
            "You don't have the `approver` role in iam-jit. Only approvers "
            "can request changes."
        )
    except slack_bot.SlackUserUnresolvable:
        return _ephemeral_reply(
            "Your Slack account isn't mapped to an iam-jit user. Have an admin "
            "register you in iam-jit using your work email."
        )

    if not action.trigger_id:
        return _ephemeral_reply(
            "Couldn't open the modal — Slack didn't supply a trigger_id."
        )

    try:
        view = slack_bot.render_request_changes_modal(action.request_id)
        slack_bot.open_modal(
            trigger_id=action.trigger_id, view=view, config=config,
        )
    except slack_bot.SlackError as e:
        logger.warning("views.open failed: %s", e)
        return _ephemeral_reply(
            "Couldn't open the modal — Slack rejected our views.open call."
        )

    # Empty 200 — Slack expects this when the action just opens a modal.
    return {"ok": True}


async def _handle_view_submission(
    *,
    payload_json: str,
    request: Request,
    config: slack_bot.SlackConfig,
) -> dict[str, Any]:
    """Handle the modal submission for 'Request changes'."""
    try:
        submission = slack_bot.parse_view_submission(payload_json)
    except slack_bot.SlackError as e:
        logger.warning("view_submission parse failed: %s", e)
        # Slack expects an `errors` response to display inside the modal
        # rather than closing it; surface the error at the input field.
        return {
            "response_action": "errors",
            "errors": {"context_block": str(e)[:150] or "Invalid submission"},
        }

    user_store = getattr(request.app.state, "user_store", None)
    request_store = getattr(request.app.state, "request_store", None)
    if user_store is None or request_store is None:
        logger.error("view_submission: stores not on app.state")
        raise HTTPException(status_code=500, detail="server misconfigured")

    resolver = slack_bot.ApproverResolver(user_store, config)
    try:
        actor = resolver.resolve(submission.submitter_slack_user_id)
    except slack_bot.UserNotApprover:
        return {
            "response_action": "errors",
            "errors": {"context_block": "You don't have the approver role."},
        }
    except slack_bot.SlackUserUnresolvable:
        return {
            "response_action": "errors",
            "errors": {"context_block": "Your Slack account isn't mapped to iam-jit."},
        }

    try:
        req = request_store.get(submission.request_id)
    except Exception:
        return {
            "response_action": "errors",
            "errors": {
                "context_block": f"Request {submission.request_id} not found."
            },
        }

    try:
        lifecycle.apply_transition(
            req,
            action="request_changes",
            actor=actor,
            reason=submission.text,
            extra={
                "channel": "slack",
                "slack_user_id": submission.submitter_slack_user_id,
                "slack_username": submission.submitter_slack_username,
                "modal_text_length": len(submission.text),
            },
        )
    except lifecycle.IllegalTransition as e:
        return {
            "response_action": "errors",
            "errors": {"context_block": f"{e}"[:150]},
        }
    except lifecycle.NotAuthorized:
        return {
            "response_action": "errors",
            "errors": {
                "context_block": "iam-jit refused this action — missing role."
            },
        }

    try:
        request_store.put(submission.request_id, req)
    except Exception as e:
        logger.exception("view_submission: failed to persist: %s", e)
        raise HTTPException(status_code=500, detail="failed to persist transition")

    # Empty 200 dict closes the modal cleanly.
    return {}


def _completion_message(
    *,
    request_id: str,
    verb: str,
    actor: User,
    slack_user_id: str,
    slack_username: str | None,
    result_state: str,
) -> dict[str, Any]:
    """Build the message body Slack uses to REPLACE the original
    approval-request message in-channel after a successful action.
    """
    emoji = ":white_check_mark:" if verb == "approve" else ":x:"
    verb_past = "approved" if verb == "approve" else "rejected"
    who = f"<@{slack_user_id}>" if slack_user_id else (slack_username or actor.id)
    return {
        "replace_original": True,
        "text": f"iam-jit request {request_id} {verb_past} by {who}",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *Request `{request_id}` {verb_past}*  ·  "
                        f"by {who}  ·  state → `{result_state}`"
                    ),
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"Audit row written. iam-jit user: `{actor.id}`."
                        ),
                    }
                ],
            },
        ],
    }
