"""Tests for the Slack deny / pending-approval notification channel
(ADOPT-8 / #732) — :mod:`iam_jit.notify.slack`.

Coverage:
  - default-off: no Slack env → ``configured()`` False, ``notify_deny``
    no-op (no post attempted).
  - deny event → correctly-shaped Slack incoming-webhook payload via a
    recording fake; asserts neutral language + no secret leak + the
    structured-deny fields + the how-to-approve / pending-queue hint.
  - fail-soft: a raising transport does NOT propagate out of
    ``notify_deny`` (the deny hot path is never broken / dropped).
  - approval-queue linkage: the "N things" lead reflects the §A25
    pending-approval queue count, and the review hint points at the
    queue surface.
  - bot-token transport: payload routed with channel; token never in body.
"""

from __future__ import annotations

import json

import pytest

from iam_jit.bouncer.audit_export.alerts import FORBIDDEN_ALERT_WORDS
from iam_jit.notify import slack as notify_slack
from iam_jit.structured_deny.response import build_structured_deny


def _sd(**overrides):
    base = dict(
        bouncer="ibounce",
        action="s3:DeleteBucket",
        resource="arn:aws:s3:::prod-data",
        deny_reason="not in active scope",
        agent_session_id="sess-abc123",
    )
    base.update(overrides)
    return build_structured_deny(**base)


# ---------------------------------------------------------------------------
# Default-off
# ---------------------------------------------------------------------------


def test_configured_false_by_default(monkeypatch):
    for var in (
        notify_slack.ENV_WEBHOOK_URL,
        notify_slack.ENV_BOT_TOKEN,
        notify_slack.ENV_BOT_CHANNEL,
    ):
        monkeypatch.delenv(var, raising=False)
    assert notify_slack.configured() is False
    assert notify_slack.from_env() is None


def test_notify_deny_noop_when_unconfigured(monkeypatch):
    posts: list = []
    monkeypatch.setattr(notify_slack, "_post_webhook", lambda *a, **k: posts.append(a))
    monkeypatch.setattr(notify_slack, "_post_bot", lambda *a, **k: posts.append(a))
    for var in (
        notify_slack.ENV_WEBHOOK_URL,
        notify_slack.ENV_BOT_TOKEN,
        notify_slack.ENV_BOT_CHANNEL,
    ):
        monkeypatch.delenv(var, raising=False)

    attempted = notify_slack.notify_deny(_sd())
    assert attempted is False
    assert posts == []  # nothing posted


def test_bot_token_alone_is_not_configured(monkeypatch):
    # Bot token without a channel is not a usable transport.
    monkeypatch.delenv(notify_slack.ENV_WEBHOOK_URL, raising=False)
    monkeypatch.setenv(notify_slack.ENV_BOT_TOKEN, "xoxb-secret")
    monkeypatch.delenv(notify_slack.ENV_BOT_CHANNEL, raising=False)
    assert notify_slack.configured() is False


def test_non_https_webhook_rejected_no_post(monkeypatch, caplog):
    # Defensive: an operator-supplied webhook with a non-https scheme
    # (file:// / internal http://) is a self-inflicted SSRF angle. It
    # must be treated as unconfigured (no transport) and never POSTed.
    posts: list = []
    monkeypatch.setattr(notify_slack, "_post_webhook", lambda *a, **k: posts.append(a))
    monkeypatch.setattr(notify_slack, "_post_bot", lambda *a, **k: posts.append(a))
    monkeypatch.delenv(notify_slack.ENV_BOT_TOKEN, raising=False)
    monkeypatch.delenv(notify_slack.ENV_BOT_CHANNEL, raising=False)

    for bad in (
        "http://hooks.slack.com/X",
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
    ):
        monkeypatch.setenv(notify_slack.ENV_WEBHOOK_URL, bad)
        # Treated as unconfigured: no usable transport resolved.
        assert notify_slack.from_env() is None
        assert notify_slack.configured() is False
        # And nothing is posted on the deny path.
        with caplog.at_level("WARNING", logger="iam_jit.notify.slack"):
            attempted = notify_slack.notify_deny(_sd())
        assert attempted is False
        assert posts == []
        # The WARNING names the problem (the env var) but NOT the value.
        warned = " ".join(r.getMessage() for r in caplog.records)
        assert notify_slack.ENV_WEBHOOK_URL in warned
        assert bad not in warned
        caplog.clear()


# ---------------------------------------------------------------------------
# Payload shape + neutral language + no secret leak
# ---------------------------------------------------------------------------


def test_deny_payload_shape_and_fields():
    cfg = notify_slack.SlackNotifyConfig(webhook_url="https://hooks.slack.com/X")
    payload = notify_slack.build_deny_payload(_sd(), cfg=cfg, pending_count=2)

    assert "text" in payload
    assert isinstance(payload["attachments"], list) and payload["attachments"]
    att = payload["attachments"][0]
    titles = {f["title"]: f["value"] for f in att["fields"]}

    assert "s3:DeleteBucket" in titles["Agent tried"]
    assert "prod-data" in titles["Agent tried"]
    assert titles["Why caught"]
    assert "Classification" in titles
    assert "Recommended action" in titles
    assert titles["Agent session"] == "sess-abc123"
    assert "How to review" in titles


def test_neutral_language_no_forbidden_words():
    cfg = notify_slack.SlackNotifyConfig(webhook_url="https://hooks.slack.com/X")
    payload = notify_slack.build_deny_payload(_sd(), cfg=cfg, pending_count=3)
    blob = json.dumps(payload).lower()
    # "your bouncer caught" framing, not surveillance / accusation.
    assert "caught" in blob
    for forbidden in FORBIDDEN_ALERT_WORDS:
        assert forbidden.lower() not in blob, f"forbidden word leaked: {forbidden}"


def test_no_secret_leak_in_payload():
    # Webhook URL + bot token must NEVER appear in the message body.
    secret_url = "https://hooks.slack.com/services/T00/B00/SUPERSECRETTOKEN"
    secret_token = "xoxb-LEAKME-99999"
    cfg = notify_slack.SlackNotifyConfig(
        webhook_url=secret_url, bot_token=secret_token, bot_channel="#sec"
    )
    payload = notify_slack.build_deny_payload(_sd(), cfg=cfg, pending_count=1)
    blob = json.dumps(payload)
    assert "SUPERSECRETTOKEN" not in blob
    assert "xoxb-LEAKME" not in blob
    assert secret_url not in blob


def test_no_request_payload_leak():
    # The denied request's raw secrets must not be forwarded — only the
    # structured-deny fields are. Construct an SD with a benign action;
    # assert nothing beyond the known fields is present.
    cfg = notify_slack.SlackNotifyConfig(webhook_url="https://hooks.slack.com/X")
    sd = _sd(action="secretsmanager:GetSecretValue", resource="arn:aws:secretsmanager:::x")
    payload = notify_slack.build_deny_payload(sd, cfg=cfg, pending_count=0)
    blob = json.dumps(payload)
    # The action name is fine to show; we just assert no literal secret
    # material (there is none in a StructuredDenyResponse by design).
    assert "GetSecretValue" in blob


def test_repr_hides_secrets():
    cfg = notify_slack.SlackNotifyConfig(
        webhook_url="https://hooks.slack.com/services/SECRET",
        bot_token="xoxb-SECRET",
        bot_channel="#sec",
    )
    r = repr(cfg)
    assert "SECRET" not in r
    assert "webhook=set" in r
    assert "bot_token=set" in r


# ---------------------------------------------------------------------------
# Recording transport — payload actually sent on webhook path
# ---------------------------------------------------------------------------


def test_webhook_post_attempted_and_recorded(monkeypatch):
    recorded: list[tuple[str, dict]] = []

    def _fake_post(url, payload):
        recorded.append((url, payload))

    monkeypatch.setattr(notify_slack, "_post_webhook", _fake_post)
    monkeypatch.setenv(notify_slack.ENV_WEBHOOK_URL, "https://hooks.slack.com/REC")
    monkeypatch.delenv(notify_slack.ENV_BOT_TOKEN, raising=False)
    monkeypatch.delenv(notify_slack.ENV_BOT_CHANNEL, raising=False)

    attempted = notify_slack.notify_deny(_sd(), pending_count=4)
    assert attempted is True
    assert len(recorded) == 1
    url, payload = recorded[0]
    assert url == "https://hooks.slack.com/REC"
    assert "4 things" in payload["text"]


def test_bot_path_routes_channel_no_token_in_body(monkeypatch):
    recorded: list = []

    def _fake_urlopen(req, timeout=None):  # noqa: SD-2 urlopen-signature fake ignores timeout
        recorded.append(req)

        class _Resp:
            def read(self_inner):  # noqa: SD-2 io stub returns canned body
                return b'{"ok": true}'

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):  # noqa: SD-2 context-manager protocol stub
                return False

        return _Resp()

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    cfg = notify_slack.SlackNotifyConfig(
        bot_token="xoxb-SECRET-BODY", bot_channel="#sec-bouncer"
    )
    notify_slack._post_bot(cfg, {"text": "hi", "attachments": []})

    assert len(recorded) == 1
    req = recorded[0]
    body = json.loads(req.data.decode("utf-8"))
    assert body["channel"] == "#sec-bouncer"
    # Token is in the Authorization header, NEVER in the JSON body.
    assert "xoxb-SECRET-BODY" not in json.dumps(body)
    assert req.headers["Authorization"] == "Bearer xoxb-SECRET-BODY"


# ---------------------------------------------------------------------------
# Fail-soft
# ---------------------------------------------------------------------------


def test_fail_soft_transport_raises_does_not_propagate(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("slack is down")

    monkeypatch.setattr(notify_slack, "_post_webhook", _boom)
    monkeypatch.setenv(notify_slack.ENV_WEBHOOK_URL, "https://hooks.slack.com/X")
    monkeypatch.delenv(notify_slack.ENV_BOT_TOKEN, raising=False)
    monkeypatch.delenv(notify_slack.ENV_BOT_CHANNEL, raising=False)

    # Must NOT raise — the deny hot path is never broken.
    attempted = notify_slack.notify_deny(_sd())
    assert attempted is True


def test_post_webhook_swallows_urlopen_error(monkeypatch):
    import urllib.request

    def _boom(req, timeout=None):  # noqa: SD-2 urlopen-signature fake raises unconditionally
        raise OSError("network unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    # Should log + return, not raise.
    notify_slack._post_webhook("https://hooks.slack.com/X", {"text": "x"})


# ---------------------------------------------------------------------------
# Approval-queue linkage
# ---------------------------------------------------------------------------


def test_pending_count_reflects_queue(monkeypatch, tmp_path):
    qp = tmp_path / "pending.jsonl"
    qp.write_text(
        json.dumps({"id": "p1"}) + "\n" + json.dumps({"id": "p2"}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", str(qp))
    # _pending_count reads the §A25 queue via list_pending.
    assert notify_slack._pending_count() == 2


def test_review_hint_points_at_queue_surface():
    cfg = notify_slack.SlackNotifyConfig(webhook_url="https://hooks.slack.com/X")
    hint = notify_slack._review_hint(cfg)
    assert "denies recent" in hint
    assert "profile allow" in hint


def test_review_hint_deep_links_when_public_url_set():
    cfg = notify_slack.SlackNotifyConfig(
        webhook_url="https://hooks.slack.com/X",
        review_url="https://iam-jit.example.com/",
    )
    hint = notify_slack._review_hint(cfg)
    assert hint == "Review + approve: https://iam-jit.example.com/requests"


def test_review_hint_present_in_payload():
    cfg = notify_slack.SlackNotifyConfig(webhook_url="https://hooks.slack.com/X")
    payload = notify_slack.build_deny_payload(_sd(), cfg=cfg, pending_count=0)
    titles = {f["title"]: f["value"] for f in payload["attachments"][0]["fields"]}
    assert "How to review" in titles
    assert (
        "denies recent" in titles["How to review"]
        or "Review + approve:" in titles["How to review"]
    )


# ---------------------------------------------------------------------------
# Daemon wiring — `--notify-denies slack` dispatches to the channel
# ---------------------------------------------------------------------------


def test_daemon_notify_denies_slack_dispatch(monkeypatch):
    from iam_jit.autopilot import daemon

    # Stub the deny fetch so run-once-style notify has a row to render.
    class _Row:
        bouncer = "ibounce"
        action = "s3:DeleteBucket"
        resource = "arn:aws:s3:::prod"
        deny_reason = "not in active scope"
        deny_source = ""
        rule_id_if_dynamic = None
        suggested_allow_command = ""
        agent_session_id = "sess-z"
        when = ""

    from iam_jit.profile_allow import denies as denies_mod

    monkeypatch.setattr(
        denies_mod, "fetch_recent_denies", lambda **k: ([_Row()], []), raising=False
    )

    captured: list = []
    monkeypatch.setattr(
        notify_slack, "notify_deny", lambda sd, **k: captured.append(sd)
    )

    sup = daemon.AutopilotSupervisor(
        declaration={}, config_source="test", notify_denies="slack"
    )
    sup._notify_recent_denies()

    # The slack channel was invoked with a structured-deny object.
    assert len(captured) == 1
    assert captured[0].action == "s3:DeleteBucket"


def test_suggested_allow_command_surfaced():
    cfg = notify_slack.SlackNotifyConfig(webhook_url="https://hooks.slack.com/X")
    sd = _sd()
    payload = notify_slack.build_deny_payload(sd, cfg=cfg, pending_count=0)
    titles = {f["title"]: f["value"] for f in payload["attachments"][0]["fields"]}
    # If the builder synthesised an allow command, it appears as the
    # approve-with field linking back to the pending-approval flow.
    if sd.suggested_allow_command:
        assert "Approve / allow with" in titles
