"""Mock Slack API server for local dev + CI E2E testing.

Implements just enough of Slack's Web API to exercise iam-jit's
Slack-bot integration end-to-end without hitting Slack itself
(no ngrok, no workspace, no bot tokens with real scopes).

Endpoints implemented:
  - POST /api/chat.postMessage      → records call, returns {ok, ts, channel}
  - POST /api/chat.update           → records call, returns {ok, ts, channel}
  - POST /api/views.open            → records call, returns {ok, view: {...}}
  - GET  /api/users.info            → returns a profile from the in-memory directory
  - POST /api/auth.test             → returns {ok, team, user, bot_id} for doctor

Two ways to use:

  (1) **As a pytest fixture** — `MockSlackServer.build()` returns a
      FastAPI app + an event log + a directory you can populate from
      tests. Mount it under `httpx.MockTransport` or run it on a
      real localhost port and point `_SLACK_API_BASE` at it.

  (2) **As a standalone process** — `iam-jit dev-slack-mock` runs
      this on a port. Useful when manually testing the bot from a
      laptop without standing up ngrok + a real workspace.

The mock is intentionally permissive: any bot_token is accepted,
signing-secret verification is NOT performed on outbound calls, and
all messages are echoed back ok=True unless the test explicitly
configures a failure for the next call. The point is to exercise
the iam-jit code path, not Slack's full state machine.
"""

from __future__ import annotations

import dataclasses
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request


@dataclasses.dataclass
class SlackCall:
    """One recorded API call against the mock."""

    method: str
    url: str
    bot_token: str | None
    headers: dict[str, str]
    json_body: dict[str, Any] | None
    query_params: dict[str, str]
    ts: float


@dataclasses.dataclass
class MockSlackUser:
    id: str
    email: str
    name: str
    team_id: str = "T_MOCK"
    is_bot: bool = False


@dataclasses.dataclass
class MockSlackServer:
    """Holds the FastAPI app + the test-controllable state."""

    app: FastAPI
    calls: list[SlackCall] = dataclasses.field(default_factory=list)
    users_by_id: dict[str, MockSlackUser] = dataclasses.field(default_factory=dict)
    # If set, the next chat.postMessage / chat.update / views.open
    # call returns {ok: false, error: <value>} instead of the success
    # shape. Useful for testing iam-jit's error-handling path.
    fail_next_with_error: str | None = None
    # Auto-assigned message timestamps. The bot reads these from
    # the response and uses them as `slack_ts` in audit records.
    next_ts_seed: int = 1_000_000_000

    @classmethod
    def build(cls) -> "MockSlackServer":
        app = FastAPI(title="iam-jit mock Slack")
        server = cls(app=app)

        def _record(req: Request, json_body: dict[str, Any] | None) -> SlackCall:
            # WB11-15 closure: mask the bearer token in the recorded
            # call so a captured SlackCall list doesn't leak raw
            # tokens via test logs / CI artifacts. Tests that need
            # to assert "the right token was used" can match on the
            # masked prefix (first 8 chars + ellipsis).
            auth = req.headers.get("authorization", "")
            raw_token = auth[7:] if auth.lower().startswith("bearer ") else None
            masked: str | None = None
            if raw_token:
                masked = raw_token[:8] + "…" if len(raw_token) > 8 else "…"
            call = SlackCall(
                method=req.method,
                url=str(req.url.path),
                bot_token=masked,
                headers={k: v for k, v in req.headers.items() if not k.lower().startswith("authorization")},
                json_body=json_body,
                query_params=dict(req.query_params),
                ts=time.time(),
            )
            server.calls.append(call)
            return call

        def _next_ts() -> str:
            server.next_ts_seed += 1
            # Slack ts is `seconds.microseconds` as a string.
            return f"{server.next_ts_seed}.000100"

        def _maybe_fail() -> dict[str, Any] | None:
            if server.fail_next_with_error:
                err = server.fail_next_with_error
                server.fail_next_with_error = None
                return {"ok": False, "error": err}
            return None

        @app.post("/api/chat.postMessage")
        async def chat_post_message(req: Request) -> dict[str, Any]:
            body = await req.json()
            _record(req, body)
            if (failure := _maybe_fail()) is not None:
                return failure
            channel = body.get("channel") or "C_DEFAULT"
            ts = _next_ts()
            return {
                "ok": True,
                "channel": channel,
                "ts": ts,
                "message": {
                    "ts": ts,
                    "text": body.get("text", ""),
                    "blocks": body.get("blocks", []),
                },
            }

        @app.post("/api/chat.update")
        async def chat_update(req: Request) -> dict[str, Any]:
            body = await req.json()
            _record(req, body)
            if (failure := _maybe_fail()) is not None:
                return failure
            return {
                "ok": True,
                "channel": body.get("channel"),
                "ts": body.get("ts"),
                "text": body.get("text", ""),
            }

        @app.post("/api/views.open")
        async def views_open(req: Request) -> dict[str, Any]:
            body = await req.json()
            _record(req, body)
            if (failure := _maybe_fail()) is not None:
                return failure
            return {
                "ok": True,
                "view": {
                    "id": f"V_{server.next_ts_seed}",
                    "type": "modal",
                    "callback_id": (body.get("view") or {}).get(
                        "callback_id", "iam_jit_changes"
                    ),
                },
            }

        @app.get("/api/users.info")
        async def users_info(req: Request) -> dict[str, Any]:
            _record(req, None)
            user_id = req.query_params.get("user", "")
            user = server.users_by_id.get(user_id)
            if user is None:
                return {"ok": False, "error": "user_not_found"}
            return {
                "ok": True,
                "user": {
                    "id": user.id,
                    "team_id": user.team_id,
                    "name": user.name,
                    "real_name": user.name,
                    "profile": {"email": user.email},
                    "is_bot": user.is_bot,
                },
            }

        @app.post("/api/auth.test")
        async def auth_test(req: Request) -> dict[str, Any]:
            try:
                body = await req.json()
            except Exception:
                body = None
            _record(req, body)
            return {
                "ok": True,
                "url": "https://iam-jit-mock.slack.local/",
                "team": "iam-jit-mock-team",
                "user": "iam-jit-bot",
                "team_id": "T_MOCK",
                "user_id": "U_MOCKBOT",
                "bot_id": "B_MOCKBOT",
            }

        return server

    def add_user(
        self,
        *,
        slack_id: str,
        email: str,
        name: str | None = None,
    ) -> MockSlackUser:
        user = MockSlackUser(
            id=slack_id, email=email, name=name or email.split("@")[0],
        )
        self.users_by_id[slack_id] = user
        return user

    def reset(self) -> None:
        self.calls.clear()
        self.users_by_id.clear()
        self.fail_next_with_error = None
        self.next_ts_seed = 1_000_000_000

    def find_calls(self, url_suffix: str) -> list[SlackCall]:
        """Return calls whose path ends with the given suffix.

        Useful for asserting "did chat.postMessage get called?"
        without worrying about path prefixes.
        """
        return [c for c in self.calls if c.url.endswith(url_suffix)]


# ---------------------------------------------------------------------------
# Standalone CLI runner.
# ---------------------------------------------------------------------------


def run_standalone(*, host: str = "127.0.0.1", port: int = 8766) -> int:
    """Run the mock as a standalone HTTP server on (host, port).

    Use this when manually testing the bot from a laptop: point
    iam-jit's slack_bot._SLACK_API_BASE at http://127.0.0.1:8766/api
    (or set the env var below if/when the constant is parameterised)
    and the bot's outbound calls will land here instead of Slack.
    """
    import uvicorn

    server = MockSlackServer.build()
    # Add a couple of sample users so users.info works out of the box.
    server.add_user(slack_id="U_ALICE", email="alice@example.com", name="alice")
    server.add_user(slack_id="U_BOB", email="bob@example.com", name="bob")

    print(f"iam-jit mock Slack server")
    print(f"  Listening on http://{host}:{port}")
    print(f"  Endpoints:")
    print(f"    POST /api/chat.postMessage")
    print(f"    POST /api/chat.update")
    print(f"    POST /api/views.open")
    print(f"    GET  /api/users.info?user=U_ALICE")
    print(f"    POST /api/auth.test")
    print(f"  Pre-seeded users: U_ALICE (alice@example.com), U_BOB (bob@example.com)")
    print(f"")
    print(f"  To stop: Ctrl+C")
    print(f"")

    uvicorn.run(server.app, host=host, port=port, log_level="info")
    return 0
