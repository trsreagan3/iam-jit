#!/usr/bin/env python3
"""Render the GitHub-access requester walkthrough PDF from the REAL iam-jit
templates + REAL stylesheet, so it looks exactly like the running UI (the
green-on-black terminal theme), not a hand-drawn mock.

It renders the actual Jinja templates (new_request, new_github, request_detail
pending + active, queue) with representative context, inlines static/style.css,
stacks them with page breaks + a caption per screen, and prints with headless
Chrome (a real browser → faithful CSS).

    python scripts/render_github_walkthrough.py
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import tempfile

from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = pathlib.Path(__file__).resolve().parent.parent
TPL = ROOT / "src" / "iam_jit" / "templates"
CSS = (ROOT / "src" / "iam_jit" / "static" / "style.css").read_text()
OUT_PDF = ROOT / "docs" / "github-jit-tokens-walkthrough.pdf"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

env = Environment(loader=FileSystemLoader(str(TPL)), autoescape=select_autoescape(["html"]))


class _User:
    def __init__(self, uid, name, roles):
        self.id, self.display_name, self.roles = uid, name, roles

    @property
    def is_approver(self):
        return bool({"admin", "approver"} & set(self.roles))

    @property
    def is_admin(self):
        return "admin" in self.roles


REQUESTER = _User("email:dev@acme.com", "dev", ["requester"])
ADMIN = _User("email:you@acme.com", "you", ["admin"])


def base_ctx(user=REQUESTER, active="new", **extra):
    ctx = dict(
        version="1.0.0", auth_mode="local", ai_enabled=False, current_user=user,
        active=active, flash=None, health_issues=[], ticket_required=False,
        ticket_hint="", request=None,
    )
    ctx.update(extra)
    return ctx


_PERMS = {"contents": "read", "pull_requests": "write"}


def _form_meta():
    from iam_jit import github_scope
    return {"common_permissions": [
        {"key": c, "desc": github_scope.PERMISSION_DESCRIPTIONS.get(c, "")}
        for c in github_scope.COMMON_GITHUB_PERMISSIONS
    ]}


def _gh_req(state, *, with_token=False):
    status = {"state": state, "owner": "email:dev@acme.com",
              "submitted_at": "2026-06-06T15:02:00Z", "last_updated_at": "2026-06-06T15:04:00Z",
              "comments": []}
    if state == "active":
        status["provisioned"] = {
            "expires_at": "2026-06-06T15:34:00Z",
            "github": {"org": "acme", "repositories": ["web", "api"], "permissions": _PERMS,
                       "expires_at": "2026-06-06T15:34:00Z", "token_active": True},
        }
        if with_token:
            status["_secret_github_token"] = "ghs_9Hb2xQ8r4Tn1Kd7vZ0pL3mW6sJ5fA2cE9bQx7r"
    return {
        "apiVersion": "iam-jit.dev/v1alpha1", "kind": "GitHubTokenRequest",
        "metadata": {"id": "ghr-7f3a", "name": "GitHub: acme/web,api",
                     "requester": {"name": "dev", "email": "dev@acme.com"}},
        "spec": {"description": "open a PR fixing the broken build",
                 "github": {"org": "acme", "repositories": ["web", "api"],
                            "permissions": _PERMS, "duration_minutes": 30}},
        "status": status,
    }


def _detail_ctx(req, user, **over):
    ctx = base_ctx(user=user, active="home", req=req, is_github=True, github_token=None,
                   policy_pretty="", assumer_resolved=True, managed_refs=[], cli_preview=None,
                   approve_blocked=None, approve_blocked_issues=[])
    ctx.update(over)
    return ctx


def _summary(req):
    from iam_jit import lifecycle
    return lifecycle.summarize(req)


SCREENS = [
    ("Part 1 · step 1 — + New request → pick GitHub repo access",
     "new_request.html", base_ctx()),
    ("Part 1 · step 2 — name the repos and pick the GitHub permissions",
     "new_github.html", base_ctx(form={"selected": _PERMS}, errors=[], **_form_meta())),
    ("Part 1 · step 3 — it lands in the approver's queue (pending, no token yet)",
     "request_detail.html", _detail_ctx(_gh_req("pending"), REQUESTER)),
    ("Part 1 · step 4 — approved → your token, shown once + Revoke",
     "request_detail.html", _detail_ctx(_gh_req("active", with_token=True), ADMIN,
                                        github_token="ghs_9Hb2xQ8r4Tn1Kd7vZ0pL3mW6sJ5fA2cE9bQx7r")),
]


def _inner_body(html: str) -> str:
    m = re.search(r"<body[^>]*>(.*)</body>", html, re.S | re.I)
    return m.group(1) if m else html


def main() -> None:
    # The queue screen needs a list of summaries (approver view).
    from iam_jit import lifecycle  # noqa: F401 (import side-effects safe)
    queue_ctx = base_ctx(user=ADMIN, active="queue",
                          requests=[_summary(_gh_req("pending"))], all_count=1)
    screens = SCREENS + [
        ("Part 1 · the same /queue an approver already uses (GitHub rows alongside AWS)",
         "queue.html", queue_ctx),
    ]

    blocks = []
    for caption, tpl, ctx in screens:
        rendered = env.get_template(tpl).render(**ctx)
        body = _inner_body(rendered)
        blocks.append(
            f'<div class="wt-screen"><div class="wt-caption">{caption}</div>{body}</div>'
        )

    combined = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<style>
{CSS}
/* walkthrough-only chrome (kept in the terminal theme) */
.wt-screen {{ page-break-after: always; padding: 0 0 8mm; }}
.wt-caption {{ font-family: ui-monospace, Menlo, monospace; color: var(--text-bright);
  border-bottom: 1px solid var(--border-strong); padding: 6px 0; margin: 0 0 10px;
  font-size: 13px; }}
.wt-caption::before {{ content: "// "; color: var(--muted); }}
body::before {{ display: none; }} /* drop the animated scanline for print legibility */
@page {{ size: A4; margin: 12mm; background: #000; }}
html, body {{ background: #000 !important; }}
</style></head><body>
{''.join(blocks)}
</body></html>"""

    with tempfile.TemporaryDirectory() as d:
        html_path = pathlib.Path(d) / "walkthrough.html"
        html_path.write_text(combined)
        subprocess.run(
            [CHROME, "--headless", "--disable-gpu", "--no-pdf-header-footer",
             f"--print-to-pdf={OUT_PDF}", f"file://{html_path}"],
            check=True, capture_output=True,
        )
    print(f"wrote {OUT_PDF}")


if __name__ == "__main__":
    main()
