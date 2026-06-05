#!/usr/bin/env python3
"""One-shot GitHub App setup for the iam-jit GitHub JIT-token feature.

Uses GitHub's App-manifest flow so the human part is two clicks: "Create
GitHub App" then "Install". The script:

  1. Spins up a localhost server and opens the browser to an auto-submitting
     manifest form (`POST https://github.com/settings/apps/new`).
  2. Catches the redirect with the temporary `code` and exchanges it
     (`POST /app-manifests/{code}/conversions`) for the App id + private key.
  3. Saves the .pem (0600), then opens the install page and polls
     `GET /app/installations` (signed with the new App's JWT) until you've
     installed it, capturing the installation id + the repos you granted.
  4. Writes the iam-jit installation registry (so `iam-jit github` + the
     serve UI work) and prints the blast-radius UAT env block.

No secrets touch the network except GitHub itself; the manifest `code` and
the App JWT are the only credentials, both short-lived.

    python scripts/setup_github_app.py --org trsreagan3

Personal account or org both work (Apps can be owned by either).
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import pathlib
import secrets
import threading
import time
import urllib.parse
import webbrowser

import httpx

from iam_jit.github_installations import (
    GitHubInstallation,
    add_installation,
    default_registry_path,
)
from iam_jit.github_provisioner import build_app_jwt

_API = "https://api.github.com"
_GH = "https://github.com"


def _manifest(redirect_url: str, name: str) -> dict:
    """The App manifest. Ceiling = Repository contents read & write so a
    minted `contents:read` token can be proven UNABLE to write (the UAT's
    permission-boundary row). Webhooks off — installation tokens don't need
    them."""
    return {
        "name": name,
        "url": "https://github.com/trsreagan3/iam-jit",
        "redirect_url": redirect_url,
        "public": False,
        "default_permissions": {"contents": "write", "metadata": "read"},
        "hook_attributes": {"url": "https://example.com/unused", "active": False},
    }


class _Handler(http.server.BaseHTTPRequestHandler):
    # Populated by the server instance.
    manifest_json: str = ""
    state: str = ""
    result: dict = {}
    done = threading.Event()

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            # Auto-submit the manifest form to GitHub.
            form = (
                f'<html><body onload="document.forms[0].submit()">'
                f'<form action="{_GH}/settings/apps/new?state={self.state}" '
                f'method="post">'
                f'<input type="hidden" name="manifest" '
                f"value='{self.manifest_json}'>"
                f'<noscript><button type="submit">Create GitHub App</button>'
                f"</noscript></form>"
                f"<p>Redirecting to GitHub to create the App…</p>"
                f"</body></html>"
            )
            self._html(form)
            return
        if parsed.path == "/callback":
            q = urllib.parse.parse_qs(parsed.query)
            code = (q.get("code") or [""])[0]
            state = (q.get("state") or [""])[0]
            if not code or state != self.state:
                self._html("<h1>State mismatch or missing code.</h1>", 400)
                return
            type(self).result = {"code": code}
            self._html(
                "<h1>App created.</h1><p>You can close this tab and return "
                "to the terminal.</p>"
            )
            type(self).done.set()
            return
        self._html("not found", 404)

    def _html(self, body: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def _run_server(port: int, manifest: dict, state: str) -> type[_Handler]:
    _Handler.manifest_json = json.dumps(manifest).replace("'", "&#39;")
    _Handler.state = state
    _Handler.result = {}
    _Handler.done = threading.Event()
    srv = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _convert(code: str) -> dict:
    with httpx.Client(timeout=30.0) as c:
        r = c.post(
            f"{_API}/app-manifests/{code}/conversions",
            headers={"Accept": "application/vnd.github+json"},
        )
    if r.status_code not in (200, 201):
        raise SystemExit(f"manifest conversion failed: {r.status_code} {r.text[:300]}")
    return r.json()


def _poll_installation(app_id: str, pem: str, timeout_s: int = 300) -> dict:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        jwt = build_app_jwt(app_id, pem)
        with httpx.Client(timeout=20.0) as c:
            r = c.get(
                f"{_API}/app/installations",
                headers={
                    "Authorization": f"Bearer {jwt}",
                    "Accept": "application/vnd.github+json",
                },
            )
        if r.status_code == 200 and r.json():
            return r.json()[0]
        time.sleep(3)
    raise SystemExit("timed out waiting for the App to be installed")


def _installation_repos(app_id: str, pem: str, installation_id: str) -> list[str]:
    jwt = build_app_jwt(app_id, pem)
    with httpx.Client(timeout=20.0) as c:
        tok = c.post(
            f"{_API}/app/installations/{installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {jwt}", "Accept": "application/vnd.github+json"},
        )
        if tok.status_code != 201:
            return []
        token = tok.json()["token"]
        repos = c.get(
            f"{_API}/installation/repositories",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        )
        if repos.status_code != 200:
            return []
        return [r["name"] for r in repos.json().get("repositories", [])]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--org", required=True, help="account/org that owns the App + repos")
    ap.add_argument("--name", default="iam-jit-jit-tokens", help="App name (must be globally unique)")
    ap.add_argument("--port", type=int, default=8731, help="localhost callback port")
    ap.add_argument(
        "--key-dir",
        default=str(pathlib.Path.home() / ".iam-jit"),
        help="where to write the App private key (.pem)",
    )
    args = ap.parse_args()

    redirect_url = f"http://localhost:{args.port}/callback"
    state = secrets.token_urlsafe(16)
    manifest = _manifest(redirect_url, args.name)
    srv = _run_server(args.port, manifest, state)

    start = f"http://localhost:{args.port}/"
    print(f"Opening {start}\n→ click 'Create GitHub App' on the GitHub page that loads.")
    webbrowser.open(start)

    if not _Handler.done.wait(timeout=300):
        raise SystemExit("timed out waiting for App creation")
    srv.shutdown()

    conv = _convert(_Handler.result["code"])
    app_id = str(conv["id"])
    slug = conv["slug"]
    pem = conv["pem"]

    key_dir = pathlib.Path(args.key_dir)
    key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = key_dir / f"{slug}.private-key.pem"
    key_path.write_text(pem)
    os.chmod(key_path, 0o600)
    print(f"\n✓ App created: id={app_id} slug={slug}")
    print(f"✓ Private key saved: {key_path}")

    install_url = f"{_GH}/apps/{slug}/installations/new"
    print(f"\nNow INSTALL the App on ≥2 repos:\n  {install_url}")
    webbrowser.open(install_url)
    print("Waiting for the installation… (select at least two repos, then come back)")

    inst = _poll_installation(app_id, pem)
    installation_id = str(inst["id"])
    repos = _installation_repos(app_id, pem, installation_id)
    print(f"\n✓ Installed: installation_id={installation_id}")
    print(f"✓ Repos granted: {', '.join(repos) or '(none listed)'}")

    # Write the iam-jit registry so `iam-jit github` + the serve UI work.
    reg = default_registry_path()
    add_installation(
        reg,
        GitHubInstallation(
            org=args.org,
            app_id=app_id,
            installation_id=installation_id,
            private_key_path=str(key_path),
            alias=slug,
        ),
    )
    print(f"✓ Wrote installation registry: {reg}")

    in_scope = repos[0] if repos else "<repo-A>"
    out_scope = repos[1] if len(repos) > 1 else "<repo-B>"
    print("\n" + "=" * 64)
    print("Blast-radius UAT env (paste into your shell, then I run the UAT):")
    print("=" * 64)
    print(f"export IAM_JIT_GH_UAT=1")
    print(f"export IAM_JIT_GH_UAT_APP_ID={app_id}")
    print(f"export IAM_JIT_GH_UAT_INSTALLATION_ID={installation_id}")
    print(f"export IAM_JIT_GH_UAT_PRIVATE_KEY_PATH={key_path}")
    print(f"export IAM_JIT_GH_UAT_OWNER={args.org}")
    print(f"export IAM_JIT_GH_UAT_REPO_IN_SCOPE={in_scope}")
    print(f"export IAM_JIT_GH_UAT_REPO_OUT_OF_SCOPE={out_scope}")
    if len(repos) < 2:
        print("\n⚠ Fewer than 2 repos granted — install on a 2nd repo and rerun the"
              " install, or set REPO_OUT_OF_SCOPE to any repo the App canNOT see.")


if __name__ == "__main__":
    main()
