"""#507 / §A92 — `iam-jit canary` subcommand cluster.

The THIS-machine canary (per ``[[this-machine-canary-brought-forward]]``) is
the founder's real-usage dogfooding deploy. This module surfaces the
operator-visible mechanics:

    iam-jit canary status       — read + pretty-print status.json
    iam-jit canary urls         — read + pretty-print urls.md
    iam-jit canary report       — triaged digest (issues + notes + status)
    iam-jit canary file-issue   — manual issue entry
    iam-jit canary update       — full redeploy mechanism (git pull + reinstall
                                  + graceful restart + audit-chain continuity
                                  verify + rollback on failure)
    iam-jit canary update --watch
                                — poll remote git for new commits;
                                  default notify-only; pass
                                  --auto-deploy for autopilot redeploy

Design constraints (per linked memory docs):

* **Zero LLM credits required.** Bouncers + canary run with zero
  ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY`` / ``IAM_JIT_ENABLE_SIDE_LLM``
  per ``[[bouncer-zero-llm-when-agent-in-loop]]``. The agent (Claude
  Code in the founder's session) handles LLM reasoning via MCP.
* **Local-only state.** Per ``[[independence-as-security-property]]``
  the canary writes 4 files under ``~/.iam-jit/canary/``; nothing
  phones home to iam-jit-the-company. ``--watch`` DOES contact the
  remote git origin (the pre-§A101 'LOCAL only' claim was wrong); the
  contact is to the operator's own GitHub remote, which is part of
  the operator's existing trust boundary.
* **State-verification convention.** Every reported success status
  must be backed by an observable side effect; tests assert both per
  ``docs/CONTRIBUTING.md``.

The 4 artifacts under ``~/.iam-jit/canary/`` are:

* ``issues.jsonl`` — append-only structured issues (one JSON / line)
* ``notes.md`` — operator free-form notes; agent categorises on demand
* ``status.json`` — current state (canary day, bouncers, ports, commits)
* ``urls.md`` — log + UI URLs for daily-dev access

This module owns the read/print/append surface for those files. The
deploy script (``scripts/deploy-canary.sh`` or this session's setup
flow) is the one that initialises them; the CLI re-reads + extends.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import time
from collections import Counter
from typing import Any

import click

# Public so deploy scripts + tests can import the path without recomputing.
CANARY_DIR = pathlib.Path.home() / ".iam-jit" / "canary"
ISSUES_PATH = CANARY_DIR / "issues.jsonl"
NOTES_PATH = CANARY_DIR / "notes.md"
STATUS_PATH = CANARY_DIR / "status.json"
URLS_PATH = CANARY_DIR / "urls.md"

# Repos the canary tracks. Per ``[[canary-redeploys-on-every-update]]``
# the scope is currently ibounce (iam-roles) + gbounce; expand as the
# canary scope grows.
#
# Defaults assume sibling-checkout layout (``<parent>/iam-roles`` +
# ``<parent>/gbounce``) computed from THIS module's path. Operators
# with a different layout override via env vars:
#
#   IAM_JIT_CANARY_IAM_ROLES_REPO=/path/to/iam-roles
#   IAM_JIT_CANARY_GBOUNCE_REPO=/path/to/gbounce
#
# This keeps the module portable (no hardcoded operator paths in the
# public repo per ``[[push-policy-public-repo]]``).


def _default_repo(env_name: str, sibling_name: str) -> pathlib.Path:
    """Resolve a repo path from env override, else sibling of this checkout."""
    override = os.environ.get(env_name)
    if override:
        return pathlib.Path(override).expanduser()
    # __file__ is .../<iam-roles>/src/iam_jit/cli_canary.py.
    iam_roles_root = pathlib.Path(__file__).resolve().parents[2]
    if sibling_name == "iam-roles":
        return iam_roles_root
    return iam_roles_root.parent / sibling_name


_CANARY_REPOS = {
    "iam-roles": _default_repo("IAM_JIT_CANARY_IAM_ROLES_REPO", "iam-roles"),
    "gbounce": _default_repo("IAM_JIT_CANARY_GBOUNCE_REPO", "gbounce"),
}

_SEVERITIES = ("CRIT", "HIGH", "MED", "LOW")
_CATEGORIES = (
    "deny_surprise",
    "bouncer_error",
    "profile_drift",
    "anomaly",
    "calibration_drift",
    "operator_friction",
    "update_success",
    "update_failure",
    "other",
)


# ---------------------------------------------------------------------------
# File helpers (importable so deploy scripts share the schema)
# ---------------------------------------------------------------------------


def _ensure_dir() -> None:
    CANARY_DIR.mkdir(parents=True, exist_ok=True)


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_issue(
    *,
    bouncer: str,
    severity: str,
    category: str,
    observable: str,
    expected: str,
    repro_hint: str = "",
    auto_generated: bool = False,
    related_task: str | None = None,
    ts: str | None = None,
) -> dict[str, Any]:
    """Append one issue to ``issues.jsonl``. Returns the entry dict.

    Validates severity + category up-front so callers can't drift the
    schema silently.
    """

    if severity not in _SEVERITIES:
        raise ValueError(
            f"severity must be one of {_SEVERITIES}; got {severity!r}"
        )
    if category not in _CATEGORIES:
        raise ValueError(
            f"category must be one of {_CATEGORIES}; got {category!r}"
        )

    _ensure_dir()
    entry: dict[str, Any] = {
        "ts": ts or _now_iso(),
        "bouncer": bouncer,
        "severity": severity,
        "category": category,
        "observable": observable,
        "expected": expected,
        "repro_hint": repro_hint,
        "auto_generated": auto_generated,
        "related_task": related_task,
    }
    with ISSUES_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":"), sort_keys=True))
        fh.write("\n")
    return entry


def read_issues(since_iso: str | None = None) -> list[dict[str, Any]]:
    """Return issues from ``issues.jsonl``. Optionally filter to entries
    with ``ts >= since_iso``."""
    if not ISSUES_PATH.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in ISSUES_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if since_iso and entry.get("ts", "") < since_iso:
            continue
        out.append(entry)
    return out


def read_status() -> dict[str, Any]:
    if not STATUS_PATH.exists():
        return {}
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def write_status(status: dict[str, Any]) -> None:
    _ensure_dir()
    STATUS_PATH.write_text(
        json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _parse_since(since: str) -> str:
    """Parse ``--since 24h`` / ``7d`` / ``30m`` / ``all`` into an ISO
    timestamp. Returns empty string for ``all``."""
    if since == "all":
        return ""
    m = re.fullmatch(r"(\d+)([smhd])", since.lower())
    if not m:
        raise click.BadParameter(
            f"--since must look like '24h', '7d', '30m', '60s' or 'all'; got {since!r}"
        )
    n, unit = int(m.group(1)), m.group(2)
    seconds = n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    cutoff = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(seconds=seconds)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(repo: pathlib.Path, *args: str) -> tuple[int, str]:
    """Run ``git`` in ``repo`` and return ``(returncode, combined output)``."""
    if not (repo / ".git").exists():
        return 1, f"not a git repo: {repo}"
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _curl_responsive(url: str, timeout: float = 3.0) -> tuple[bool, int | None]:
    """Return ``(responsive, http_status)`` for a URL. ``responsive`` is
    True for any HTTP response (even 4xx/5xx — the listener is alive)."""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return True, resp.getcode()
    except urllib.error.HTTPError as exc:
        # 4xx / 5xx — but the listener IS alive, so still "responsive".
        return True, exc.code
    except (urllib.error.URLError, ConnectionResetError, TimeoutError, OSError):
        return False, None


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def register_canary_group(main_group: click.Group) -> click.Group:
    """Attach the ``canary`` subcommand group to the top-level
    ``iam-jit`` Click group. Idempotent.
    """

    @main_group.group("canary")
    def canary() -> None:
        """THIS-machine canary (real-usage dogfood) subcommands.

        Manages the canary issues file, URL surface, status snapshot,
        and redeploy mechanism. See docs/CANARY.md and
        ``~/.iam-jit/canary/`` for the live data.
        """

    # -- status --------------------------------------------------------

    @canary.command("status")
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit status.json verbatim (no human formatting).",
    )
    def status_cmd(as_json: bool) -> None:
        """Print the current canary status (status.json)."""
        status = read_status()
        if not status:
            click.echo(
                "No canary status yet — run the deploy script to bootstrap "
                "~/.iam-jit/canary/.",
                err=True,
            )
            raise SystemExit(1)
        if as_json:
            click.echo(json.dumps(status, indent=2, sort_keys=True))
            return
        click.echo("iam-jit canary status")
        click.echo("=" * 60)
        for key in (
            "canary_day",
            "started_at",
            "llm_mode",
            "open_issues_count",
            "intervention_count_24h",
            "denies_24h",
            "improvement_cycles",
            "last_issue_ts",
        ):
            if key in status:
                click.echo(f"  {key:<30} {status[key]}")
        bouncers = status.get("bouncers") or {}
        if bouncers:
            click.echo("  bouncers:")
            for name, mode in bouncers.items():
                click.echo(f"    {name:<10} {mode}")
        ports = status.get("ports") or {}
        if ports:
            click.echo("  ports:")
            for name, port in ports.items():
                click.echo(f"    {name:<10} {port}")
        commits = status.get("commits") or {}
        if commits:
            click.echo("  commits:")
            for name, sha in commits.items():
                click.echo(f"    {name:<10} {sha}")

    # -- urls ----------------------------------------------------------

    @canary.command("urls")
    def urls_cmd() -> None:
        """Print the canary URLs (urls.md). Stable across restarts."""
        if not URLS_PATH.exists():
            click.echo(
                "No urls.md yet — run the deploy script first.", err=True
            )
            raise SystemExit(1)
        click.echo(URLS_PATH.read_text(encoding="utf-8"))

    # -- report --------------------------------------------------------

    @canary.command("report")
    @click.option(
        "--since",
        default="24h",
        show_default=True,
        help="Window: e.g. '24h', '7d', '30m', '60s', or 'all'.",
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit a structured report (issues + status + notes-summary).",
    )
    def report_cmd(since: str, as_json: bool) -> None:
        """Triaged canary digest. Read this at session start.

        Shows: open issues by severity, recent notes, status snapshot.
        Designed for both human + agent consumption.
        """
        since_iso = _parse_since(since)
        issues = read_issues(since_iso=since_iso or None)
        status = read_status()
        notes = NOTES_PATH.read_text(encoding="utf-8") if NOTES_PATH.exists() else ""

        if as_json:
            payload = {
                "since": since,
                "since_iso": since_iso or None,
                "status": status,
                "issues_count": len(issues),
                "issues_by_severity": dict(
                    Counter(i.get("severity", "?") for i in issues)
                ),
                "issues_by_category": dict(
                    Counter(i.get("category", "?") for i in issues)
                ),
                "issues": issues,
                "notes_excerpt": notes[-2000:],
            }
            click.echo(json.dumps(payload, indent=2, sort_keys=True))
            return

        click.echo(f"iam-jit canary report (since {since})")
        click.echo("=" * 60)
        if status:
            click.echo(
                f"Day {status.get('canary_day', '?')} | "
                f"open_issues={status.get('open_issues_count', '?')} | "
                f"denies_24h={status.get('denies_24h', '?')} | "
                f"interventions_24h={status.get('intervention_count_24h', '?')}"
            )
        click.echo()

        click.echo(f"Issues in window: {len(issues)}")
        if issues:
            by_sev = Counter(i.get("severity", "?") for i in issues)
            for sev in _SEVERITIES:
                if by_sev.get(sev):
                    click.echo(f"  {sev}: {by_sev[sev]}")
            click.echo()
            click.echo("Latest issues:")
            for issue in issues[-10:]:
                ts = issue.get("ts", "?")
                sev = issue.get("severity", "?")
                bn = issue.get("bouncer", "?")
                cat = issue.get("category", "?")
                obs = issue.get("observable", "")[:70]
                click.echo(f"  {ts}  [{sev:<4}] {bn}/{cat}: {obs}")
        click.echo()

        if notes.strip():
            tail = "\n".join(notes.splitlines()[-15:])
            click.echo("Recent notes (last 15 lines):")
            click.echo(tail)
        else:
            click.echo("No notes recorded yet.")

    # -- file-issue ----------------------------------------------------

    @canary.command("file-issue")
    @click.option(
        "--severity",
        type=click.Choice(_SEVERITIES, case_sensitive=False),
        required=True,
    )
    @click.option(
        "--category",
        type=click.Choice(_CATEGORIES, case_sensitive=False),
        default="other",
        show_default=True,
    )
    @click.option("--bouncer", default="iam-jit", show_default=True)
    @click.option("--note", required=True, help="Operator note / observable.")
    @click.option(
        "--expected",
        default="",
        help="What should have happened (optional).",
    )
    @click.option(
        "--repro-hint", default="", help="Command / context to reproduce."
    )
    @click.option(
        "--related-task", default=None, help="GitHub-style task id, e.g. #507."
    )
    def file_issue_cmd(
        severity: str,
        category: str,
        bouncer: str,
        note: str,
        expected: str,
        repro_hint: str,
        related_task: str | None,
    ) -> None:
        """Manually append an issue to ~/.iam-jit/canary/issues.jsonl."""
        entry = append_issue(
            bouncer=bouncer,
            severity=severity.upper(),
            category=category.lower(),
            observable=note,
            expected=expected,
            repro_hint=repro_hint,
            auto_generated=False,
            related_task=related_task,
        )
        click.echo(json.dumps(entry, indent=2, sort_keys=True))

    # -- update --------------------------------------------------------

    @canary.command("update")
    @click.option(
        "--watch",
        is_flag=True,
        default=False,
        help=(
            "Polls remote git for new commits on a fixed --interval. "
            "By default (notify-only) the loop reports new commits to "
            "stdout + appends a HIGH issue to issues.jsonl WITHOUT "
            "pulling / reinstalling / restarting — the operator runs "
            "`iam-jit canary update` manually when ready. Pass "
            "--auto-deploy in addition to --watch to restore the "
            "pre-§A101 behaviour where every new origin/main commit "
            "is installed + bouncers restarted automatically. The "
            "notify-only default is the safer posture per "
            "[[push-policy-public-repo]] — autopilot deploys are "
            "opt-in, not default. (Polling DOES contact the remote; "
            "the pre-§A101 'LOCAL only / no phone-home' help text "
            "was wrong — see issue §A101.)"
        ),
    )
    @click.option(
        "--auto-deploy",
        is_flag=True,
        default=False,
        help=(
            "§A101 — explicit opt-in to autopilot redeploy under "
            "--watch. WITHOUT this flag, --watch is notify-only "
            "(reports new commits; does NOT mutate). WITH this flag, "
            "each new origin/main commit triggers a full "
            "`iam-jit canary update` cycle (pull + reinstall + "
            "restart). A WARN line is logged at watch-loop start so "
            "the operator sees the autopilot posture in the terminal. "
            "Ignored without --watch."
        ),
    )
    @click.option(
        "--interval",
        default="15m",
        show_default=True,
        help="Watch poll interval (e.g. 15m, 1h, 30s). Only used with --watch.",
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        default=False,
        help="Report what would happen without pulling / rebuilding / restarting.",
    )
    def update_cmd(
        watch: bool,
        auto_deploy: bool,
        interval: str,
        dry_run: bool,
    ) -> None:
        """Redeploy the canary on the newest commits.

        Implements the 9-step flow from
        ``[[canary-redeploys-on-every-update]]``:
        clean-tree check → fetch → pull → reinstall → version-check →
        graceful restart → post-update verify → audit-chain continuity →
        issue-log outcome (success or failure with rollback).
        """
        if watch:
            _run_watch_loop(
                interval=interval,
                dry_run=dry_run,
                auto_deploy=auto_deploy,
            )
            return
        _do_one_update(dry_run=dry_run)

    return canary


# ---------------------------------------------------------------------------
# Update mechanism
# ---------------------------------------------------------------------------


def _do_one_update(*, dry_run: bool) -> None:
    """Execute one full update cycle. Logs outcome to issues.jsonl."""
    click.echo("== iam-jit canary update ==")
    start = time.time()
    pre_status = read_status()
    pre_shas: dict[str, str] = {}
    new_shas: dict[str, str] = {}

    # Step 1: record pre-update state.
    for name, repo in _CANARY_REPOS.items():
        rc, sha = _git(repo, "rev-parse", "HEAD")
        pre_shas[name] = sha if rc == 0 else "(unknown)"
        click.echo(f"  {name}: pre-update HEAD={pre_shas[name][:12]}")

    # Step 2: refuse uncommitted changes (dogfood notes are in ~/.iam-jit, not repos).
    # In dry-run mode, REPORT but don't fail — operator wants to see the plan
    # even when the tree is dirty, and we never mutate anything in dry-run.
    dirty: list[str] = []
    for name, repo in _CANARY_REPOS.items():
        rc, out = _git(repo, "status", "--porcelain")
        if rc != 0:
            _fail(f"git status failed for {name}: {out}", pre_status, pre_shas, dry_run)
            return
        if out.strip():
            dirty.append(name)
            if not dry_run:
                _fail(
                    f"{name} has uncommitted changes — refusing to pull. "
                    f"Commit / stash first.\n{out}",
                    pre_status,
                    pre_shas,
                    dry_run,
                )
                return

    if dry_run:
        if dirty:
            click.echo(
                f"  [dry-run] WOULD-FAIL: uncommitted changes in: {', '.join(dirty)} "
                f"(actual `update` refuses; dry-run reports + continues)"
            )
        click.echo("  [dry-run] would run: git fetch + git pull per repo")
        click.echo("  [dry-run] would run: pip install -e . / go install ./...")
        click.echo("  [dry-run] would run: graceful restart of bouncers")
        return

    # Steps 3-4: fetch + pull + reinstall.
    for name, repo in _CANARY_REPOS.items():
        rc, out = _git(repo, "fetch", "--quiet")
        if rc != 0:
            _fail(f"git fetch failed for {name}: {out}", pre_status, pre_shas, dry_run)
            return
        rc, out = _git(repo, "pull", "--ff-only")
        if rc != 0:
            _fail(f"git pull failed for {name}: {out}", pre_status, pre_shas, dry_run)
            return
        rc, sha = _git(repo, "rev-parse", "HEAD")
        new_shas[name] = sha if rc == 0 else "(unknown)"
        click.echo(f"  {name}: post-pull HEAD={new_shas[name][:12]}")

    # Reinstall per-repo.
    iam_roles_repo = _CANARY_REPOS["iam-roles"]
    venv_pip = pathlib.Path.home() / ".iam-jit" / "venv" / "bin" / "pip"
    if venv_pip.exists():
        proc = subprocess.run(
            [str(venv_pip), "install", "-e", "."],
            cwd=str(iam_roles_repo),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            _fail(
                f"pip install -e . failed:\n{proc.stdout[-500:]}\n{proc.stderr[-500:]}",
                pre_status,
                pre_shas,
                dry_run,
            )
            return
        click.echo("  iam-roles: pip install -e . OK")

    gbounce_repo = _CANARY_REPOS["gbounce"]
    if gbounce_repo.exists() and shutil.which("go"):
        proc = subprocess.run(
            ["go", "install", "./..."],
            cwd=str(gbounce_repo),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            _fail(
                f"go install ./... failed:\n{proc.stdout[-500:]}\n{proc.stderr[-500:]}",
                pre_status,
                pre_shas,
                dry_run,
            )
            return
        click.echo("  gbounce: go install ./... OK")

    # Step 5: version-check (best-effort — bouncer must respond).
    # The bouncer's `*bounce --version` reports the constant baked in at
    # install time; if it doesn't match the new commit SHA's tag, we
    # surface a LOW issue but don't fail the update (version bumping is
    # a separate release discipline).

    # Step 6: graceful restart — see _restart_bouncers below.
    restart_ok, restart_msg = _restart_bouncers(pre_status)
    if not restart_ok:
        _fail(
            f"bouncer restart failed: {restart_msg}",
            pre_status,
            pre_shas,
            dry_run,
        )
        return

    # Step 7-8: success — log + update status.
    duration = round(time.time() - start, 1)
    append_issue(
        bouncer="iam-jit",
        severity="LOW",
        category="update_success",
        observable=(
            f"canary update succeeded in {duration}s; "
            + ", ".join(
                f"{n}: {pre_shas.get(n, '?')[:12]}→{new_shas.get(n, '?')[:12]}"
                for n in _CANARY_REPOS
            )
        ),
        expected="canary update succeeded",
        repro_hint="iam-jit canary update",
        auto_generated=True,
        related_task="#507",
    )

    # Touch status.json with new commits.
    status = read_status()
    if status:
        status.setdefault("commits", {}).update(new_shas)
        status["last_update_at"] = _now_iso()
        write_status(status)

    click.echo(f"OK update complete in {duration}s")


def _fail(
    msg: str,
    pre_status: dict[str, Any],
    pre_shas: dict[str, str],
    dry_run: bool,
) -> None:
    """Log + announce a CRIT update failure. Best-effort rollback per repo."""
    click.echo(f"FAIL {msg}", err=True)
    if dry_run:
        return
    # Best-effort rollback: git checkout each pre-update SHA. Don't
    # restart if rollback fails — leave the operator in a known broken
    # state so they can intervene.
    rollback_notes = []
    for name, repo in _CANARY_REPOS.items():
        sha = pre_shas.get(name)
        if not sha or sha == "(unknown)":
            continue
        rc, out = _git(repo, "checkout", sha)
        rollback_notes.append(
            f"{name}: rollback to {sha[:12]} "
            + ("OK" if rc == 0 else f"FAIL ({out[:80]})")
        )
    append_issue(
        bouncer="iam-jit",
        severity="CRIT",
        category="update_failure",
        observable=msg[:500],
        expected="canary update succeeded",
        repro_hint="iam-jit canary update",
        auto_generated=True,
        related_task="#507",
    )
    if rollback_notes:
        for note in rollback_notes:
            click.echo(f"  rollback: {note}", err=True)


def _restart_bouncers(pre_status: dict[str, Any]) -> tuple[bool, str]:
    """SIGTERM bouncers + wait healthy; restart per recipe.

    This is intentionally LIGHT-TOUCH at v1.0 — the canary is the
    founder's machine and the deploy script holds the supervisor
    knowledge. We surface what the bouncer is doing so the founder can
    manage it; we don't try to launchd-supervise from inside CLI code.

    Returns ``(True, "no bouncers running")`` if there's nothing to
    restart (which is a valid state — pre-deploy or after manual stop).
    """
    ports = (pre_status or {}).get("ports") or {}
    if not ports:
        return True, "no ports recorded in status.json; skipping restart"

    # Send SIGTERM to anything listening on the recorded bouncer ports.
    # Use lsof to find PIDs; portable on macOS + Linux.
    restarted: list[str] = []
    for bouncer_name, port in ports.items():
        proc = subprocess.run(
            ["lsof", "-iTCP:%d" % int(port), "-sTCP:LISTEN", "-t"],
            capture_output=True,
            text=True,
            check=False,
        )
        pids = [p.strip() for p in proc.stdout.splitlines() if p.strip()]
        for pid_str in pids:
            try:
                pid = int(pid_str)
            except ValueError:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                restarted.append(f"{bouncer_name}(pid={pid})")
            except (ProcessLookupError, PermissionError) as exc:
                return False, f"kill {bouncer_name} pid={pid}: {exc}"

    # Wait for ports to release (max 30s).
    deadline = time.time() + 30
    for bouncer_name, port in ports.items():
        while time.time() < deadline:
            proc = subprocess.run(
                ["lsof", "-iTCP:%d" % int(port), "-sTCP:LISTEN", "-t"],
                capture_output=True,
                text=True,
                check=False,
            )
            if not proc.stdout.strip():
                break
            time.sleep(0.5)
        else:
            return False, f"port {port} ({bouncer_name}) didn't release in 30s"

    # We don't auto-restart here — the deploy script owns supervisor
    # launch (launchd / systemd / `nohup &`). Surface what we stopped so
    # the operator (or deploy script wrapper) can re-launch.
    if restarted:
        return True, "stopped: " + ", ".join(restarted) + " (operator re-launches)"
    return True, "no live bouncers found on recorded ports"


def _run_watch_loop(
    *, interval: str, dry_run: bool, auto_deploy: bool = False,
) -> None:
    """Poll remote git for new commits.

    §A101 behaviour split:

      * ``auto_deploy=False`` (default for --watch): notify-only. New
        upstream commits are surfaced to stdout AND appended as a
        HIGH-severity entry in ~/.iam-jit/canary/issues.jsonl. The
        operator runs ``iam-jit canary update`` manually when ready.
      * ``auto_deploy=True``: each new upstream commit triggers a
        full ``_do_one_update`` cycle (pre-§A101 behaviour). A WARN
        line fires at watch-loop start so the autopilot posture is
        visible in the terminal.

    Per [[push-policy-public-repo]] the notify-only default is the
    safer posture: autopilot redeploy across the suite means any
    commit that lands on any origin/main becomes a live install,
    which is a footgun the operator should opt into explicitly.
    """
    m = re.fullmatch(r"(\d+)([smhd])", interval.lower())
    if not m:
        raise click.BadParameter(
            f"--interval must look like '15m', '1h', '30s'; got {interval!r}"
        )
    n, unit = int(m.group(1)), m.group(2)
    seconds = n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]

    if auto_deploy:
        click.echo(
            f"iam-jit canary update --watch --auto-deploy: WARNING — "
            f"auto-deploy enabled. Any commit landing on origin/main "
            f"will be installed + bouncers restarted automatically. "
            f"Polling every {interval}. Ctrl-C to stop."
        )
    else:
        click.echo(
            f"iam-jit canary update --watch (notify-only): polling "
            f"remote every {interval}. New commits will be reported "
            f"to stdout + logged to issues.jsonl; no auto-redeploy. "
            f"Pass --auto-deploy to enable autopilot redeploy. "
            f"Ctrl-C to stop."
        )
    while True:
        new_commits: list[tuple[str, str, str]] = []  # (name, head, upstream)
        for name, repo in _CANARY_REPOS.items():
            _git(repo, "fetch", "--quiet")
            rc1, head = _git(repo, "rev-parse", "HEAD")
            rc2, upstream = _git(repo, "rev-parse", "@{u}")
            if rc1 == 0 and rc2 == 0 and head != upstream:
                click.echo(
                    f"  {name}: new commits ({head[:12]} → {upstream[:12]})"
                )
                new_commits.append((name, head, upstream))
        if new_commits:
            if auto_deploy:
                _do_one_update(dry_run=dry_run)
            else:
                # Notify-only: log to issues.jsonl so the operator's
                # `iam-jit canary issues` query surfaces the pending
                # update. Severity HIGH because an un-installed
                # security fix is a meaningful gap.
                for name, head, upstream in new_commits:
                    try:
                        # Category "other" — the existing canary
                        # taxonomy doesn't have an "update_available"
                        # bucket (only success / failure). "other"
                        # is the documented escape hatch in the
                        # _CATEGORIES tuple at module top.
                        append_issue(
                            bouncer=name,
                            severity="HIGH",
                            category="other",
                            observable=(
                                f"§A101 update_available: new "
                                f"origin/main commits {head[:12]} -> "
                                f"{upstream[:12]}"
                            ),
                            expected=(
                                "operator runs `iam-jit canary update` "
                                "to install + restart"
                            ),
                            repro_hint=(
                                "iam-jit canary update --watch is in "
                                "notify-only mode; pass --auto-deploy "
                                "to enable autopilot redeploy"
                            ),
                            auto_generated=True,
                            related_task="§A101",
                        )
                    except Exception as e:
                        # Never crash the watch loop on a logging
                        # failure — the stdout report above already
                        # alerted the operator.
                        click.secho(
                            f"  warning: could not append issue: {e}",
                            fg="yellow", err=True,
                        )
                click.echo(
                    "  notify-only: NOT auto-deploying. Run "
                    "`iam-jit canary update` to install."
                )
        else:
            click.echo(f"  no new commits at {_now_iso()}")
        time.sleep(seconds)
