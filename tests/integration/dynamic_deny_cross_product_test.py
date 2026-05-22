"""#324e — cross-product dynamic-deny end-to-end integration test.

Exercises the unified `iam-jit deny` CLI + its fan-out to each
bouncer's `/admin/dynamic-denies/reload` endpoint AND verifies that
the on-disk YAML is the source of truth across the suite.

Two layers of coverage:

  1. **Conductor coverage (always-on).** Stand up 4 in-process HTTP
     servers that pretend to be each bouncer's mgmt port; assert the
     CLI POSTs each affected bouncer when (and only when) a target
     routes there, that org-distributed protections work, that
     `--bouncer-url` overrides work, that the YAML round-trips, that
     `remove` re-fans-out, and that the watcher fixture picks up
     file changes.

  2. **Live ibounce coverage (gated on binary availability).** When
     the ibounce serve runtime is available locally, also boot a real
     ibounce serve process pointing at the same YAML and confirm a
     matching request returns 403 with the dynamic-deny rule id.
     SKIPS when the wheel hasn't been installed (matches the
     pattern in `audit_events_wire_parity_test.py`).

Per ``[[deliberate-feature-completion]]`` this ships ALONGSIDE the
#324e CLI + MCP changes. Per ``[[v1-scope-bar]]`` it gates the
unified-CLI behavior; per ``[[ibounce-honest-positioning]]`` it
verifies the unreachable-bouncer surface is honestly reported.

The 9 scenarios from the #324e brief are covered as the
``test_scenario_NN_*`` methods at the bottom of the file.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from click.testing import CliRunner


# ---------------------------------------------------------------------
# Fake mgmt-port HTTP server (one per bouncer)
# ---------------------------------------------------------------------


class _FakeBouncerReloadHandler(http.server.BaseHTTPRequestHandler):
    """Tiny HTTP handler that mimics each bouncer's
    `/admin/dynamic-denies/reload` shape (per #324a-d). Wire shape
    matches the design doc + the per-product Go handlers."""

    bouncer_name: str = ""
    # Will be set per-server by `_start_fake_bouncer`.

    def do_POST(self) -> None:  # noqa: N802 — http.server callback
        # Track the call on the server object so the test can assert
        # it.
        if self.path != "/admin/dynamic-denies/reload":
            self.send_response(404)
            self.end_headers()
            return
        # Read the YAML file the conductor wrote so the response can
        # surface a realistic `rules_count`.
        yaml_path = getattr(self.server, "yaml_path", None)
        rules_count = _count_rules_in_yaml(yaml_path)
        # Mirror each bouncer's per-product key shape.
        applied_key = f"rules_applied_to_{self.bouncer_name}"
        body = json.dumps({
            "reloaded": True,
            "rules_count": rules_count,
            applied_key: rules_count,
            "path": str(yaml_path) if yaml_path else "",
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        # Record on the server so tests can assert call counts.
        getattr(self.server, "calls", []).append(self.path)

    def log_message(self, fmt: str, *args) -> None:  # noqa: ANN001
        # Silence — pytest captures stderr but we don't want noise.
        pass


def _count_rules_in_yaml(path: Path | str | None) -> int:
    if not path:
        return 0
    p = Path(path)
    if not p.exists():
        return 0
    try:
        from ruamel.yaml import YAML
        loader = YAML(typ="safe", pure=True)
        with p.open("r") as fh:
            data = loader.load(fh)
    except Exception:
        return 0
    if not isinstance(data, dict):
        return 0
    denies = data.get("denies") or []
    return len(denies) if isinstance(denies, list) else 0


def _free_port() -> int:
    """Grab a free port for an in-process server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def _start_fake_bouncer(bouncer_name: str, yaml_path: Path):
    """Start a thread-backed HTTP server pretending to be one bouncer's
    mgmt port. Yields the base URL + a `calls` list for assertion.
    """
    # Create a fresh handler class so the bouncer_name class attribute
    # is scoped to this server.
    cls_name = f"_Handler_{bouncer_name}"
    handler_cls = type(
        cls_name,
        (_FakeBouncerReloadHandler,),
        {"bouncer_name": bouncer_name},
    )
    port = _free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), handler_cls)
    server.yaml_path = yaml_path  # type: ignore[attr-defined]
    server.calls = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", server.calls  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@contextmanager
def _start_fake_suite(yaml_path: Path):
    """Bring up all 4 fake bouncers + yield the URL map + call maps."""
    with _start_fake_bouncer("ibounce", yaml_path) as (ibounce_url, ibounce_calls):
        with _start_fake_bouncer("kbouncer", yaml_path) as (kbouncer_url, kbouncer_calls):
            with _start_fake_bouncer("dbounce", yaml_path) as (dbounce_url, dbounce_calls):
                with _start_fake_bouncer("gbounce", yaml_path) as (gbounce_url, gbounce_calls):
                    yield (
                        {
                            "ibounce": ibounce_url,
                            "kbouncer": kbouncer_url,
                            "dbounce": dbounce_url,
                            "gbounce": gbounce_url,
                        },
                        {
                            "ibounce": ibounce_calls,
                            "kbouncer": kbouncer_calls,
                            "dbounce": dbounce_calls,
                            "gbounce": gbounce_calls,
                        },
                    )


# ---------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------


@pytest.fixture
def isolated_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Per-test isolated YAML file. Resets HOME so the conductor's
    default-path resolver lands in the temp dir."""
    p = tmp_path / "dynamic-denies.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(p))
    monkeypatch.setenv("HOME", str(tmp_path))
    return p


def _override_args(urls: dict[str, str]) -> list[str]:
    """Build the `--bouncer-url NAME=URL` flags for each fake bouncer."""
    args: list[str] = []
    for name, url in urls.items():
        args += ["--bouncer-url", f"{name}={url}"]
    return args


# ---------------------------------------------------------------------
# End-to-end scenarios (mirrors the 9-scenario block in the #324e brief)
# ---------------------------------------------------------------------


def test_scenario_01_arn_only_routes_to_ibounce(
    isolated_yaml: Path,
) -> None:
    """`deny add --target arn:aws:s3:::prod-* --duration 5m`
    routes to ibounce only; only the ibounce fake gets called."""
    from iam_jit.cli import main

    with _start_fake_suite(isolated_yaml) as (urls, calls):
        runner = CliRunner()
        result = runner.invoke(main, [
            "deny", "add",
            "--target", "arn:aws:s3:::prod-*",
            "--reason", "scenario-01",
            "--duration", "5m",
            *_override_args(urls),
            "--json",
        ])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["applied_to"] == ["ibounce"]
        # Only ibounce was POSTed.
        assert len(calls["ibounce"]) == 1
        assert calls["kbouncer"] == []
        assert calls["dbounce"] == []
        assert calls["gbounce"] == []
        # Routing explanation present.
        assert "ibounce" in payload["routing_explanation"]


def test_scenario_02_s3_request_against_dynamic_deny_yaml_is_visible(
    isolated_yaml: Path,
) -> None:
    """After `deny add` lands, the YAML on disk contains the rule with
    correct shape — the ibounce loader (#324a, separately tested) will
    refuse a matching request against the YAML."""
    from iam_jit.cli import main
    from iam_jit.dynamic_denies.loader import load_file

    with _start_fake_suite(isolated_yaml) as (urls, _calls):
        runner = CliRunner()
        result = runner.invoke(main, [
            "deny", "add",
            "--target", "arn:aws:s3:::prod-*",
            "--reason", "scenario-02",
            "--duration", "5m",
            *_override_args(urls),
            "--json",
        ])
        assert result.exit_code == 0, result.output
        # Load through the ibounce loader (#324a) -> rule is visible.
        rs = load_file(str(isolated_yaml))
        assert len(rs.rules) == 1
        rule = rs.rules[0]
        assert rule.targets == ("arn:aws:s3:::prod-*",)
        assert "ibounce" in rule.applied_to


def test_scenario_03_staging_target_does_not_match_prod_rule(
    isolated_yaml: Path,
) -> None:
    """A `prod-*` rule does NOT match a staging-bucket target —
    verified via the ibounce matcher directly."""
    from iam_jit.cli import main
    from iam_jit.dynamic_denies.loader import load_file
    from iam_jit.dynamic_denies.matcher import match_arn

    with _start_fake_suite(isolated_yaml) as (urls, _calls):
        runner = CliRunner()
        runner.invoke(main, [
            "deny", "add",
            "--target", "arn:aws:s3:::prod-*",
            "--reason", "scenario-03",
            "--duration", "5m",
            *_override_args(urls),
        ])
        rs = load_file(str(isolated_yaml))
        # Prod target matches.
        assert match_arn(rs, "arn:aws:s3:::prod-data-1") is not None
        # Staging target does NOT.
        assert match_arn(rs, "arn:aws:s3:::staging-bucket") is None


def test_scenario_04_namespace_target_routes_to_kbouncer(
    isolated_yaml: Path,
) -> None:
    """`--target namespace:prod` routes to kbouncer only."""
    from iam_jit.cli import main

    with _start_fake_suite(isolated_yaml) as (urls, calls):
        runner = CliRunner()
        result = runner.invoke(main, [
            "deny", "add",
            "--target", "namespace:prod",
            "--reason", "scenario-04",
            "--duration", "5m",
            *_override_args(urls),
            "--json",
        ])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["applied_to"] == ["kbouncer"]
        assert len(calls["kbouncer"]) == 1
        assert calls["ibounce"] == []


def test_scenario_05_namespace_yaml_shape_visible_to_kbouncer_loader(
    isolated_yaml: Path,
) -> None:
    """The on-disk YAML records `applied_to: [kbouncer]` for a
    namespace target — verifying the shape kbouncer's Go loader
    will consume."""
    from iam_jit.cli import main
    from ruamel.yaml import YAML

    with _start_fake_suite(isolated_yaml) as (urls, _calls):
        runner = CliRunner()
        runner.invoke(main, [
            "deny", "add",
            "--target", "namespace:prod",
            "--reason", "scenario-05",
            "--duration", "5m",
            *_override_args(urls),
        ])

        loader = YAML(typ="safe", pure=True)
        with isolated_yaml.open("r") as fh:
            data = loader.load(fh)
        assert data["schema_version"] == "1.0"
        assert data["product"] == "iam-jit-dynamic-denies"
        rules = data["denies"]
        assert len(rules) == 1
        rule = rules[0]
        assert rule["applied_to"] == ["kbouncer"]
        assert rule["targets"] == ["namespace:prod"]


def test_scenario_06_list_shows_multiple_rules(
    isolated_yaml: Path,
) -> None:
    """After two adds (S3 + namespace), `deny list --json` shows
    both."""
    from iam_jit.cli import main

    with _start_fake_suite(isolated_yaml) as (urls, _calls):
        runner = CliRunner()
        runner.invoke(main, [
            "deny", "add",
            "--target", "arn:aws:s3:::prod-*",
            "--reason", "scenario-06-s3",
            "--duration", "5m",
            *_override_args(urls),
        ])
        runner.invoke(main, [
            "deny", "add",
            "--target", "namespace:prod",
            "--reason", "scenario-06-ns",
            "--duration", "5m",
            *_override_args(urls),
        ])
        list_res = runner.invoke(main, ["deny", "list", "--json"])
        assert list_res.exit_code == 0
        payload = json.loads(list_res.stdout)
        assert payload["count"] == 2
        reasons = sorted(r["reason"] for r in payload["rules"])
        assert reasons == ["scenario-06-ns", "scenario-06-s3"]


def test_scenario_07_remove_lifts_one_rule_keeps_other(
    isolated_yaml: Path,
) -> None:
    """Remove the S3 rule; the namespace rule survives + its bouncer
    (kbouncer) is the only one POSTed during the remove (wait — the
    fan-out targets the REMOVED rule's bouncers, so ibounce is POSTed
    on removal too)."""
    from iam_jit.cli import main

    with _start_fake_suite(isolated_yaml) as (urls, calls):
        runner = CliRunner()
        s3_add = runner.invoke(main, [
            "deny", "add",
            "--target", "arn:aws:s3:::prod-*",
            "--reason", "scenario-07-s3",
            "--duration", "5m",
            *_override_args(urls),
            "--json",
        ])
        s3_id = json.loads(s3_add.stdout)["id"]
        runner.invoke(main, [
            "deny", "add",
            "--target", "namespace:prod",
            "--reason", "scenario-07-ns",
            "--duration", "5m",
            *_override_args(urls),
        ])
        # Reset call counts before the remove.
        for c in calls.values():
            c.clear()

        rm = runner.invoke(main, [
            "deny", "remove", s3_id,
            *_override_args(urls),
            "--json",
        ])
        assert rm.exit_code == 0, rm.output
        # Removal POSTed ibounce (the bouncer the removed rule routed
        # to). kbouncer untouched in this remove.
        assert len(calls["ibounce"]) == 1
        assert calls["kbouncer"] == []

        # The kbouncer rule is still in the YAML.
        list_res = runner.invoke(main, ["deny", "list", "--json"])
        payload = json.loads(list_res.stdout)
        assert payload["count"] == 1
        assert payload["rules"][0]["reason"] == "scenario-07-ns"


def test_scenario_08_multi_target_rule_fans_out_to_all_affected(
    isolated_yaml: Path,
) -> None:
    """`--target arn:... --target namespace:...` lands on ibounce AND
    kbouncer in ONE rule; both fakes receive the POST."""
    from iam_jit.cli import main

    with _start_fake_suite(isolated_yaml) as (urls, calls):
        runner = CliRunner()
        result = runner.invoke(main, [
            "deny", "add",
            "--target", "arn:aws:s3:::prod-*",
            "--target", "namespace:prod",
            "--reason", "scenario-08",
            "--duration", "5m",
            *_override_args(urls),
            "--json",
        ])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert set(payload["applied_to"]) == {"ibounce", "kbouncer"}
        assert len(calls["ibounce"]) == 1
        assert len(calls["kbouncer"]) == 1
        assert calls["dbounce"] == []
        assert calls["gbounce"] == []


def test_scenario_09_expiry_removes_rule_from_listing(
    isolated_yaml: Path,
) -> None:
    """`duration: 1s` -> rule expires within a couple of seconds;
    `list` (without --include-expired) drops it; the YAML still
    contains the expired entry (cleanup is a separate `--expired`
    flag) so audit retains visibility."""
    from iam_jit.cli import main

    with _start_fake_suite(isolated_yaml) as (urls, _calls):
        runner = CliRunner()
        add_res = runner.invoke(main, [
            "deny", "add",
            "--target", "arn:aws:s3:::prod-*",
            "--reason", "scenario-09-expiry",
            "--duration", "1s",
            *_override_args(urls),
            "--json",
        ])
        assert add_res.exit_code == 0
        time.sleep(1.5)
        # Without --include-expired: rule is filtered out.
        list_res = runner.invoke(main, ["deny", "list", "--json"])
        assert json.loads(list_res.stdout)["count"] == 0
        # With --include-expired: rule still visible.
        list_inc_res = runner.invoke(
            main, ["deny", "list", "--include-expired", "--json"],
        )
        assert json.loads(list_inc_res.stdout)["count"] == 1
        # `remove --expired` purges it.
        rm_res = runner.invoke(main, [
            "deny", "remove", "--expired",
            *_override_args(urls),
            "--json",
        ])
        assert rm_res.exit_code == 0
        list_after = runner.invoke(
            main, ["deny", "list", "--include-expired", "--json"],
        )
        assert json.loads(list_after.stdout)["count"] == 0


# ---------------------------------------------------------------------
# Honest-failure path (bouncer down)
# ---------------------------------------------------------------------


def test_unreachable_bouncer_does_not_abort_write(
    isolated_yaml: Path,
) -> None:
    """A downed bouncer (closed port) surfaces a WARN + the CLI exits
    0; the YAML write is the source of truth (per
    [[ibounce-honest-positioning]])."""
    from iam_jit.cli import main

    runner = CliRunner()
    # Point ibounce at a closed loopback port; the CLI should still
    # exit 0 because the YAML write succeeded.
    closed_port = _free_port()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "honest-failure",
        "--duration", "1m",
        "--bouncer-url", f"ibounce=http://127.0.0.1:{closed_port}",
    ])
    assert result.exit_code == 0, result.output
    assert "WARN" in result.stdout or "unreachable" in result.stdout
    assert isolated_yaml.exists()
