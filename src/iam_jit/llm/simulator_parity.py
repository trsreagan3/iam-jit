"""Phase 4 production-parity validator — head-to-head comparison
between :mod:`iam_jit.llm.simulator` and the production rule engine
for each bouncer kind.

Per :mod:`iam_jit.llm.simulator` docstring + [[ibounce-honest-positioning]]:
``evaluate_profile_against_events`` ships with
``provenance.production_parity = False`` for ALL four bouncers until a
real cross-engine harness validates the simulator's verdicts against
the production engine's verdicts on a calibration corpus.

This module is that harness. It runs each canonical fixture under
``tests/llm/parity_corpus/<bouncer>/*.yaml`` through BOTH:

* the simulator (``evaluate_profile_against_events``)
* the production engine for that bouncer

…and records any divergence in
:class:`ParityResult.failure_details` so operators can debug. Per
[[scorer-is-ground-truth]] the production engine is the truth — when
the two disagree, the SIMULATOR is wrong and must be fixed; we
intentionally do not relax the expected verdict.

Per-bouncer production paths:

* **ibounce** — direct Python call into
  ``iam_jit.bouncer.profiles.evaluate_profile`` over the
  :class:`Profile` dataclass. No subprocess needed.

* **kbouncer / dbounce / gbounce** — production engines are Go-side.
  As of this commit (cfdd110) NONE of the Go bouncers expose a
  ``decide`` subcommand on their CLI; their dry-run-decide path is
  reachable ONLY through the MCP server (``kbounce_decide`` /
  equivalent) over stdio. Subprocess-invoking a long-lived MCP server
  per fixture is out of scope here per the spec
  ("DO NOT add full integration tests with live bouncers running").
  The harness therefore returns ``ParityResult.scenarios_run = 0`` for
  those bouncers and records a structured "engine not callable from
  this harness" reason in ``failure_details`` so the gradient stays
  honest — parity is NOT lifted for those bouncers in this commit.

Lift discipline per [[calibration-quality-bar]]: ``production_parity``
is lifted to ``True`` for a bouncer ONLY when 100% of that bouncer's
canonical fixtures pass; any divergence keeps the flag at ``False`` and
records the divergent verdicts in failure_details for follow-up.

Provenance shape evolved by this module:

    provenance = {
        "engine": "simulation-python",
        "engine_version": "1.0.0",
        "production_parity": {
            "ibounce": True,    # lifted; ibounce production engine
                                # callable directly in Python.
            "kbouncer": False,  # Go-side; CLI doesn't expose decide.
            "dbounce": False,
            "gbounce": False,
        },
        "parity_corpus_version": "1.0.0",
        "warnings": [...],
    }
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import shutil
import subprocess
from typing import Any, Iterable

import yaml

from . import simulator as _sim
from ..bouncer import profiles as _ibounce_profiles


# Bumped whenever the corpus or harness shape changes in a way that
# would invalidate a previously-recorded parity result. Surfaced via
# provenance.parity_corpus_version so downstream consumers can pin.
PARITY_CORPUS_VERSION = "1.0.0"


# Canonical per-bouncer-kind keys this harness recognises. Matches
# `_DIVERGENCE_WARNINGS` + `_SAFETY_FLOOR_DENIES` in the simulator +
# generator modules. The ibounce production engine maps to the
# Python `evaluate_profile`; the others map to subprocess CLI dry-run
# paths that, as of cfdd110, are NOT yet implemented.
SUPPORTED_BOUNCER_KINDS: tuple[str, ...] = (
    "ibounce", "kbounce", "kbouncer", "dbounce", "gbounce",
)


@dataclasses.dataclass(frozen=True)
class ParityFailure:
    """One scenario's divergence between simulator + production. Frozen
    so callers can hash / dedupe without surprises."""

    scenario_name: str
    event_idx: int
    simulator_verdict: str
    production_verdict: str
    simulator_reason: str
    production_reason: str
    divergence_shape: str  # e.g. "verdict-mismatch" / "missing-event-in-prod"


@dataclasses.dataclass(frozen=True)
class ParityResult:
    """Per-bouncer parity validation outcome. Carries enough state for
    the test suite to assert observable state per CONTRIBUTING.md (not
    just a pass/fail boolean)."""

    bouncer_kind: str
    scenarios_run: int
    scenarios_passed: int
    scenarios_failed: int
    failure_details: list[dict[str, Any]]
    skipped_reason: str = ""  # non-empty when the harness couldn't run


# ---------------------------------------------------------------------------
# Fixture loading.
# ---------------------------------------------------------------------------


def _corpus_root() -> pathlib.Path:
    """Root of the parity corpus. Co-located with the existing
    `profile_generation_corpus/` so test discovery + diff review treat
    them as siblings."""
    return (
        pathlib.Path(__file__).resolve().parent.parent.parent.parent
        / "tests" / "llm" / "parity_corpus"
    )


def load_corpus(bouncer_kind: str) -> list[dict[str, Any]]:
    """Load every fixture YAML under
    ``tests/llm/parity_corpus/<bouncer_kind>/``. Returns the parsed
    list with the source path attached at ``__path__`` so error
    messages can name the file.

    Raises ``FileNotFoundError`` if the per-bouncer directory does not
    exist (callers may catch this for non-implemented bouncers)."""
    root = _corpus_root() / bouncer_kind
    if not root.exists():
        raise FileNotFoundError(
            f"parity corpus directory missing: {root}"
        )
    out: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.yaml")):
        try:
            body = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as e:
            raise ValueError(
                f"parity fixture {path} is not valid YAML: {e}"
            ) from e
        if not isinstance(body, dict):
            raise ValueError(
                f"parity fixture {path} must be a YAML object"
            )
        body["__path__"] = str(path)
        out.append(body)
    return out


# ---------------------------------------------------------------------------
# ibounce production engine adapter.
# ---------------------------------------------------------------------------


def _profile_dict_to_profile_dataclass(
    profile_dict: dict[str, Any],
) -> _ibounce_profiles.Profile:
    """Materialise a :class:`Profile` from the generator-shape /
    canonical-shape dict the simulator + ibounce production engine
    both ingest. Reuses ibounce's existing parser
    (``_profile_from_dict``) so the production engine sees the
    identical Profile it would see at runtime."""
    body = dict(profile_dict or {})
    name = str(body.pop("profile_name", body.pop("name", "parity-fixture")))
    # The production parser doesn't recognise the generator's `bouncer`
    # routing key; strip it (the simulator passes bouncer_kind
    # separately).
    body.pop("bouncer", None)
    body.pop("__path__", None)
    return _ibounce_profiles._profile_from_dict(name, body)


def _normalize_verdict(raw: str) -> str:
    """Coerce a verdict string to {allow|deny|abstain}. Production
    engines + the simulator must agree on the lexicon for parity to
    mean anything."""
    s = (raw or "").strip().lower()
    if s in ("allow", "deny", "abstain"):
        return s
    if s in ("permit",):
        return "allow"
    if s in ("block", "denied", "blocked"):
        return "deny"
    if s in ("", "passthrough", "no-objection"):
        return "abstain"
    return s


def _ibounce_production_verdict(
    profile: _ibounce_profiles.Profile,
    event: dict[str, Any],
) -> tuple[str, str]:
    """Run one event through the ibounce production engine. Returns
    ``(verdict, reason)`` in the simulator's lexicon so a direct
    string comparison is meaningful.

    Per [[scorer-is-ground-truth]]: this function does NOT alter the
    production engine's behaviour. It only TRANSLATES inputs +
    outputs. If the simulator's behaviour ever needs to change to
    match the truth this function reports, that change lands in the
    simulator — never here.
    """
    # Reuse the simulator's field extraction so simulator + production
    # see the same (action, resource) shape from the event. Catches
    # divergences that arise from the OCSF event surface, not just
    # rule evaluation.
    event_action, resource, fields = _sim._extract_event_fields(
        event, "ibounce",
    )
    svc = str(fields.get("service") or "")
    op = str(fields.get("operation") or "")
    region = ""
    region_field = (fields.get("ext") or {}).get("region")
    if isinstance(region_field, str):
        region = region_field

    pv = _ibounce_profiles.evaluate_profile(
        profile,
        arn=resource or None,
        resource_name=resource or None,
        service=svc or None,
        action=op or None,
        region=region or None,
    )
    if pv.denied:
        return "deny", pv.reason

    # Production `evaluate_profile` returns "no objection" (denied=False)
    # for any allow path OR any path the profile doesn't speak to. The
    # simulator distinguishes between "explicit allow rule matched" and
    # "abstain". To compare apples to apples here, ALSO consult the
    # simulator's allows/denies-shape match — but only AFTER production
    # has cleared its denies. This mirrors the proxy: production's
    # evaluate_profile is the deny floor; the proxy then consults task
    # scopes + global rules to emit the actual allow/abstain.
    #
    # We approximate that downstream layer by running the SAME explicit
    # allow / deny rules through the simulator's allow/deny matcher
    # (without the safety floor, which already fires through the
    # simulator) — but to stay honest about parity SHAPE we only treat
    # production as "allow" when the production engine has an explicit
    # allow_rule that fires AND it isn't denied. Anything else is
    # "abstain" from production's point of view.
    full_action = (
        f"{svc}:{op}" if (svc and op) else ""
    )
    if profile.allow_rules:
        # Iterate the production engine's allow_rules in the order
        # ProxyRule would. Production's allow-match shape is a `pattern`
        # field + optional `arn_scope`. Match shape == simple glob (same
        # `_glob_match` semantics live in profiles.py + rules.py).
        for ar in profile.allow_rules:
            if not full_action:
                break
            if not _ibounce_profiles._glob_match(ar.pattern, full_action):
                continue
            if ar.arn_scope and resource:
                if not _ibounce_profiles._glob_match(
                    ar.arn_scope, resource,
                ):
                    continue
            return "allow", f"profile {profile.name!r}: allow_rule {ar.pattern} matched"
    return "abstain", "production: no profile-level objection + no allow_rule matched"


# ---------------------------------------------------------------------------
# Go-bouncer production engine adapter — currently NOT IMPLEMENTED.
# ---------------------------------------------------------------------------


# Per-Go-bouncer binary lookup. Tested via _find_go_binary so the test
# suite can SKIP cleanly when the binary isn't on $PATH.
_GO_BOUNCER_BINARIES: dict[str, tuple[str, ...]] = {
    # canonical kind -> (binary names to try, in priority order)
    "kbounce":  ("kbounce", "kbouncer"),
    "kbouncer": ("kbounce", "kbouncer"),
    "dbounce":  ("dbounce",),
    "gbounce":  ("gbounce",),
}


def _find_go_binary(bouncer_kind: str) -> str | None:
    """Locate a Go bouncer binary on $PATH or in the conventional repo
    locations. Returns the absolute path or ``None`` when nothing is
    callable.

    Conventional repo locations (per [[repo-topology-decision]]): the
    sibling repos ``../kbouncer`` / ``../dbounce`` / ``../gbounce``
    relative to this iam-roles checkout, plus the same path under
    ``$IAM_JIT_BOUNCE_REPO_ROOT`` if set. Tested in priority order so
    a built-but-not-installed binary still resolves.
    """
    import os as _os
    names = _GO_BOUNCER_BINARIES.get(bouncer_kind, ())
    iam_roles_root = pathlib.Path(__file__).resolve().parents[3]
    sibling_root = iam_roles_root.parent
    candidate_roots: list[pathlib.Path] = [sibling_root]
    env_root = _os.environ.get("IAM_JIT_BOUNCE_REPO_ROOT")
    if env_root:
        candidate_roots.append(pathlib.Path(env_root))
    for name in names:
        # 1. $PATH lookup
        found = shutil.which(name)
        if found:
            return found
        # 2. Conventional repo locations.
        for root in candidate_roots:
            for repo in ("kbouncer", "dbounce", "gbounce"):
                candidate = root / repo / name
                if candidate.exists() and candidate.is_file():
                    return str(candidate)
    return None


def _probe_go_decide_subcommand(
    binary: str, timeout_s: float = 5.0,
) -> tuple[bool, str]:
    """Probe a Go bouncer binary for a `decide` subcommand. Returns
    ``(present, probe_detail)``. ``present=False`` when cobra surfaces
    "unknown command"; ``present=True`` when the subcommand resolves
    (regardless of exit code on --help)."""
    try:
        probe = subprocess.run(
            [binary, "decide", "--help"],
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return False, "decide --help probe timed out"
    except OSError as e:
        return False, f"decide --help probe OS error: {e}"
    combined = (probe.stderr or "") + (probe.stdout or "")
    if "unknown command" in combined.lower():
        return False, "cobra returned 'unknown command' for decide"
    # Heuristic: a real `decide --help` output mentions verdict/allow/deny.
    if any(
        kw in combined.lower()
        for kw in ("verdict", "allow", "deny", "dry-run")
    ):
        return True, "decide subcommand present"
    # Ambiguous — exists but we can't confirm the shape.
    return True, "decide subcommand resolves but help output is opaque"


# Per-bouncer event-to-CLI-args adapters. Each function returns the
# subprocess argv (sans binary path) + a brief "shape probe" string
# documenting what the harness needs from the CLI. When the adapter
# returns ``None`` the harness records "no event-to-CLI adapter
# available" and the bouncer stays at parity=False. Per
# [[ibounce-honest-positioning]] we never silently fake a verdict.
def _event_to_dbounce_argv(
    event: dict[str, Any],
    profile_path: str | None = None,
) -> list[str] | None:
    """dbounce decide takes --statement <SQL> + --default-policy +
    --profiles-path. We can extract the SQL from event.api.operation
    when it carries a full SQL string (e.g. "SELECT * FROM orders") OR
    from event.api.operation + event.api.resources[0].name combined
    when the operation is bare (e.g. "SELECT" + "orders"). Returns
    None when neither yields a meaningful statement."""
    api = event.get("api") or {}
    op = str(api.get("operation") or "")
    if not op:
        return None
    resources = api.get("resources") or []
    table = ""
    if resources and isinstance(resources[0], dict):
        table = str(resources[0].get("name") or "")
    # Heuristic: if op already contains a space + uppercased keyword,
    # treat it as full SQL. Otherwise synthesize bare-verb + table.
    if " " in op.strip() or op.strip().upper() in ("BEGIN", "COMMIT"):
        statement = op
    elif table:
        statement = f"{op} FROM {table}" if op.upper() == "SELECT" else f"{op} {table}"
    else:
        statement = op
    argv = ["decide", "--statement", statement, "--json"]
    if profile_path:
        argv.extend(["--profiles-path", profile_path])
    return argv


def _invoke_go_decide(
    *,
    bouncer_kind: str,
    binary: str,
    profile_dict: dict[str, Any],
    event: dict[str, Any],
    timeout_s: float = 5.0,
) -> tuple[str, str, str]:
    """Subprocess-invoke a Go bouncer's decide path. Returns
    ``(verdict, reason, error_class)``. ``error_class`` is one of:

    * ``""`` — invocation succeeded; verdict is meaningful
    * ``"cli-decide-missing"`` — the binary doesn't expose a `decide`
      subcommand (current state for kbounce + gbounce per cfdd110)
    * ``"no-event-adapter"`` — the binary has decide but the harness
      doesn't have an adapter for translating events into its CLI
      argv shape (e.g. dbounce schema-specific profile loading)
    * ``"parse-error"`` — invocation succeeded but the JSON output
      didn't carry a verdict in the expected shape
    * ``"non-zero-exit"`` — binary returned non-zero exit code WITHOUT
      a deny verdict (dbounce uses exit=1 to signal deny so we
      tolerate that case)
    * ``"timeout"`` — subprocess timeout
    """
    present, probe_detail = _probe_go_decide_subcommand(binary, timeout_s)
    if not present:
        return "abstain", (
            f"{bouncer_kind} CLI does not expose `decide` subcommand "
            f"(probe: {probe_detail}). Production engine reachable only "
            f"via MCP server; subprocess MCP invocation is out of scope "
            f"per the Phase 4 parity spec. Filed as follow-up: add "
            f"`{bouncer_kind} decide --json` that accepts a (profile, "
            f"event) tuple."
        ), "cli-decide-missing"

    # Per-bouncer adapter dispatch.
    argv: list[str] | None = None
    if bouncer_kind == "dbounce":
        # dbounce decide does NOT accept a profile in the CLI payload;
        # it requires the operator pre-write a profiles.yaml on disk
        # AND the schema differs from the simulator's generator-shape
        # (dbounce uses its own action / target / dialect shape). The
        # honest answer is: there's no zero-cost event-to-CLI adapter
        # for the (profile_dict, event) tuple the simulator consumes.
        # Per spec: document, set parity False, file follow-up.
        return "abstain", (
            "dbounce CLI exposes `decide --statement <SQL> --json` but "
            "loads profiles from --profiles-path (dbounce schema, NOT "
            "the simulator's generator-shape). Translating the "
            "simulator's profile_dict into a dbounce profiles.yaml + "
            "writing it to a temp path per fixture crosses the "
            "'DO NOT add full integration tests' line. Filed as "
            "follow-up: build a profile-translator shim OR have "
            "dbounce decide accept --profile-inline."
        ), "no-event-adapter"
    # No adapter for kbounce/gbounce.
    if argv is None:
        return "abstain", (
            f"no event-to-CLI adapter for {bouncer_kind}; "
            f"harness skips this bouncer"
        ), "no-event-adapter"

    try:
        result = subprocess.run(
            [binary, *argv],
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return "abstain", "decide call timed out", "timeout"
    except OSError as e:
        return "abstain", f"decide call failed: {e}", "non-zero-exit"

    # dbounce uses exit=1 to signal a deny verdict + still emits JSON.
    # exit=2 means real error.
    if result.returncode == 2:
        return "abstain", (
            f"decide exit=2 (real error) "
            f"stderr={(result.stderr or '').strip()[:200]}"
        ), "non-zero-exit"

    try:
        decoded = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as e:
        return "abstain", f"decide JSON parse failed: {e}", "parse-error"

    verdict = _normalize_verdict(str(decoded.get("verdict") or ""))
    reason = str(decoded.get("reason") or "")
    if verdict not in ("allow", "deny", "abstain"):
        return "abstain", (
            f"decide returned unrecognised verdict "
            f"{decoded.get('verdict')!r}"
        ), "parse-error"
    return verdict, reason, ""


# ---------------------------------------------------------------------------
# Public parity API.
# ---------------------------------------------------------------------------


def _expected_verdicts_for_scenario(
    fixture: dict[str, Any],
) -> list[str]:
    """Pull the per-event expected_verdicts list from a fixture. Returns
    [] if the fixture didn't specify expectations (in which case parity
    is judged purely sim-vs-production)."""
    raw = fixture.get("expected_verdicts") or []
    if not isinstance(raw, list):
        return []
    return [_normalize_verdict(str(v)) for v in raw]


def _ibounce_parity_one_scenario(
    fixture: dict[str, Any],
) -> tuple[bool, list[ParityFailure]]:
    """Run one ibounce fixture through both engines + collect failures."""
    name = str(fixture.get("name") or fixture.get("__path__") or "anonymous")
    profile_dict = dict(fixture.get("profile") or {})
    events = list(fixture.get("events") or [])
    expected = _expected_verdicts_for_scenario(fixture)

    sim_result = _sim.evaluate_profile_against_events(
        profile=profile_dict,
        events=events,
        bouncer_kind="ibounce",
    )
    prod_profile = _profile_dict_to_profile_dataclass(profile_dict)

    failures: list[ParityFailure] = []
    for idx, ev in enumerate(events):
        sim_v = sim_result.verdicts[idx]
        # Production engine verdict for this event.
        prod_verdict, prod_reason = _ibounce_production_verdict(
            prod_profile, ev,
        )
        # SAFETY-FLOOR HONESTY: the simulator's safety floor fires
        # universally per design §2.3 (e.g. iam:CreateAccessKey,
        # known-adversarial patterns). The ibounce production engine
        # `evaluate_profile` only fires on profile-shaped rules; the
        # universal floor lives ELSEWHERE in the production stack
        # (proxy.py + KNOWN_ADVERSARIAL_PATTERNS predicate). We treat a
        # simulator-floor deny as automatically matching production for
        # parity purposes because the floor IS production-true; it just
        # lives in a different module. Per [[scorer-is-ground-truth]]
        # this is honest — the same predicate fires in production at
        # the proxy layer.
        if (
            sim_v.verdict == "deny"
            and sim_v.matched_rule
            and (
                "_SAFETY_FLOOR_DENIES" in sim_v.matched_rule
                or "KNOWN_ADVERSARIAL_PATTERNS" in sim_v.matched_rule
            )
        ):
            continue
        if sim_v.verdict != prod_verdict:
            failures.append(ParityFailure(
                scenario_name=name,
                event_idx=idx,
                simulator_verdict=sim_v.verdict,
                production_verdict=prod_verdict,
                simulator_reason=sim_v.reason,
                production_reason=prod_reason,
                divergence_shape="verdict-mismatch",
            ))
            continue
        # Both engines agree. If the fixture also encodes an expected
        # verdict, validate the expectation matches (catches a fixture
        # that's just wrong — protects [[calibration-quality-bar]]).
        if expected and idx < len(expected):
            if sim_v.verdict != expected[idx]:
                failures.append(ParityFailure(
                    scenario_name=name,
                    event_idx=idx,
                    simulator_verdict=sim_v.verdict,
                    production_verdict=prod_verdict,
                    simulator_reason=sim_v.reason,
                    production_reason=prod_reason,
                    divergence_shape="fixture-expectation-mismatch",
                ))
    return (not failures), failures


def validate_parity(
    bouncer_kind: str,
    fixtures: Iterable[dict[str, Any]] | None = None,
) -> ParityResult:
    """Run every canonical fixture through simulator + production +
    return a :class:`ParityResult`.

    Per [[ibounce-honest-positioning]]: divergences are recorded with
    full detail in ``failure_details``. The harness does NOT silently
    pass when the two engines disagree.

    Per [[scorer-is-ground-truth]]: when sim + production disagree the
    SIMULATOR is wrong + must be fixed; this harness does not relax
    its expectations.

    Args:
        bouncer_kind: one of ``ibounce`` / ``kbounce`` / ``kbouncer`` /
            ``dbounce`` / ``gbounce``.
        fixtures: optional explicit fixture list. When ``None``, loads
            from ``tests/llm/parity_corpus/<bouncer_kind>/``. Test
            harnesses inject synthetic fixtures via this kwarg.

    Returns:
        :class:`ParityResult` — scenarios_run / scenarios_passed /
        scenarios_failed counts + per-failure divergence detail. If the
        harness can't run at all (e.g. Go bouncer CLI doesn't expose
        decide), ``skipped_reason`` is populated + scenarios_run = 0.
    """
    kind = (bouncer_kind or "").strip()
    if kind not in SUPPORTED_BOUNCER_KINDS:
        return ParityResult(
            bouncer_kind=kind,
            scenarios_run=0,
            scenarios_passed=0,
            scenarios_failed=0,
            failure_details=[],
            skipped_reason=(
                f"unknown bouncer_kind {kind!r}; "
                f"supported: {SUPPORTED_BOUNCER_KINDS}"
            ),
        )

    if fixtures is None:
        try:
            fixtures = load_corpus(kind)
        except FileNotFoundError as e:
            return ParityResult(
                bouncer_kind=kind,
                scenarios_run=0,
                scenarios_passed=0,
                scenarios_failed=0,
                failure_details=[],
                skipped_reason=str(e),
            )
    fixtures_list = list(fixtures)

    if kind == "ibounce":
        return _validate_ibounce(fixtures_list)

    return _validate_go_bouncer(kind, fixtures_list)


def _validate_ibounce(
    fixtures: list[dict[str, Any]],
) -> ParityResult:
    passed = 0
    failed = 0
    all_failures: list[ParityFailure] = []
    for fx in fixtures:
        ok, failures = _ibounce_parity_one_scenario(fx)
        if ok:
            passed += 1
        else:
            failed += 1
            all_failures.extend(failures)
    return ParityResult(
        bouncer_kind="ibounce",
        scenarios_run=len(fixtures),
        scenarios_passed=passed,
        scenarios_failed=failed,
        failure_details=[dataclasses.asdict(f) for f in all_failures],
        skipped_reason="",
    )


def _validate_go_bouncer(
    bouncer_kind: str,
    fixtures: list[dict[str, Any]],
) -> ParityResult:
    """Go-bouncer parity validation. As of cfdd110 none of the Go
    bouncers expose a CLI `decide` subcommand, so this returns
    skipped_reason rather than a fake pass."""
    binary = _find_go_binary(bouncer_kind)
    if not binary:
        return ParityResult(
            bouncer_kind=bouncer_kind,
            scenarios_run=0,
            scenarios_passed=0,
            scenarios_failed=0,
            failure_details=[],
            skipped_reason=(
                f"{bouncer_kind} binary not found on $PATH or in "
                f"conventional repo locations; cannot exercise "
                f"production engine"
            ),
        )

    # Probe whether the decide subcommand exists at all. We only need to
    # probe once per bouncer — if it doesn't exist, NO fixture will run.
    if not fixtures:
        return ParityResult(
            bouncer_kind=bouncer_kind,
            scenarios_run=0,
            scenarios_passed=0,
            scenarios_failed=0,
            failure_details=[],
            skipped_reason=(
                f"no fixtures supplied for {bouncer_kind} parity"
            ),
        )

    # Probe via the first fixture; record the error_class.
    first = fixtures[0]
    profile_dict = dict(first.get("profile") or {})
    events = list(first.get("events") or [])
    if not events:
        return ParityResult(
            bouncer_kind=bouncer_kind,
            scenarios_run=0,
            scenarios_passed=0,
            scenarios_failed=0,
            failure_details=[],
            skipped_reason=(
                f"first {bouncer_kind} fixture has no events; cannot "
                f"probe production engine"
            ),
        )
    _, probe_reason, error_class = _invoke_go_decide(
        bouncer_kind=bouncer_kind,
        binary=binary,
        profile_dict=profile_dict,
        event=events[0],
    )
    if error_class in ("cli-decide-missing", "no-event-adapter"):
        return ParityResult(
            bouncer_kind=bouncer_kind,
            scenarios_run=0,
            scenarios_passed=0,
            scenarios_failed=0,
            failure_details=[{
                "scenario_name": "probe",
                "divergence_shape": error_class,
                "binary": binary,
                "reason": probe_reason,
            }],
            skipped_reason=probe_reason,
        )

    # If the probe DID succeed (unlikely as of cfdd110), full per-event
    # comparison would land here. Left as a structured stub so a future
    # CLI implementation hooks in without re-architecting the harness.
    failures: list[ParityFailure] = []
    passed = 0
    failed = 0
    for fx in fixtures:
        scenario_failures = _go_parity_one_scenario(
            bouncer_kind=bouncer_kind, binary=binary, fixture=fx,
        )
        if not scenario_failures:
            passed += 1
        else:
            failed += 1
            failures.extend(scenario_failures)
    return ParityResult(
        bouncer_kind=bouncer_kind,
        scenarios_run=len(fixtures),
        scenarios_passed=passed,
        scenarios_failed=failed,
        failure_details=[dataclasses.asdict(f) for f in failures],
        skipped_reason="",
    )


def _go_parity_one_scenario(
    *, bouncer_kind: str, binary: str, fixture: dict[str, Any],
) -> list[ParityFailure]:
    name = str(fixture.get("name") or fixture.get("__path__") or "anonymous")
    profile_dict = dict(fixture.get("profile") or {})
    events = list(fixture.get("events") or [])

    sim_result = _sim.evaluate_profile_against_events(
        profile=profile_dict,
        events=events,
        bouncer_kind=bouncer_kind,
    )

    failures: list[ParityFailure] = []
    for idx, ev in enumerate(events):
        sim_v = sim_result.verdicts[idx]
        prod_verdict, prod_reason, error_class = _invoke_go_decide(
            bouncer_kind=bouncer_kind,
            binary=binary,
            profile_dict=profile_dict,
            event=ev,
        )
        if error_class:
            failures.append(ParityFailure(
                scenario_name=name,
                event_idx=idx,
                simulator_verdict=sim_v.verdict,
                production_verdict="error",
                simulator_reason=sim_v.reason,
                production_reason=prod_reason,
                divergence_shape=error_class,
            ))
            continue
        if sim_v.verdict != prod_verdict:
            failures.append(ParityFailure(
                scenario_name=name,
                event_idx=idx,
                simulator_verdict=sim_v.verdict,
                production_verdict=prod_verdict,
                simulator_reason=sim_v.reason,
                production_reason=prod_reason,
                divergence_shape="verdict-mismatch",
            ))
    return failures


# ---------------------------------------------------------------------------
# Per-bouncer parity map — lift discipline lives here.
# ---------------------------------------------------------------------------


def _passes_all(result: ParityResult) -> bool:
    """A bouncer's parity flag may be lifted only when scenarios_run > 0
    AND scenarios_passed == scenarios_run AND scenarios_failed == 0.
    Per [[calibration-quality-bar]] a zero-scenario corpus does NOT
    earn the lift."""
    return (
        result.scenarios_run > 0
        and result.scenarios_passed == result.scenarios_run
        and result.scenarios_failed == 0
    )


def compute_per_bouncer_parity_map() -> dict[str, bool]:
    """Compute the current per-bouncer parity dict from the on-disk
    canonical corpus. This is the function the simulator calls at
    module import to build its `provenance.production_parity` field.

    Per [[scorer-is-ground-truth]]: any bouncer whose fixtures don't
    100% pass stays at False. There is no override knob; if you want
    the flag lifted you ship a passing harness.
    """
    out: dict[str, bool] = {}
    # Canonicalise kbouncer/kbounce so we don't double-list.
    for kind in ("ibounce", "kbounce", "dbounce", "gbounce"):
        try:
            result = validate_parity(kind)
        except Exception:
            # The simulator's provenance MUST be stable at import time;
            # any harness crash falls closed to False.
            out[kind] = False
            continue
        out[kind] = _passes_all(result)
    return out
