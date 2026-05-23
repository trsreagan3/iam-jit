# Anomaly Detection (Phase H)

Phase H ships per-agent **behavioral anomaly detection** as an
opt-in layer the bouncer composes on top of the deterministic deny
floor. The detector learns a rolling 14-day baseline of each
agent's action mix, scores every request via a per-dimension
z-score ensemble, and (in `block` mode) tightens a floor-ALLOW to
DENY when an action's score crosses the operator-configured
sensitivity threshold.

Per [[scorer-is-ground-truth]] anomaly detection is **advisory** —
the deterministic floor (profile + dynamic-deny + safe-default)
always wins on conflict. Per [[ibounce-honest-positioning]] the
operator-observable surface (`iam-jit posture`, `/healthz`, OCSF
event stream) reports the detector's state HONESTLY: enabled vs
off, alert vs block, alert counts, last-emit timestamp.

Status: **ibounce-only at v1.0**. kbouncer / dbounce / gbounce
Phase H parity ships in v1.0+1 (see task #508).

---

## When to enable

Anomaly detection is most valuable when:

* You're running ibounce in a **discovery** posture (no enforcing
  profile) and want a passive "what does this agent normally do?"
  surface that flags drift before it becomes an incident.
* You're running with a `safe-default` (or other) deny floor and
  want a **second layer** that catches novel agent behavior even
  when the action passes the floor's allowlist (defense-in-depth
  per [[bouncer-positioning-locked-iam]]).
* You operate a **multi-agent fleet** where each agent has a
  distinct identity (e.g. Claude Code vs Codex CLI vs a CI runner)
  and you want per-agent baselines instead of one-size-fits-all
  static rules.

Skip it when:

* Your agent population is very small + traffic is very low (the
  baseline never matures and cold-start fallback dominates).
* You're already running a `strict` profile that denies anything
  not explicitly listed (anomaly detection adds no signal because
  every novel action already gets denied by the floor).

---

## Enabling

### Quick start (CLI)

```bash
ibounce run --anomaly-detection alert
```

That's it. The hook installs at startup, the baseline DB lives at
`~/.iam-jit/anomaly-baseline.db`, and every request is scored.
**Alert mode never tightens ALLOW to DENY** — it's purely
observational. To start blocking on anomalies:

```bash
ibounce run --anomaly-detection block --anomaly-sensitivity medium
```

### Declarative (`.iam-jit.yaml`)

```yaml
iam-jit:
  anomaly_detection:
    enabled: true
    mode: alert            # alert | block
    sensitivity: medium    # low (3.0σ) | medium (2.0σ) | high (1.5σ)
    baseline_window: 14d
```

CLI flags override declarative values; declarative values override
shipped defaults. The discovery flow matches the
`audit-chain` / `retention` blocks (per [[apply-config-export-wire-divergence]]).

---

## Modes

| Mode | Scoring | Enforcement | Baseline writes |
| --- | --- | --- | --- |
| `off` (default) | none | none | none |
| `alert` | every request | NEVER tightens ALLOW | yes |
| `block` | every request | tightens ALLOW → DENY when anomalous + floor allowed | yes |
| `detection-only` | every request | NEVER tightens (advisory) | yes |

`detection-only` is the same advisory shape as `alert`, but does
NOT require a configured profile — designed for the
[[discovery-first-default]] deployment shape where the bouncer is
in pass-through observation mode.

Shorthand: `ibounce run --detection-only` = `--anomaly-detection
detection-only`.

---

## Sensitivity

`--anomaly-sensitivity {low,medium,high}` maps to the z-score
threshold the detector flags above:

* `low` → 3.0σ (quietest; only the most extreme outliers)
* `medium` → 2.0σ (default; ~5% false-positive rate on a normal
  distribution)
* `high` → 1.5σ (loudest; ~13% false-positive rate)

Per [[ibounce-honest-positioning]] the default is conservative
(`medium`) so the operator doesn't get flooded on day 1; raise to
`high` after the baseline matures.

---

## Cold-start period

The detector reports `verdict: insufficient_data` (and `block`
mode does NOT tighten) until the per-agent baseline reaches
`min_actions_for_baseline` (default: 50 observations).

During cold start the F.2 fallback consults the #404 deny
classifier so well-known dangerous actions (root key creation,
PassRole, etc.) still flag even before the baseline matures. The
fallback path is logged in OCSF events as `cold_start_fallback_used: true`.

**Implication for `block` mode**: on a fresh deployment, the hook
runs but does NOT tighten anything until the baseline matures.
This is intentional — denying novel-but-benign actions is the
exact "block-happy = uninstalled" failure mode
[[safety-mode-lean-permissive]] warns against.

---

## OCSF events

Every anomalous verdict emits an `anomaly_detected` synthetic event
(`class_uid: 6003`, `activity_name: anomaly_detected`) through the
bouncer's existing audit-export channels (JSONL log + webhook +
routes + object storage). Shape:

```json
{
  "class_uid": 6003,
  "activity_name": "anomaly_detected",
  "severity": "High",
  "actor": {"user": {"name": "claude-code:abc123"}},
  "api": {"operation": "anomaly_detected"},
  "unmapped": {
    "iam_jit": {
      "event_type": "anomaly_detected",
      "anomaly": {
        "anomaly_score": 0.87,
        "verdict": "anomalous",
        "explanations": [...],
        "mitre_atlas_techniques": [...],
        "baseline_observations": 142
      },
      "mode": "block",
      "action": "iam:DeleteUser",
      "resource": "arn:aws:iam::123:user/svc-build"
    }
  }
}
```

In `block` mode the bouncer ALSO writes a follow-up decision event
with `decision_source: "anomaly_detection"` and the synthetic 403
response carries `caught_by_bouncer: ibounce` + `deny_source_classified:
anomaly_detection` per [[ambient-value-prop-and-friction-framing]].

---

## Verifying it's running

Per [[ibounce-honest-positioning]] the operator MUST be able to
verify the hook is actually wired. Three places to check:

```bash
# 1. iam-jit posture — single-line per-bouncer summary
iam-jit posture
# ...
# Bouncers:
#   ibounce: RUNNING on 127.0.0.1:8767
#     Mode: cooperative   Profile: full-user
#     Anomaly detection: enabled (mode=alert, sensitivity=medium, alerts_emitted=0)
```

```bash
# 2. /healthz — structured shape for monitoring
curl -s http://127.0.0.1:8767/healthz | jq .anomaly_detection
# {
#   "enabled": true,
#   "mode": "alert",
#   "sensitivity": "medium",
#   "baseline_window_seconds": 1209600,
#   "baseline_path": "/Users/<you>/.iam-jit/anomaly-baseline.db",
#   "detection_only": false,
#   "alerts_emitted_total": 3,
#   "last_alert_at_unix": 1779540000.12
# }
```

```bash
# 3. iam-jit anomaly status — baseline DB-level inspection
iam-jit anomaly status
# ...
# Tracked agents: 4
#   - claude-code:abc123
#   - codex-cli:xyz789
#   - ci-runner:gh-actions
#   - smoke-test
```

If `posture` and `/healthz` BOTH report `anomaly_detection: None`
after you set the gate, the hook failed to install. Look in the
bouncer's stderr for the LOUD warning:

```
anomaly_detection: CONFIGURED but NOT WIRED — reason: <X>
  (operator action needed; the hook will NOT score requests
   until this is resolved)
```

Common causes:
* Baseline path is unwritable (e.g. `~/.iam-jit` owned by root).
  Fix the permission OR set `IAM_JIT_ANOMALY_BASELINE_PATH=/path/you/own`.
* Bad CLI flag value (e.g. typo'd `--anomaly-baseline-window 14days`
  instead of `14d`). Read the error + fix the value.

---

## Trade-offs (honest list)

* **Per-process baseline**: the SQLite baseline lives on the
  bouncer's local disk. Per [[independence-as-security-property]]
  + [[no-hosted-saas]] there is NO central aggregation; if you
  run multiple ibounce instances they each maintain their own
  baseline. Use a shared baseline path (NFS, EFS) if you want
  consistent scoring across instances, but be aware of SQLite +
  network-filesystem sharp edges.
* **z-score-only signal**: v1.0 uses per-dimension z-scores +
  threat-feed boost + #404 classifier fallback. No deep model.
  See the F.5 MITRE ATLAS pre-scoring path for the patterns that
  ARE caught even before the baseline matures.
* **Block-mode false positives**: `block` mode tightens on
  ANYTHING above the threshold. If your agent legitimately drifts
  (e.g. a feature ship adds new actions), you'll see denies. Stay
  in `alert` mode for the first 2-4 weeks; flip to `block` once
  you've seen the false-positive rate.
* **Cold start ≠ no protection**: during cold start the F.2
  classifier fallback DOES catch the well-known dangerous actions
  even if the baseline is empty. Read
  `src/iam_jit/anomaly_detection/detector.py:_try_classifier_fallback`
  for the exact list.
* **Restart-required mode switch**: changing `--anomaly-detection`
  requires a `ibounce run` restart (the hook is installed at
  startup). Hot-reload is roadmap, not v1.0.

---

## Related

* `docs/HARDENING-AGAINST-PROMPT-INJECTION.md` — anomaly detection
  is Layer 5 of the 6-layer defense.
* `docs/PRODUCTION-LOG-STORAGE.md` — the OCSF anomaly events land
  in the same audit-export channels as decision events.
* [[scorer-is-ground-truth]] — why the deterministic floor wins
  on conflict.
* [[ambient-value-prop-and-friction-framing]] — why every deny
  surface frames "your bouncer caught X" not "ERROR".
