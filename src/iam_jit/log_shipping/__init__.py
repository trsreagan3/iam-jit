"""#429 / §A68 — log shipping detection + opt-in setup.

Phase F launch-blocker. Today an operator who wants their bouncer's
OCSF audit firehose forwarded to a SIEM has to read 3 separate doc
pages (#257 webhook presets / #258 Security Lake / #317 S3 sink),
look up the right env-var names, hand-roll the right flag set, and
restart the bouncer. The §A68 wedge is a one-command auto-detect:

    iam-jit logs ship-to --detect

inspects the operator's environment for the standard signal markers
(AWS credentials file, ``DD_API_KEY``, ``SPLUNK_HEC_URL``, K8s pod
markers) + tells them which destinations are available + the exact
follow-up command to enable each. Then:

    iam-jit logs ship-to <destination>

prints the recommended flag set the operator can copy into their
bouncer command line. Per ``[[creates-never-mutates]]`` we do NOT
silently rewrite ``.iam-jit.yaml`` or restart the bouncer; the
operator decides when to apply.

Per ``[[v1-scope-bar]]`` this slice ships NO new SIEM adapters —
the presets (#257) + Security Lake (#258) + S3 sink (#317) already
exist. §A68 is the discovery + recommendation surface on top.

Per ``[[no-hosted-saas]]`` every recommended destination is operator-
controlled (their AWS account / their Datadog org / their Splunk
HEC). iam-jit-the-company is never on the billing path.

Per ``[[self-host-zero-billing-dependency]]`` detection runs entirely
locally — no calls out to AWS / Datadog / Splunk / K8s API. The
detectors only read env vars + filesystem markers the operator
already exposed to the bouncer process.
"""

from __future__ import annotations

from .detect import (
    Destination,
    DetectedDestination,
    DetectionEnv,
    capture_env,
    detect_destinations,
    recommend_flags,
)

__all__ = [
    "Destination",
    "DetectedDestination",
    "DetectionEnv",
    "capture_env",
    "detect_destinations",
    "recommend_flags",
]
