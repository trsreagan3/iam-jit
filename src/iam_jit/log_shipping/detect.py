"""#429 / §A68 — environment detection + flag recommendation.

Pure-function module: every detector takes a :class:`DetectionEnv`
snapshot (env vars + filesystem probes already resolved) and returns
zero or more :class:`DetectedDestination` records. This lets the CLI +
the tests + a future ``iam-jit posture`` integration all run the same
logic without each having to re-stub ``os.environ`` / ``pathlib`` /
``shutil``.

Per ``[[v1-scope-bar]]`` the destination catalog is intentionally
narrow — only the existing SIEM adapters (#257 / #258 / #317) get
recommendations. Adding a new destination means shipping a new
adapter; this module never invents one.

Per ``[[creates-never-mutates]]`` no destination is auto-applied. The
``apply_destination`` helper writes a snippet to stdout (or returns
it) the operator copies into their bouncer launch — explicit opt-in.

Detection markers
-----------------

* **AWS** — ``~/.aws/credentials`` exists OR ``AWS_ACCESS_KEY_ID``
  env var set OR ``AWS_PROFILE`` env var set. Maps to two
  destinations: ``cloudwatch-logs`` (via the #257 generic webhook
  preset pointed at an operator-provisioned API Gateway / Lambda
  intake) AND ``security-lake`` (via the existing #258 S3 NDJSON
  sink writing to an AWS Security Lake S3 bucket).
* **Datadog** — ``DD_API_KEY`` env var. Maps to ``datadog``
  destination (uses the #257 ``datadog`` webhook preset).
* **Splunk** — ``SPLUNK_HEC_URL`` or ``SPLUNK_HEC_TOKEN`` env var.
  Maps to ``splunk-hec`` (uses the #257 ``splunk-hec`` preset).
* **Kubernetes** — ``KUBERNETES_SERVICE_HOST`` env var OR
  ``/var/run/secrets/kubernetes.io/serviceaccount/token`` file
  exists. Maps to ``loki-elk`` destination (recommends pointing the
  #317 S3-compat sink at a cluster-local MinIO / ELK ingest, OR
  using the #257 generic webhook against a Loki HTTP endpoint).

The detectors are ANDed with the operator's opt-in: a positive
detection only surfaces the destination on ``--detect``; nothing is
applied until ``iam-jit logs ship-to <destination>`` is invoked.
"""

from __future__ import annotations

import dataclasses
import enum
import os
import pathlib
from collections.abc import Mapping
from typing import Any


class Destination(str, enum.Enum):
    """Destinations the auto-detector recognises.

    Each maps to an existing adapter:

      * ``cloudwatch-logs`` — #257 generic webhook preset against an
        operator-provisioned API Gateway / Lambda intake (or AWS
        CloudWatch Logs PutLogEvents via SigV4-signed HTTP — operator
        handles the auth side).
      * ``security-lake`` — #317 S3-compat NDJSON sink targeting an
        AWS Security Lake S3 bucket the operator provisions.
      * ``datadog`` — #257 ``datadog`` webhook preset (Logs HTTP
        intake; ``DD-API-KEY`` header).
      * ``splunk-hec`` — #257 ``splunk-hec`` webhook preset.
      * ``loki-elk`` — #317 S3-compat sink against a cluster-local
        MinIO / ELK ingest OR the #257 generic preset pointed at a
        Loki HTTP endpoint.
    """

    CLOUDWATCH_LOGS = "cloudwatch-logs"
    SECURITY_LAKE = "security-lake"
    DATADOG = "datadog"
    SPLUNK_HEC = "splunk-hec"
    LOKI_ELK = "loki-elk"


@dataclasses.dataclass(frozen=True)
class DetectionEnv:
    """Snapshot of the operator's environment for detection.

    Built by :func:`capture_env`; passed to :func:`detect_destinations`
    so the detector remains a pure function (easy to unit-test by
    constructing a synthetic env).
    """

    env: Mapping[str, str]
    aws_credentials_path_exists: bool
    aws_config_path_exists: bool
    k8s_serviceaccount_token_exists: bool


@dataclasses.dataclass(frozen=True)
class DetectedDestination:
    """One detection result.

    Carries the destination identifier + the marker(s) that triggered
    detection so the CLI can surface a human-readable "why we
    detected this" line.
    """

    destination: Destination
    markers: tuple[str, ...]
    summary: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "destination": self.destination.value,
            "markers": list(self.markers),
            "summary": self.summary,
        }


def capture_env(
    *,
    env: Mapping[str, str] | None = None,
    home_dir: pathlib.Path | None = None,
) -> DetectionEnv:
    """Take an OS-level snapshot to pass to :func:`detect_destinations`.

    ``env`` defaults to :data:`os.environ`. ``home_dir`` defaults to
    ``pathlib.Path.home()``. Both override hooks exist so tests can
    pin the inputs without monkeypatching the global namespace.
    """
    env_use = env if env is not None else os.environ
    home = home_dir if home_dir is not None else pathlib.Path.home()
    aws_creds = (home / ".aws" / "credentials").exists()
    aws_config = (home / ".aws" / "config").exists()
    k8s_token = pathlib.Path(
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ).exists()
    return DetectionEnv(
        env=dict(env_use),
        aws_credentials_path_exists=aws_creds,
        aws_config_path_exists=aws_config,
        k8s_serviceaccount_token_exists=k8s_token,
    )


def detect_destinations(
    detection_env: DetectionEnv,
) -> list[DetectedDestination]:
    """Return every destination the env signals support for.

    Order: AWS-derived destinations first (cloudwatch + security-lake),
    then Datadog, then Splunk, then K8s-derived. Operators who match
    multiple categories see them all; the CLI presents the list +
    asks them to pick one (or several) to apply.

    Per ``[[v1-scope-bar]]`` we never invent a destination — every
    return value maps to an already-shipped adapter. New destinations
    require new adapters; this function never silently widens scope.
    """
    out: list[DetectedDestination] = []
    out.extend(_detect_aws(detection_env))
    out.extend(_detect_datadog(detection_env))
    out.extend(_detect_splunk(detection_env))
    out.extend(_detect_kubernetes(detection_env))
    return out


def _detect_aws(d: DetectionEnv) -> list[DetectedDestination]:
    """AWS markers → cloudwatch-logs + security-lake recommendations."""
    markers: list[str] = []
    if d.aws_credentials_path_exists:
        markers.append("~/.aws/credentials")
    if d.aws_config_path_exists:
        markers.append("~/.aws/config")
    if d.env.get("AWS_ACCESS_KEY_ID"):
        markers.append("AWS_ACCESS_KEY_ID")
    if d.env.get("AWS_PROFILE"):
        markers.append(f"AWS_PROFILE={d.env['AWS_PROFILE']}")
    if d.env.get("AWS_SESSION_TOKEN"):
        markers.append("AWS_SESSION_TOKEN")
    if not markers:
        return []
    markers_t = tuple(markers)
    return [
        DetectedDestination(
            destination=Destination.CLOUDWATCH_LOGS,
            markers=markers_t,
            summary=(
                "Detected AWS credentials. Ship to CloudWatch Logs via "
                "the operator-provisioned API Gateway / Lambda intake "
                "(uses the #257 generic webhook preset)."
            ),
        ),
        DetectedDestination(
            destination=Destination.SECURITY_LAKE,
            markers=markers_t,
            summary=(
                "Detected AWS credentials. Ship to an AWS Security Lake "
                "S3 bucket via the #317 S3-compat NDJSON sink (hive-"
                "partitioned, gzip-compressed, OCSF-compliant)."
            ),
        ),
    ]


def _detect_datadog(d: DetectionEnv) -> list[DetectedDestination]:
    """Datadog markers → datadog webhook-preset recommendation."""
    markers: list[str] = []
    if d.env.get("DD_API_KEY"):
        markers.append("DD_API_KEY")
    if d.env.get("DATADOG_API_KEY"):
        markers.append("DATADOG_API_KEY")
    if d.env.get("DD_SITE"):
        markers.append(f"DD_SITE={d.env['DD_SITE']}")
    if not markers:
        return []
    return [
        DetectedDestination(
            destination=Destination.DATADOG,
            markers=tuple(markers),
            summary=(
                "Detected Datadog. Ship to Datadog Logs intake via the "
                "#257 'datadog' webhook preset (Bearer-less DD-API-KEY "
                "header; OCSF event overlayed with ddsource / service "
                "/ ddtags so DD-native pipelines auto-categorise)."
            ),
        ),
    ]


def _detect_splunk(d: DetectionEnv) -> list[DetectedDestination]:
    """Splunk markers → splunk-hec webhook-preset recommendation."""
    markers: list[str] = []
    if d.env.get("SPLUNK_HEC_URL"):
        markers.append("SPLUNK_HEC_URL")
    if d.env.get("SPLUNK_HEC_TOKEN"):
        markers.append("SPLUNK_HEC_TOKEN")
    if d.env.get("SPLUNK_URL"):
        markers.append("SPLUNK_URL")
    if not markers:
        return []
    return [
        DetectedDestination(
            destination=Destination.SPLUNK_HEC,
            markers=tuple(markers),
            summary=(
                "Detected Splunk HEC config. Ship to Splunk HTTP Event "
                "Collector via the #257 'splunk-hec' webhook preset "
                "(NDJSON; sourcetype iam_jit:bouncer:<product>)."
            ),
        ),
    ]


def _detect_kubernetes(d: DetectionEnv) -> list[DetectedDestination]:
    """K8s markers → cluster-local Loki / ELK recommendation."""
    markers: list[str] = []
    if d.env.get("KUBERNETES_SERVICE_HOST"):
        markers.append("KUBERNETES_SERVICE_HOST")
    if d.env.get("KUBERNETES_PORT"):
        markers.append("KUBERNETES_PORT")
    if d.k8s_serviceaccount_token_exists:
        markers.append("/var/run/secrets/kubernetes.io/serviceaccount/token")
    if not markers:
        return []
    return [
        DetectedDestination(
            destination=Destination.LOKI_ELK,
            markers=tuple(markers),
            summary=(
                "Detected Kubernetes pod environment. Ship to cluster-"
                "local Loki / Elasticsearch via the #257 generic "
                "webhook preset (point --audit-webhook-url at the "
                "cluster service) OR the #317 S3-compat sink against "
                "an in-cluster MinIO bucket."
            ),
        ),
    ]


def recommend_flags(destination: Destination) -> list[str]:
    """Return the bouncer-launch flag SUGGESTION for a destination.

    The flags compose with the existing #257 + #258 + #317 surfaces.
    Operators substitute their own URL / bucket / token before pasting
    into their bouncer command. Per ``[[creates-never-mutates]]`` this
    function NEVER auto-applies — it returns the recommendation as a
    list of CLI tokens for the operator to inspect + copy.

    Each token is a placeholder where the operator must fill in the
    site-specific value (URL / bucket / token). The CLI prints them
    with a ``<…>`` hint so it's obvious which fields need substitution.
    """
    if destination == Destination.CLOUDWATCH_LOGS:
        return [
            "--audit-webhook-url=<https://<your-cloudwatch-ingest-url>>",
            "--audit-webhook-token=<your-bearer-token>",
            "--audit-webhook-preset=generic",
        ]
    if destination == Destination.SECURITY_LAKE:
        return [
            "--audit-object-storage-bucket=<your-security-lake-bucket>",
            "--audit-object-storage-endpoint=https://s3.<region>.amazonaws.com",
            "--audit-object-storage-region=<your-aws-region>",
            "--audit-object-storage-prefix=<security-lake-prefix>",
        ]
    if destination == Destination.DATADOG:
        return [
            "--audit-webhook-url=https://http-intake.logs.datadoghq.com/api/v2/logs",
            "--audit-webhook-token=$DD_API_KEY",
            "--audit-webhook-preset=datadog",
        ]
    if destination == Destination.SPLUNK_HEC:
        return [
            "--audit-webhook-url=$SPLUNK_HEC_URL",
            "--audit-webhook-token=$SPLUNK_HEC_TOKEN",
            "--audit-webhook-preset=splunk-hec",
        ]
    if destination == Destination.LOKI_ELK:
        return [
            "--audit-webhook-url=<http://loki.observability.svc:3100/loki/api/v1/push>",
            "--audit-webhook-token=<your-loki-tenant-or-bearer>",
            "--audit-webhook-preset=generic",
        ]
    raise ValueError(f"unknown destination: {destination!r}")
