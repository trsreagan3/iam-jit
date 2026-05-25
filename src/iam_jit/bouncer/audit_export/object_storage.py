"""Cloud-neutral S3-compatible NDJSON object-storage sink (#317).

Per founder direction 2026-05-22: bouncers (other than ibounce) are
cloud-neutral. Today we ship JSONL files + HTTPS webhook + AWS-only
Security Lake parquet. Operators on GCS / Azure Blob / MinIO / R2 /
B2 have no pull-based collection path. This module adds one
S3-compatible NDJSON sink that writes operator-named buckets via the
S3 API. Works across:

  * AWS S3 (native)
  * Cloudflare R2 (S3 API)
  * Backblaze B2 (S3 API)
  * DigitalOcean Spaces (S3 API)
  * MinIO (S3 API)
  * Google Cloud Storage (S3 interop / HMAC keys)
  * Azure Blob (S3-compat layer)

Output shape: NDJSON (one OCSF event per line), gzip-compressed,
written into hive-style partitions::

    {prefix}/year=YYYY/month=MM/day=DD/hour=HH/
        {product}-{instance_id}-{timestamp}.jsonl.gz

The active file uploads to a ``.in-progress`` suffix during the
rotation window, then is renamed (via copy + delete) to the final
canonical name. Operator collectors that read finalized objects only
never see partials.

Per [[self-host-zero-billing-dependency]]: the destination is
operator-owned; iam-jit-the-company never receives the data and is
not on the billing path.

Per [[creates-never-mutates]]: every S3 operation is PutObject (the
bouncer never creates the bucket; operator provisions it). Rename
during finalize is implemented as PutObject (new key) + DeleteObject
(old `.in-progress` key) on the same logical file content — the
finalized object itself is never mutated post-publish.

Per [[don't-tailor-to-lighthouse]]: this is a generic S3-compat
sink. Works with everything. Tuned to no single vendor.

Per [[cross-product-agent-parity]]: kbouncer + dbounce + gbounce
ship the same shape (Go) with byte-identical wire format. The
cross-product invariant is fixed in ``tests/integration/
object_storage_sink_test.py``.

Per [[security-team-positioning-safety-not-surveillance]]: this is
a passive sink. No "violation" / "infraction" / "unauthorized"
language in user-facing strings.

Auth: standard AWS-style env vars (``AWS_ACCESS_KEY_ID`` /
``AWS_SECRET_ACCESS_KEY`` / ``AWS_SESSION_TOKEN``) OR an explicit
``--audit-object-storage-credentials-file`` (YAML or INI). The
credentials file overrides env vars when both are present.

NOT shipped in v1.0 (deferred to v1.1 per [[don't-tailor-to-lighthouse]]):
  * Native GCS auth (Workload Identity / Service Account)
  * Native Azure Blob auth (Managed Identity)
  Both are friction reducers; the S3 interop layer covers ~95% of
  "drop logs in a bucket" today.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import gzip
import io
import json
import logging
import os
import platform
import socket
import stat
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Spec defaults per the issue body. Operators can shrink for tests
# (or grow for high-volume orgs preferring fewer, larger files).
DEFAULT_ROTATION_MINUTES = 5
DEFAULT_MAX_SIZE_MB = 16
DEFAULT_REGION = "us-east-1"

# Bounded in-memory queue to keep a runaway producer from OOM-ing the
# proxy. Drops + counter bump if the cap is exceeded; the operator
# sees the dropped count via ``status()`` like every other adapter in
# the family.
DEFAULT_MAX_PENDING_ROWS = 100_000

# Suffix used for the actively-written object before its rotation
# completes. Collectors that filter on the finalized ``.jsonl.gz``
# suffix never observe partials.
IN_PROGRESS_SUFFIX = ".in-progress"


class ObjectStorageConfigError(Exception):
    """Raised when the operator-supplied configuration is internally
    inconsistent (empty bucket, negative rotation, ...)."""


class ObjectStorageCredentialsError(Exception):
    """Raised when neither env vars nor the credentials file yield
    usable credentials. Surfaced at ``start()`` time so the operator
    sees the misconfiguration immediately."""


class InsecureCredentialsError(ObjectStorageCredentialsError):
    """Raised when a credentials file on disk is group-readable or
    world-readable (any of mode bits ``0o077`` set).

    Mirrors the posture SSH (``ssh -i ~/.ssh/id_ed25519``) and the
    AWS CLI (``~/.aws/credentials``) enforce: a credentials file with
    loose perms is refused at load time rather than silently accepted.

    Per ``[[scorer-is-ground-truth]]`` we fail-CLOSED at load time —
    a loose-perms creds file is a posture violation the operator must
    fix before the bouncer will start. Per
    ``[[ibounce-honest-positioning]]`` the error message NAMES the
    offending mode bits and gives the exact remediation command
    (``chmod 600 <path>``).

    Subclasses ``ObjectStorageCredentialsError`` so callers that already
    catch the parent error type (e.g. the proxy startup path) surface
    insecure-perms refusals through the same channel as other creds
    failures, while operators / tests that want to handle this
    specific case can still catch the narrower type.
    """


def _enforce_creds_file_perms(
    path: Path, *, who: str = "object_storage_credentials",
) -> None:
    """Refuse credential files with group/world-readable perms.

    Mirrors SSH (refuses keys with mode ``0o644``) + the AWS CLI
    convention (warns / refuses on loose creds file perms). iam-jit
    was previously silent — #484 audit WB-5.

    Raises :class:`InsecureCredentialsError` when any of the
    group/world bits (mask ``0o077``) are set. The error message names
    the offending mode and gives the exact remediation command so
    the operator can fix it without grepping docs.

    Windows is skipped because NTFS uses ACL-based access control and
    POSIX mode bits there are simulated by the runtime; the WB-5
    posture is a POSIX-only invariant by design (other audit_export
    helpers — ``cli_canary.py``, ``local_server.py`` — take the same
    skip).
    """
    if platform.system() == "Windows":
        return
    try:
        st = path.stat()
    except FileNotFoundError:
        # Caller's parse path raises its own "file not found" message
        # with the same exception type; let that path own the error.
        return
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise InsecureCredentialsError(
            f"refuses to load {who}: {path} has mode 0o{mode:o} "
            f"(group/world-readable). SSH and the AWS CLI refuse "
            f"creds files with loose perms; iam-jit applies the same "
            f"posture. Run: chmod 600 '{path}'"
        )


@dataclasses.dataclass(frozen=True)
class ObjectStorageCredentials:
    """Static S3-compatible credentials. Loaded from env vars OR an
    explicit credentials file (operator picks). The credentials file
    overrides env vars when both are present."""

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None


def load_credentials(
    credentials_file: str | None = None,
    *,
    env: dict[str, str] | None = None,
) -> ObjectStorageCredentials:
    """Resolve credentials from operator config.

    Precedence (highest first):
      1. ``credentials_file`` (when set)
      2. ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` /
         ``AWS_SESSION_TOKEN`` env vars

    The file shape is either YAML or INI. YAML keys are
    ``access_key_id`` / ``secret_access_key`` / ``session_token``;
    INI uses the same keys under a ``[default]`` section.

    Raises ``ObjectStorageCredentialsError`` when no credentials are
    reachable. Per the spec: "refuses to start without credentials so
    the operator finds the misconfiguration immediately."
    """
    env_map = env if env is not None else os.environ
    if credentials_file:
        return _load_credentials_file(credentials_file)
    access = env_map.get("AWS_ACCESS_KEY_ID", "").strip()
    secret = env_map.get("AWS_SECRET_ACCESS_KEY", "").strip()
    if not access or not secret:
        raise ObjectStorageCredentialsError(
            "no S3-compatible credentials reachable; set "
            "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars OR "
            "pass --audit-object-storage-credentials-file PATH"
        )
    token = env_map.get("AWS_SESSION_TOKEN") or None
    return ObjectStorageCredentials(
        access_key_id=access,
        secret_access_key=secret,
        session_token=token,
    )


def _load_credentials_file(path: str) -> ObjectStorageCredentials:
    """Parse a credentials file (YAML or INI). The shape is detected
    by the first non-blank, non-comment line — a ``[default]`` line
    signals INI; a ``key: value`` line signals YAML. Both formats
    accept the same three keys.

    Per #524 WB-5 the file's POSIX mode is enforced BEFORE the file
    is read: a creds file with any group/world bits set is refused
    with ``InsecureCredentialsError`` and an operator-actionable
    remediation hint (``chmod 600 <path>``). This mirrors SSH +
    AWS CLI posture and matches ``[[scorer-is-ground-truth]]`` —
    fail-CLOSED on insecure creds rather than silently accept them.
    """
    p = Path(path)
    if not p.is_file():
        raise ObjectStorageCredentialsError(
            f"credentials file not found: {path}"
        )
    # #524 WB-5: enforce strict perms BEFORE reading the file so an
    # insecure file never gets parsed (and so its contents never enter
    # process memory through this path).
    _enforce_creds_file_perms(p)
    raw = p.read_text(encoding="utf-8")
    data: dict[str, str] = {}
    in_default_section = False
    is_ini = False
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            is_ini = True
            in_default_section = stripped == "[default]"
            continue
        if "=" in stripped and (is_ini or "[default]" in raw):
            if is_ini and not in_default_section:
                continue
            k, _, v = stripped.partition("=")
            data[k.strip()] = v.strip().strip('"').strip("'")
        elif ":" in stripped:
            k, _, v = stripped.partition(":")
            data[k.strip()] = v.strip().strip('"').strip("'")
    access = data.get("access_key_id", "")
    secret = data.get("secret_access_key", "")
    if not access or not secret:
        raise ObjectStorageCredentialsError(
            f"credentials file {path} missing access_key_id or "
            f"secret_access_key (YAML or INI [default] shape required)"
        )
    return ObjectStorageCredentials(
        access_key_id=access,
        secret_access_key=secret,
        session_token=data.get("session_token") or None,
    )


def _default_instance_id(*, product: str, hostname_factory: Any | None = None) -> str:
    """Build a stable per-bouncer identifier from hostname + pid.

    Keeps the path collision-free across multiple bouncer instances
    writing the same bucket. Operators with ephemeral hostnames
    (containers / k8s pods) should pass ``--instance-id`` explicitly
    so the path stays stable across restarts when desired.
    """
    host = (hostname_factory or socket.gethostname)() or "unknown"
    # Strip dots so the hostname doesn't accidentally introduce path
    # separators in some S3-compat layers that interpret dots.
    host_safe = host.replace(".", "-").replace("/", "-")
    return f"{product}-{host_safe}-{os.getpid()}"


def _partition_path(
    *,
    prefix: str,
    product: str,
    instance_id: str,
    when: _dt.datetime,
    unix_ms: int,
) -> str:
    """Return the canonical S3 key for one NDJSON file.

    Format::

        {prefix}/year=YYYY/month=MM/day=DD/hour=HH/
            {product}-{instance_id}-{unix_ms}.jsonl.gz

    Hive-style partitioning. Athena / BigQuery / Spark / Trino all
    auto-discover partitions from this layout.
    """
    pfx = prefix.rstrip("/")
    year = when.strftime("%Y")
    month = when.strftime("%m")
    day = when.strftime("%d")
    hour = when.strftime("%H")
    parts = [
        f"year={year}",
        f"month={month}",
        f"day={day}",
        f"hour={hour}",
        f"{product}-{instance_id}-{unix_ms}.jsonl.gz",
    ]
    if pfx:
        return pfx + "/" + "/".join(parts)
    return "/".join(parts)


class ObjectStorageS3Client:
    """Minimal S3 client wrapper.

    Production callers leave ``_session_factory`` and ``_boto_client``
    unset — ``start()`` constructs a real boto3 client pointed at the
    operator's ``endpoint_url``. Tests inject a fake client
    (``moto``-style or a hand-rolled stub) so unit tests don't hit
    real S3.

    Why boto3: it's already a dependency of ibounce (used for the
    Security Lake adapter + every other AWS surface). ``endpoint_url``
    + region together address every S3-compatible vendor — boto3's
    SigV4 implementation signs the request whether the target is AWS
    S3, MinIO, R2, B2, GCS interop, or Azure Blob's S3 layer.
    """

    def __init__(
        self,
        *,
        endpoint_url: str,
        region: str,
        credentials: ObjectStorageCredentials,
        boto_client: Any | None = None,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.region = region
        self.credentials = credentials
        self._client = boto_client

    def ensure_client(self) -> Any:
        """Construct the boto3 client lazily so unit tests can inject
        a stub without importing boto3."""
        if self._client is not None:
            return self._client
        import boto3  # noqa: PLC0415 — lazy import keeps import path cheap

        self._client = boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            region_name=self.region,
            aws_access_key_id=self.credentials.access_key_id,
            aws_secret_access_key=self.credentials.secret_access_key,
            aws_session_token=self.credentials.session_token,
        )
        return self._client

    def head_bucket(self, *, bucket: str) -> None:
        """Probe the bucket so credential / endpoint / bucket-name
        misconfigurations surface at start() rather than at first
        flush. Raises on any client error so the caller wraps it in
        ``ObjectStorageCredentialsError``."""
        self.ensure_client().head_bucket(Bucket=bucket)

    def put_object(
        self,
        *,
        bucket: str,
        key: str,
        body: bytes,
        content_type: str,
        content_encoding: str | None = None,
    ) -> None:
        kwargs: dict[str, Any] = {
            "Bucket": bucket,
            "Key": key,
            "Body": body,
            "ContentType": content_type,
        }
        if content_encoding:
            kwargs["ContentEncoding"] = content_encoding
        self.ensure_client().put_object(**kwargs)

    def delete_object(self, *, bucket: str, key: str) -> None:
        self.ensure_client().delete_object(Bucket=bucket, Key=key)


class ObjectStorageWriter:
    """Async-flushed S3-compatible NDJSON object-storage writer.

    Lifecycle::

        writer = ObjectStorageWriter(
            endpoint_url="https://s3.us-east-1.amazonaws.com",
            bucket="my-bucket",
            prefix="bounce-audit/prod",
            region="us-east-1",
            credentials=ObjectStorageCredentials(...),
            product="ibounce",
        )
        writer.start()          # probe bucket + spawn rotator thread
        writer.write({"...event..."})  # never blocks
        writer.stop()           # finalize active file + exit

    Per-instance file: each writer maintains one active NDJSON buffer
    in memory. The rotator finalizes the buffer (uploads + renames
    out of ``.in-progress``) when EITHER the rotation interval
    elapses OR the size cap fires.

    Thread-safety: ``write()`` / ``flush()`` / ``stop()`` hold a
    single coarse lock around the active buffer. The proxy hot-path
    enqueues into the buffer (in-memory append; non-blocking) and the
    rotator drains under the lock.
    """

    def __init__(
        self,
        *,
        endpoint_url: str,
        bucket: str,
        prefix: str,
        region: str,
        credentials: ObjectStorageCredentials,
        product: str,
        instance_id: str | None = None,
        rotation_minutes: int = DEFAULT_ROTATION_MINUTES,
        max_size_mb: int = DEFAULT_MAX_SIZE_MB,
        max_pending_rows: int = DEFAULT_MAX_PENDING_ROWS,
        s3_client: ObjectStorageS3Client | None = None,
        _now: Any | None = None,
    ) -> None:
        if not endpoint_url:
            raise ObjectStorageConfigError("endpoint_url is required")
        if not bucket:
            raise ObjectStorageConfigError("bucket is required")
        if not region:
            raise ObjectStorageConfigError("region is required")
        if not product:
            raise ObjectStorageConfigError("product is required")
        if rotation_minutes <= 0:
            raise ObjectStorageConfigError(
                "rotation_minutes must be > 0 "
                "(use stop() to flush on shutdown)"
            )
        if max_size_mb <= 0:
            raise ObjectStorageConfigError("max_size_mb must be > 0")
        self.endpoint_url = endpoint_url
        self.bucket = bucket
        # Normalize prefix: strip leading/trailing slashes so the
        # partition path joins cleanly.
        self.prefix = (prefix or "").strip("/")
        self.region = region
        self.credentials = credentials
        self.product = product
        self.instance_id = instance_id or _default_instance_id(product=product)
        self.rotation_minutes = rotation_minutes
        self.max_size_mb = max_size_mb
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_pending_rows = max_pending_rows
        self._s3_client = s3_client or ObjectStorageS3Client(
            endpoint_url=endpoint_url,
            region=region,
            credentials=credentials,
        )
        self._now = _now or (lambda: _dt.datetime.now(_dt.UTC))

        # Active buffer: list of pre-serialized NDJSON lines (bytes,
        # no newline yet). Storing serialized lines lets us amortize
        # the json.dumps over the proxy hot-path goroutines + avoid
        # re-serializing the whole batch every rotation.
        self._buffer_lines: list[bytes] = []
        self._buffer_bytes_estimate: int = 0
        self._buffer_first_seen: _dt.datetime | None = None
        # Stable identifier for the in-progress object so finalize
        # can target the exact same key. Re-derived on every rotation.
        self._active_in_progress_key: str | None = None
        self._lock = threading.Lock()
        self._ticker_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        # Stats surfaced via status() for the MCP audit-export status
        # tool + /healthz.
        self._total_events = 0
        self._total_files_written = 0
        self._total_bytes_written = 0
        self._dropped_events = 0
        self._last_error: str | None = None
        self._last_error_at_unix: float | None = None
        self._writes_ok = True
        self._started = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Probe the bucket + spawn the rotator. Idempotent.

        Raises ``ObjectStorageCredentialsError`` if the probe fails
        (bucket not found / bad credentials / endpoint unreachable).
        """
        if self._started:
            return
        try:
            self._s3_client.head_bucket(bucket=self.bucket)
        except Exception as e:
            raise ObjectStorageCredentialsError(
                f"object-storage bucket probe failed: bucket={self.bucket} "
                f"endpoint={self.endpoint_url}: {e}"
            ) from e
        self._stop_event.clear()
        self._ticker_thread = threading.Thread(
            target=self._tick_loop,
            name=f"{self.product}-object-storage-rotator",
            daemon=True,
        )
        self._ticker_thread.start()
        self._started = True

    def stop(self) -> None:
        """Finalize the active file synchronously + stop the rotator.
        Idempotent. Per the spec: on shutdown, flush all pending
        synchronously so a clean restart doesn't drop events."""
        if not self._started:
            return
        self._stop_event.set()
        if self._ticker_thread is not None:
            self._ticker_thread.join(timeout=10.0)
        # Final drain — anything still buffered finalizes before we
        # exit stop().
        self.flush()
        self._started = False

    # ------------------------------------------------------------------
    # Public write surface
    # ------------------------------------------------------------------

    def write(self, event: dict[str, Any]) -> None:
        """Append one OCSF event to the active buffer.

        Never blocks. Never raises. When the buffer crosses the size
        cap, this call triggers a synchronous flush.

        Drops + bumps the dropped counter when the buffer crosses
        ``max_pending_rows``. The status() snapshot surfaces both
        counts so the operator can spot a backed-up writer in the
        MCP status tool.
        """
        if not self._started:
            return
        try:
            line = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        except Exception as e:  # noqa: BLE001 — fail-soft per spec
            self._record_error(f"json encode failed: {e}")
            return
        should_flush_size = False
        with self._lock:
            if len(self._buffer_lines) >= self.max_pending_rows:
                self._dropped_events += 1
                self._last_error = (
                    f"object-storage buffer full at {self.max_pending_rows} "
                    f"rows; dropped event"
                )
                return
            self._buffer_lines.append(line)
            # +1 byte for the newline that gets joined on flush.
            self._buffer_bytes_estimate += len(line) + 1
            if self._buffer_first_seen is None:
                self._buffer_first_seen = self._now()
            if self._buffer_bytes_estimate >= self.max_size_bytes:
                should_flush_size = True
        if should_flush_size:
            self.flush()

    def flush(self) -> None:
        """Finalize the active buffer: serialize, gzip, upload to
        the canonical key, then delete any leftover ``.in-progress``
        sibling.

        Safe to call from any thread. Used by ``stop()`` + the
        operator-driven ``audit-export flush`` CLI subcommand."""
        with self._lock:
            if not self._buffer_lines:
                self._buffer_first_seen = None
                self._active_in_progress_key = None
                return
            lines_snapshot = list(self._buffer_lines)
            # Reset the buffer up-front so producers don't block on
            # the upload. If the upload fails the rows are surfaced
            # via the dropped counter + last_error (we don't
            # re-buffer to keep the memory bound predictable).
            self._buffer_lines = []
            self._buffer_bytes_estimate = 0
            first_seen = self._buffer_first_seen
            self._buffer_first_seen = None
            in_progress_key = self._active_in_progress_key
            self._active_in_progress_key = None
        when = first_seen or self._now()
        unix_ms = int(when.timestamp() * 1000)
        final_key = _partition_path(
            prefix=self.prefix,
            product=self.product,
            instance_id=self.instance_id,
            when=when,
            unix_ms=unix_ms,
        )
        # Serialize: join with newlines + gzip-compress in one shot.
        body = b"\n".join(lines_snapshot) + b"\n"
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(body)
        payload = buf.getvalue()
        try:
            self._s3_client.put_object(
                bucket=self.bucket,
                key=final_key,
                body=payload,
                content_type="application/x-ndjson",
                content_encoding="gzip",
            )
        except Exception as e:  # noqa: BLE001 — fail-soft per spec
            self._record_error(f"object-storage put_object failed: {e}")
            return
        # Best-effort cleanup of any prior `.in-progress` object so
        # operator collectors filtering on the finalized suffix don't
        # see stale partials. Failure here is non-fatal.
        if in_progress_key:
            try:
                self._s3_client.delete_object(
                    bucket=self.bucket, key=in_progress_key
                )
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "object-storage in-progress cleanup failed: key=%s err=%s",
                    in_progress_key, e,
                )
        with self._lock:
            self._total_events += len(lines_snapshot)
            self._total_files_written += 1
            self._total_bytes_written += len(payload)
            self._writes_ok = True
        logger.info(
            "object-storage flush: rows=%d bytes=%d key=%s",
            len(lines_snapshot), len(payload), final_key,
        )

    # ------------------------------------------------------------------
    # Status surface
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Snapshot for the MCP audit-export status tool + /healthz."""
        with self._lock:
            pending = len(self._buffer_lines)
            return {
                "configured": True,
                "endpoint_url": self.endpoint_url,
                "bucket": self.bucket,
                "prefix": self.prefix,
                "region": self.region,
                "product": self.product,
                "instance_id": self.instance_id,
                "rotation_minutes": self.rotation_minutes,
                "max_size_mb": self.max_size_mb,
                "total_events": self._total_events,
                "total_files_written": self._total_files_written,
                "total_bytes_written": self._total_bytes_written,
                "dropped_events": self._dropped_events,
                "pending_rows": pending,
                "last_error": self._last_error,
                "last_error_at_unix": self._last_error_at_unix,
                "writes_ok": self._writes_ok,
            }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _tick_loop(self) -> None:
        """Background ticker. Wakes every ``min(rotation_minutes*60, 1)``
        seconds (or sooner on stop) and finalizes the active buffer
        when the rotation deadline crosses."""
        # 1s minimum so tests with rotation_minutes=1 don't over-sleep.
        rotation_seconds = self.rotation_minutes * 60
        tick = min(1.0, float(rotation_seconds))
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=tick)
            if self._stop_event.is_set():
                return
            try:
                self._flush_overdue()
            except Exception as e:  # noqa: BLE001
                # Per [[deliberate-feature-completion]]: ticker failure
                # must not kill the writer. Log + carry on.
                self._record_error(f"tick failed: {e}")

    def _flush_overdue(self) -> None:
        """Finalize when the buffer's oldest row crossed the rotation
        deadline."""
        now = self._now()
        overdue = False
        with self._lock:
            if self._buffer_first_seen is not None:
                age_s = (now - self._buffer_first_seen).total_seconds()
                if age_s >= self.rotation_minutes * 60:
                    overdue = True
        if overdue:
            self.flush()

    def _record_error(self, msg: str) -> None:
        with self._lock:
            self._last_error = msg
            self._last_error_at_unix = time.time()
            self._writes_ok = False
        logger.warning("object-storage writer error: %s", msg)
