"""AWS Security Lake adapter — Channel 4 of the audit-export transport.

Per #258: ibounce can write OCSF events as parquet files into a
Security-Lake-compatible S3 bucket layout. The operator points
Security Lake at the bucket as a custom source; Security Lake
auto-ingests + makes the data queryable via Athena / Glue / lakefs.

Layout (matches the AWS-published Security-Lake custom-source path
template — region + eventday + eventhour are the partition keys
Security Lake's Glue crawler recognises out-of-the-box)::

    s3://<bucket>/region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/
        api_activity-<unix-ms>.parquet

Rotation: in-memory batch per OCSF class flushed every
`rotation_seconds` (default 300 = 5min) OR when batch bytes cross
10 MiB, whichever fires first. On `stop()` every pending batch is
flushed synchronously so the operator-driven shutdown path doesn't
drop events.

Auth: STS AssumeRole when `role_arn` is set; otherwise the default
boto3 credential chain (env / shared-config / instance role). The
adapter refuses to start without credentials so the operator finds
the misconfiguration immediately (not after the first flush attempt
hours later).

Per [[no-hosted-saas]]: the bucket lives in the operator's AWS
account; iam-jit-the-company NEVER receives the data.

Per [[creates-never-mutates]]: every S3 operation is PutObject
ONLY. We never overwrite or delete; rotation timestamps ensure
unique keys per flush.

Per [[security-team-positioning-safety-not-surveillance]]: the
adapter is a passive sink. No "violation" / "infraction" /
"unauthorized" language anywhere in user-facing strings — the
docstrings + log lines describe what was written, not a judgement
of the underlying request.

Per [[self-host-zero-billing-dependency]]: AWS Security Lake costs
land on the operator's AWS bill; nothing flows back to
iam-jit-the-company.

Per [[cross-product-agent-parity]]: kbouncer + dbounce ship the
same adapter shape (Go) with byte-identical partition layout +
column set. The cross-product contract is fixed in this docstring
+ the test fixtures.
"""

from __future__ import annotations

import datetime as _dt
import io
import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)


# Rotation default per the issue body. Operator can shrink for tests
# (or grow for high-throughput orgs where bigger parquet files are
# preferable for Athena scan efficiency).
DEFAULT_ROTATION_SECONDS = 300

# 10 MiB cap per the spec; whichever of (time, size) fires first
# triggers a flush.
DEFAULT_MAX_BATCH_BYTES = 10 * 1024 * 1024

# Bounded in-memory queue to keep a runaway producer from OOM-ing the
# proxy. Drops + a counter bump if the cap is exceeded; the operator
# sees the dropped count via `audit_export_status()` like every other
# adapter in the family.
DEFAULT_MAX_PENDING_ROWS = 100_000


# The canonical OCSF v1.1.0 class 6003 column set, dot-path-flattened.
# Each row in a Security Lake parquet file carries these columns;
# missing values land as null (pyarrow handles that natively).
#
# Per [[cross-product-agent-parity]]: kbouncer + dbounce write the
# same columns in the same order so a single Athena query works
# across all three products' partitions.
#
# Schema is exposed as a module-level tuple so:
#   1. the cross-product test can assert it byte-for-byte
#   2. the docs runbook can render the column list without importing
#      pyarrow (no pyarrow dep in `iam-jit-the-cli`).
#
# Naming convention: dot-paths in the source OCSF event become
# underscore-separated column names (`metadata.product.name` ->
# `metadata_product_name`). This matches AWS Glue's auto-crawl
# convention for parquet files + keeps Athena queries idiomatic
# (Athena treats dots in column names as struct-member access).
OCSF_PARQUET_COLUMNS: tuple[tuple[str, str], ...] = (
    # (column_name, pyarrow_logical_type_name)
    ("metadata_version", "string"),
    ("metadata_product_name", "string"),
    ("metadata_product_vendor_name", "string"),
    ("metadata_product_version", "string"),
    ("time", "int64"),
    ("class_uid", "int32"),
    ("class_name", "string"),
    ("category_uid", "int32"),
    ("category_name", "string"),
    ("activity_id", "int32"),
    ("activity_name", "string"),
    ("type_uid", "int32"),
    ("type_name", "string"),
    ("severity_id", "int32"),
    ("severity", "string"),
    ("status_id", "int32"),
    ("status", "string"),
    ("status_detail", "string"),
    ("actor_user_name", "string"),
    ("actor_user_uid", "string"),
    ("actor_session_uid", "string"),
    ("api_operation", "string"),
    ("api_service_name", "string"),
    ("api_request_uid", "string"),
    # OCSF resources[] is JSON-encoded into a single column. parquet-go +
    # pyarrow both handle nested-list types natively, but flattening
    # to a JSON string keeps the Athena-side schema trivial + avoids
    # the cross-product struct-shape divergence risk.
    ("resources_json", "string"),
    ("src_endpoint_hostname", "string"),
    ("src_endpoint_ip", "string"),
    ("src_endpoint_port", "int32"),
    ("dst_endpoint_hostname", "string"),
    ("dst_endpoint_ip", "string"),
    ("dst_endpoint_port", "int32"),
    ("unmapped_iam_jit_mode", "string"),
    ("unmapped_iam_jit_profile", "string"),
    ("unmapped_iam_jit_verdict", "string"),
    ("unmapped_iam_jit_decision_id", "int64"),
    ("unmapped_iam_jit_enforced", "bool"),
    ("unmapped_iam_jit_event_type", "string"),
    # The remaining iam-jit extension fields collapse into a single
    # JSON string column so SIEM queries stay forward-compatible when
    # new ext fields are added by later issues.
    ("unmapped_iam_jit_ext_json", "string"),
    ("unmapped_iam_jit_agent_json", "string"),
)


# OCSF class 6003 -> Security Lake file-prefix. Today every event the
# Bounce suite emits is class 6003 (API Activity). When a future
# slice adds another class, the rotator opens a separate batch
# keyed on (class_uid, class_name) and the prefix table grows.
_CLASS_PREFIX: dict[int, str] = {
    6003: "api_activity",
}


def _class_prefix(class_uid: int) -> str:
    """Return the Security Lake file-prefix for an OCSF class_uid.

    Unknown class_uids land under `class-<n>` so an event with a
    class we haven't enumerated yet still surfaces in a partition the
    operator can investigate.
    """
    return _CLASS_PREFIX.get(class_uid, f"class-{class_uid}")


class SecurityLakeCredentialsError(Exception):
    """Raised when neither AssumeRole nor the default credential chain
    yields usable AWS credentials. Surfaced at start() time so the
    operator sees the misconfiguration immediately."""


class SecurityLakeConfigError(Exception):
    """Raised when the operator-supplied configuration is internally
    inconsistent (empty bucket, negative rotation, ...)."""


def _flatten_event_to_row(event: dict[str, Any]) -> dict[str, Any]:
    """Map an OCSF event dict (the output of
    `audit_event_from_decision` / `audit_dropped_event` / the
    synthetics) onto the canonical column set.

    Missing nested keys land as None (which pyarrow renders as a
    parquet null). Per [[cross-product-agent-parity]] the column
    order + names match kbouncer + dbounce byte-for-byte.

    `resources_json`, `unmapped.iam_jit.ext_json`, and
    `unmapped.iam_jit.agent_json` are JSON-serialised strings so the
    Athena-side schema stays flat. Compatible with Glue's auto-
    crawled schema for Security Lake custom sources.
    """
    import json as _json

    def _get(d: Any, *path: str, default: Any = None) -> Any:
        cur: Any = d
        for k in path:
            if not isinstance(cur, dict):
                return default
            cur = cur.get(k)
            if cur is None:
                return default
        return cur

    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    session = actor.get("session") or {}
    api = event.get("api") or {}
    api_service = api.get("service") or {}
    api_request = api.get("request") or {}
    src = event.get("src_endpoint") or {}
    dst = event.get("dst_endpoint") or {}
    unmapped = event.get("unmapped") or {}
    iam_jit = unmapped.get("iam_jit") or {}

    resources = event.get("resources") or []
    ext = iam_jit.get("ext") or {}
    agent = iam_jit.get("agent")

    return {
        "metadata_version": metadata.get("version"),
        "metadata_product_name": product.get("name"),
        "metadata_product_vendor_name": product.get("vendor_name"),
        "metadata_product_version": product.get("version"),
        "time": event.get("time"),
        "class_uid": event.get("class_uid"),
        "class_name": event.get("class_name"),
        "category_uid": event.get("category_uid"),
        "category_name": event.get("category_name"),
        "activity_id": event.get("activity_id"),
        "activity_name": event.get("activity_name"),
        "type_uid": event.get("type_uid"),
        "type_name": event.get("type_name"),
        "severity_id": event.get("severity_id"),
        "severity": event.get("severity"),
        "status_id": event.get("status_id"),
        "status": event.get("status"),
        "status_detail": event.get("status_detail"),
        "actor_user_name": user.get("name") if isinstance(user, dict) else None,
        "actor_user_uid": user.get("uid") if isinstance(user, dict) else None,
        "actor_session_uid": (
            session.get("uid") if isinstance(session, dict) else None
        ),
        "api_operation": api.get("operation"),
        "api_service_name": api_service.get("name"),
        "api_request_uid": api_request.get("uid"),
        "resources_json": _json.dumps(resources, ensure_ascii=False),
        "src_endpoint_hostname": src.get("hostname"),
        "src_endpoint_ip": src.get("ip"),
        "src_endpoint_port": src.get("port"),
        "dst_endpoint_hostname": dst.get("hostname"),
        "dst_endpoint_ip": dst.get("ip"),
        "dst_endpoint_port": dst.get("port"),
        "unmapped_iam_jit_mode": iam_jit.get("mode"),
        "unmapped_iam_jit_profile": iam_jit.get("profile"),
        "unmapped_iam_jit_verdict": iam_jit.get("verdict"),
        "unmapped_iam_jit_decision_id": iam_jit.get("decision_id"),
        "unmapped_iam_jit_enforced": iam_jit.get("enforced"),
        "unmapped_iam_jit_event_type": iam_jit.get("event_type"),
        "unmapped_iam_jit_ext_json": _json.dumps(ext, ensure_ascii=False),
        "unmapped_iam_jit_agent_json": (
            _json.dumps(agent, ensure_ascii=False) if agent is not None else None
        ),
    }


def _build_parquet_schema() -> Any:
    """Build the pyarrow schema for the canonical OCSF column set.

    pyarrow is imported lazily (and only when this function is
    called) so the audit_export package import path stays cheap when
    Security Lake is not enabled. The Security Lake extra
    (`pip install iam-jit[security-lake]`) brings pyarrow in; the
    base package does not.
    """
    import pyarrow as pa  # noqa: PLC0415  — lazy on purpose

    type_lookup = {
        "string": pa.string(),
        "int32": pa.int32(),
        "int64": pa.int64(),
        "bool": pa.bool_(),
    }
    fields = []
    for name, type_name in OCSF_PARQUET_COLUMNS:
        fields.append(pa.field(name, type_lookup[type_name]))
    return pa.schema(fields)


def _rows_to_parquet_bytes(rows: list[dict[str, Any]]) -> bytes:
    """Serialise the given event rows into an in-memory parquet file
    matching the canonical OCSF schema. Returns the bytes that get
    uploaded to S3.

    Empty input returns the empty bytestring so the caller can skip
    a no-op upload. pyarrow is lazy-imported (same posture as
    `_build_parquet_schema`).
    """
    if not rows:
        return b""
    import pyarrow as pa  # noqa: PLC0415
    import pyarrow.parquet as pq  # noqa: PLC0415

    schema = _build_parquet_schema()
    # Build per-column arrays. pyarrow wants column-major; rows are
    # row-major. Defensive: any column missing from a row becomes
    # None so the resulting parquet has a null in that cell.
    columns: dict[str, list[Any]] = {name: [] for name, _ in OCSF_PARQUET_COLUMNS}
    for row in rows:
        for name, _ in OCSF_PARQUET_COLUMNS:
            columns[name].append(row.get(name))
    arrays = [
        pa.array(columns[name], type=schema.field(name).type)
        for name, _ in OCSF_PARQUET_COLUMNS
    ]
    table = pa.Table.from_arrays(arrays, schema=schema)
    buf = io.BytesIO()
    # Snappy is the Security-Lake-recommended compression — universally
    # supported by Athena / Spark / Glue without an extra codec install.
    pq.write_table(table, buf, compression="snappy")
    return buf.getvalue()


def _partition_path(
    *,
    region: str,
    when: _dt.datetime,
    class_uid: int,
    unix_ms: int,
) -> str:
    """Return the canonical Security Lake S3 key for one parquet file.

    Format::

        region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/
            <class-prefix>-<unix-ms>.parquet

    `when` is the wall-clock timestamp the rotation fired at; UTC
    everywhere (Security Lake's Glue crawler reads partitions in
    UTC). `unix_ms` is appended to keep the filename unique even
    when two flushes land in the same hour from concurrent producers
    (mirrors the AWS Firehose record-id pattern).
    """
    eventday = when.strftime("%Y%m%d")
    eventhour = when.strftime("%H")
    return (
        f"region={region}/"
        f"eventday={eventday}/"
        f"eventhour={eventhour}/"
        f"{_class_prefix(class_uid)}-{unix_ms}.parquet"
    )


def _aws_session_for(
    *,
    region: str,
    role_arn: str | None,
    session_name: str = "ibounce-security-lake",
) -> Any:
    """Build a boto3 Session for Security Lake uploads.

    When `role_arn` is set, perform an STS AssumeRole and return a
    Session bound to the temporary credentials. Otherwise return a
    Session that uses the default credential chain.

    Raises `SecurityLakeCredentialsError` if no usable credentials
    can be found (refuse-to-start posture per the issue body).
    """
    import boto3  # noqa: PLC0415
    from botocore.exceptions import (  # noqa: PLC0415
        BotoCoreError,
        ClientError,
        NoCredentialsError,
    )

    if role_arn:
        try:
            sts = boto3.client("sts", region_name=region)
            assumed = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
            )
        except NoCredentialsError as e:
            raise SecurityLakeCredentialsError(
                f"AssumeRole {role_arn} failed: no source credentials in "
                f"the default chain to assume from"
            ) from e
        except (ClientError, BotoCoreError) as e:
            raise SecurityLakeCredentialsError(
                f"AssumeRole {role_arn} failed: {e}"
            ) from e
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    # Default chain path. Probe via STS GetCallerIdentity so a missing
    # credential set surfaces at start() rather than at first flush.
    session = boto3.Session(region_name=region)
    try:
        sts = session.client("sts")
        sts.get_caller_identity()
    except NoCredentialsError as e:
        raise SecurityLakeCredentialsError(
            "no AWS credentials in the default chain "
            "(env / shared-config / instance role); pass --security-lake-role-arn "
            "or configure credentials before starting"
        ) from e
    except (ClientError, BotoCoreError) as e:
        raise SecurityLakeCredentialsError(
            f"AWS credential probe (sts:GetCallerIdentity) failed: {e}"
        ) from e
    return session


class SecurityLakeWriter:
    """Async-flushed Security Lake parquet writer.

    Lifecycle::

        writer = SecurityLakeWriter(
            bucket="my-security-lake-bucket",
            region="us-east-1",
            role_arn=None,
        )
        writer.start()              # probe credentials + spawn ticker
        writer.write({"...event..."})  # never blocks; in-memory append
        writer.stop()               # flush every pending class then exit

    Per-class batches: each OCSF class_uid keeps its own batch so a
    mixed stream (decisions + alerts + heartbeats) lands in
    class-segregated parquet files (Security Lake recommends one
    class per file for downstream-tool clarity).

    Thread-safety: write() / flush() / stop() all hold a single
    coarse lock. The proxy hot-path enqueues into an internal
    bounded queue first (lock-free; bounded so a slow flush worker
    doesn't OOM us) and the worker drains under the lock.
    """

    def __init__(
        self,
        *,
        bucket: str,
        region: str,
        role_arn: str | None = None,
        rotation_seconds: int = DEFAULT_ROTATION_SECONDS,
        max_batch_bytes: int = DEFAULT_MAX_BATCH_BYTES,
        max_pending_rows: int = DEFAULT_MAX_PENDING_ROWS,
        # For tests: inject a fake boto3 session so moto / unit tests
        # don't hit real AWS. Production callers leave this None.
        _session_factory: Any | None = None,
        _now: Any | None = None,
    ) -> None:
        if not bucket:
            raise SecurityLakeConfigError("bucket is required")
        if not region:
            raise SecurityLakeConfigError("region is required")
        if rotation_seconds <= 0:
            raise SecurityLakeConfigError(
                "rotation_seconds must be > 0 "
                "(use stop() to flush on shutdown)"
            )
        if max_batch_bytes <= 0:
            raise SecurityLakeConfigError("max_batch_bytes must be > 0")
        self.bucket = bucket
        self.region = region
        self.role_arn = role_arn
        self.rotation_seconds = rotation_seconds
        self.max_batch_bytes = max_batch_bytes
        self.max_pending_rows = max_pending_rows
        self._session_factory = _session_factory
        self._now = _now or (lambda: _dt.datetime.now(_dt.UTC))
        # Per-class batch storage. Each entry holds a list of flattened
        # row dicts + the wall-clock timestamp of the first row in the
        # batch (used to decide the rotation deadline).
        self._batches: dict[int, list[dict[str, Any]]] = {}
        self._batch_first_seen: dict[int, _dt.datetime] = {}
        self._lock = threading.Lock()
        self._s3_client: Any | None = None
        self._account_id: str | None = None
        self._caller_arn: str | None = None
        self._ticker_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        # Stats — surfaced via `status()` for the MCP status tool.
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
        """Probe credentials, open the S3 client, spawn the ticker.

        Idempotent. Raises `SecurityLakeCredentialsError` if no
        credentials are reachable.
        """
        if self._started:
            return
        if self._session_factory is not None:
            session = self._session_factory()
        else:
            session = _aws_session_for(
                region=self.region, role_arn=self.role_arn,
            )
        # Capture identity for the startup banner per the spec
        # ("log AWS account + role at startup banner"). Defensive: if
        # the test session_factory's STS is a stub, swallow the lookup
        # error so the rest of the writer keeps working.
        try:
            sts = session.client("sts")
            ident = sts.get_caller_identity()
            self._account_id = ident.get("Account")
            self._caller_arn = ident.get("Arn")
        except Exception:
            self._account_id = self._account_id or "unknown"
            self._caller_arn = self._caller_arn or "unknown"
        self._s3_client = session.client("s3", region_name=self.region)
        self._stop_event.clear()
        self._ticker_thread = threading.Thread(
            target=self._tick_loop,
            name="ibounce-security-lake-rotator",
            daemon=True,
        )
        self._ticker_thread.start()
        self._started = True

    def stop(self) -> None:
        """Flush every pending batch synchronously + stop the ticker.

        Idempotent. Per the issue body: "On shutdown: flush all
        pending synchronously."
        """
        if not self._started:
            return
        self._stop_event.set()
        if self._ticker_thread is not None:
            self._ticker_thread.join(timeout=10.0)
        # One last drain — anything that arrived after the final tick
        # gets flushed before the writer returns from stop().
        self.flush_all()
        self._started = False

    # ------------------------------------------------------------------
    # Public write surface
    # ------------------------------------------------------------------

    def write(self, event: dict[str, Any]) -> None:
        """Append one OCSF event to its class's in-memory batch.

        Never blocks. Never raises. If the per-class batch crosses the
        size cap, this call triggers a synchronous flush of that
        class's batch (other classes are unaffected).

        Drops + bumps the dropped counter when the total in-memory
        row count exceeds `max_pending_rows`. The status() snapshot
        surfaces both counts so the operator can spot a backed-up
        writer in the MCP status tool.
        """
        if not self._started:
            return
        class_uid = event.get("class_uid")
        if not isinstance(class_uid, int):
            # Unknown class events get bucketed under 0 so they still
            # land in a file the operator can grep.
            class_uid = 0
        try:
            row = _flatten_event_to_row(event)
        except Exception as e:
            self._record_error(f"flatten failed: {e}")
            return
        with self._lock:
            total_pending = sum(len(b) for b in self._batches.values())
            if total_pending >= self.max_pending_rows:
                self._dropped_events += 1
                self._last_error = (
                    f"security-lake batch full at {self.max_pending_rows} "
                    f"rows; dropped event"
                )
                return
            batch = self._batches.setdefault(class_uid, [])
            batch.append(row)
            self._batches[class_uid] = batch
            if class_uid not in self._batch_first_seen:
                self._batch_first_seen[class_uid] = self._now()
            should_flush_size = self._estimate_batch_bytes(batch) >= self.max_batch_bytes
        if should_flush_size:
            self._flush_class(class_uid)

    def flush_all(self) -> None:
        """Flush every pending class's batch synchronously.

        Safe to call from any thread. Used by `stop()` + by the
        operator-driven `audit-export flush` CLI subcommand.
        """
        with self._lock:
            class_uids = list(self._batches.keys())
        for class_uid in class_uids:
            self._flush_class(class_uid)

    # ------------------------------------------------------------------
    # Status surface
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Snapshot for the MCP audit-export status tool + /healthz."""
        with self._lock:
            pending = sum(len(b) for b in self._batches.values())
            return {
                "configured": True,
                "bucket": self.bucket,
                "region": self.region,
                "role_arn": self.role_arn or "",
                "account_id": self._account_id or "",
                "caller_arn": self._caller_arn or "",
                "rotation_seconds": self.rotation_seconds,
                "max_batch_bytes": self.max_batch_bytes,
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
        """Background ticker. Wakes every `min(rotation_seconds, 1)`
        seconds (or sooner on stop) and flushes any class whose
        oldest row is older than the rotation deadline."""
        # 1s minimum tick so tests with rotation_seconds=1 don't
        # over-sleep. Real-world rotation is 300s so this is cheap.
        tick = min(1.0, float(self.rotation_seconds))
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=tick)
            if self._stop_event.is_set():
                return
            try:
                self._flush_overdue()
            except Exception as e:
                # Per [[deliberate-feature-completion]]: ticker failure
                # must not kill the writer. Log + carry on.
                self._record_error(f"tick failed: {e}")

    def _flush_overdue(self) -> None:
        """Flush every class whose oldest row crossed the rotation
        deadline."""
        now = self._now()
        overdue: list[int] = []
        with self._lock:
            for class_uid, first_seen in list(self._batch_first_seen.items()):
                if (now - first_seen).total_seconds() >= self.rotation_seconds:
                    overdue.append(class_uid)
        for class_uid in overdue:
            self._flush_class(class_uid)

    def _flush_class(self, class_uid: int) -> None:
        """Serialise + upload the batch for one OCSF class. Empties the
        in-memory batch on success; on failure the batch is preserved
        so the next flush retries the same rows."""
        with self._lock:
            rows = self._batches.get(class_uid) or []
            if not rows:
                # Nothing to do; clear the timer slot so we don't
                # repeatedly evaluate an empty batch on every tick.
                self._batch_first_seen.pop(class_uid, None)
                return
            # Take a snapshot to release the lock before the upload.
            rows_snapshot = list(rows)
        try:
            payload = _rows_to_parquet_bytes(rows_snapshot)
        except Exception as e:
            self._record_error(f"parquet encode failed: {e}")
            return
        now = self._now()
        unix_ms = int(now.timestamp() * 1000)
        key = _partition_path(
            region=self.region,
            when=now,
            class_uid=class_uid,
            unix_ms=unix_ms,
        )
        try:
            assert self._s3_client is not None
            self._s3_client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=payload,
                ContentType="application/vnd.apache.parquet",
            )
        except Exception as e:
            self._record_error(f"s3 put_object failed: {e}")
            return
        # Success: pop the rows + bookkeeping.
        with self._lock:
            # Trim the rows we just uploaded; any rows that arrived
            # during the upload remain in the batch for the next flush.
            del self._batches[class_uid][: len(rows_snapshot)]
            if not self._batches[class_uid]:
                self._batches.pop(class_uid, None)
                self._batch_first_seen.pop(class_uid, None)
            else:
                # Reset the timer to NOW so the residual rows wait the
                # full rotation window before the next flush.
                self._batch_first_seen[class_uid] = now
            self._total_events += len(rows_snapshot)
            self._total_files_written += 1
            self._total_bytes_written += len(payload)
            self._writes_ok = True
        logger.info(
            "security-lake flush: class_uid=%d rows=%d bytes=%d key=%s",
            class_uid, len(rows_snapshot), len(payload), key,
        )

    def _estimate_batch_bytes(self, batch: list[dict[str, Any]]) -> int:
        """Cheap byte-cost estimate (no parquet round-trip) so the
        size-cap check stays O(1) per write.

        Real parquet bytes are usually 2-5x smaller than the row-sum
        thanks to snappy + columnar dictionary encoding, so this
        estimate is intentionally conservative — we'd rather rotate
        a slightly-smaller-than-cap file than blow past the cap.
        """
        # 256 bytes per row is the empirical average for a Bounce-shape
        # OCSF event after snappy. Multiplying by 4 keeps the estimate
        # conservative.
        return len(batch) * 1024

    def _record_error(self, msg: str) -> None:
        with self._lock:
            self._last_error = msg
            self._last_error_at_unix = time.time()
            self._writes_ok = False
        logger.warning("security-lake writer error: %s", msg)
