"""Plan-capture file reader (v1alpha1).

Reads the JSONL capture format defined in
`docs/specs/PLAN-CAPTURE-FORMAT.md`. Producers will land later
(see task #118); the reader is the durable contract iam-jit uses
to consume captures regardless of who produced them.

Usage:

    from iam_jit.plan_capture import read_capture

    for call in read_capture("plan.jsonl"):
        print(call.iam_action, call.iam_resource)

The CapturedCall dataclass exposes the `iam_jit` sub-block
fields directly (iam_action, iam_resource, access_type), since
those are what the recommender / synthesizer consumes. The raw
request / response objects are kept under `raw` for callers
that need them.
"""

from __future__ import annotations

import dataclasses
import gzip
import io
import json
import pathlib
from typing import Any, Iterable, Iterator


SCHEMA_VERSION_V1ALPHA1 = "iam-jit.dev/plan-capture/v1alpha1"

# Schemas the reader accepts. Add v1, v2, ... here as they ship.
_ACCEPTED_SCHEMAS: frozenset[str] = frozenset({SCHEMA_VERSION_V1ALPHA1})

# WB11-10 closure: cap reader inputs so a poisoned capture file
# can't OOM the recommender. A real-world plan capture is on the
# order of hundreds of KB even for large terraform plans; multi-MB
# is suspicious and gigabyte-scale is hostile (decompression bombs,
# log-injected captures from a compromised proxy).
_MAX_LINE_BYTES = 1 * 1024 * 1024          # 1 MB per JSONL line
_MAX_FILE_BYTES_UNCOMPRESSED = 256 * 1024 * 1024   # 256 MB total uncompressed


class PlanCaptureError(Exception):
    """Raised when a capture file fails validation."""


@dataclasses.dataclass(frozen=True)
class CapturedCall:
    """One captured AWS API call. Fields mirror the on-disk shape."""

    ts: str
    service: str
    action: str
    region: str
    iam_action: str
    iam_resource: str | tuple[str, ...]
    access_type: str
    account_id: str | None = None
    principal_arn: str | None = None
    response_status: int | None = None
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def is_read_only(self) -> bool:
        return self.access_type in ("read-only", "read")


def _open_capture(path: pathlib.Path | str) -> Iterator[str]:
    """Open the capture file, transparently handling .gz.

    Enforces per-line + total-size caps to defend against
    decompression-bomb captures (WB11-10). Lines exceeding
    `_MAX_LINE_BYTES` raise PlanCaptureError; total uncompressed
    bytes exceeding `_MAX_FILE_BYTES_UNCOMPRESSED` aborts iteration.
    """
    p = pathlib.Path(path)
    is_gz = p.suffix == ".gz" or str(p).endswith(".jsonl.gz")
    opener = gzip.open if is_gz else open  # type: ignore[assignment]
    total = 0
    with opener(p, "rt", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line_bytes = len(line.encode("utf-8"))
            if line_bytes > _MAX_LINE_BYTES:
                raise PlanCaptureError(
                    f"line {lineno}: exceeds {_MAX_LINE_BYTES} bytes "
                    f"(was {line_bytes}). A single API call should never "
                    f"need this much capture data; reject as malformed."
                )
            total += line_bytes
            if total > _MAX_FILE_BYTES_UNCOMPRESSED:
                raise PlanCaptureError(
                    f"capture exceeds {_MAX_FILE_BYTES_UNCOMPRESSED} "
                    f"uncompressed bytes (decompression-bomb defense)"
                )
            yield line


def parse_line(line: str, *, lineno: int = 0) -> CapturedCall:
    """Parse one line of a capture file into a CapturedCall.

    Raises PlanCaptureError on malformed lines. Blank lines and
    comment lines are not permitted by the spec; callers should
    skip them at the source.
    """
    if not line.strip():
        raise PlanCaptureError(f"line {lineno}: blank lines not permitted")
    try:
        data = json.loads(line)
    except json.JSONDecodeError as e:
        raise PlanCaptureError(f"line {lineno}: invalid JSON ({e})")

    schema = data.get("schema")
    if schema not in _ACCEPTED_SCHEMAS:
        raise PlanCaptureError(
            f"line {lineno}: unsupported schema {schema!r}. "
            f"Accepted: {sorted(_ACCEPTED_SCHEMAS)}"
        )

    # Required top-level fields.
    for field in ("ts", "service", "action", "region"):
        if not isinstance(data.get(field), str):
            raise PlanCaptureError(
                f"line {lineno}: missing/invalid required field {field!r}"
            )

    # Required iam_jit projection.
    iam_jit_block = data.get("iam_jit") or {}
    if not isinstance(iam_jit_block, dict):
        raise PlanCaptureError(
            f"line {lineno}: 'iam_jit' must be an object"
        )
    iam_action = iam_jit_block.get("iam_action")
    iam_resource = iam_jit_block.get("iam_resource")
    access_type = iam_jit_block.get("access_type")
    if not (isinstance(iam_action, str)
            and isinstance(access_type, str)
            and isinstance(iam_resource, (str, list))):
        # WB11-09 closure: iam_resource MUST be present + typed.
        # Previously `iam_resource: null` was silently promoted to
        # `"*"` — a producer bug + a recommender footgun.
        raise PlanCaptureError(
            f"line {lineno}: iam_jit must have "
            "iam_action:str, iam_resource:str|array (NOT null), "
            "access_type:str"
        )

    # Normalise iam_resource to a str or tuple[str, ...]
    if isinstance(iam_resource, list):
        if not all(isinstance(r, str) for r in iam_resource):
            raise PlanCaptureError(
                f"line {lineno}: iam_resource array must contain strings"
            )
        if not iam_resource:
            raise PlanCaptureError(
                f"line {lineno}: iam_resource array must not be empty"
            )
        iam_resource_normalized: str | tuple[str, ...] = tuple(iam_resource)
    else:
        iam_resource_normalized = iam_resource

    return CapturedCall(
        ts=data["ts"],
        service=data["service"],
        action=data["action"],
        region=data["region"],
        iam_action=iam_action,
        iam_resource=iam_resource_normalized,
        access_type=access_type,
        account_id=data.get("account_id"),
        principal_arn=data.get("principal_arn"),
        response_status=data.get("response_status"),
        raw=data,
    )


def read_capture(path: pathlib.Path | str) -> Iterator[CapturedCall]:
    """Yield CapturedCall objects from a capture file.

    Raises PlanCaptureError on a malformed line (and aborts iteration).
    """
    for lineno, line in enumerate(_open_capture(path), start=1):
        if not line.strip():
            # The spec says blank lines aren't permitted, but it's
            # ergonomically nice to allow trailing newlines. We
            # silently skip them when they're literally just
            # whitespace; we error on non-whitespace bad lines.
            continue
        yield parse_line(line, lineno=lineno)


def read_captures(paths: Iterable[pathlib.Path | str]) -> Iterator[CapturedCall]:
    """Yield CapturedCalls from multiple capture files in order."""
    for p in paths:
        yield from read_capture(p)


def summarize(calls: Iterable[CapturedCall]) -> dict[str, Any]:
    """Roll up a capture into a small dict suitable for the recommender.

    Returns:
      {
        "total": int,
        "by_service": {service: count},
        "by_access_type": {access_type: count},
        "iam_actions": sorted list of unique iam_action strings,
        "resources_touched": sorted list of unique resource ARNs,
      }
    """
    by_service: dict[str, int] = {}
    by_access: dict[str, int] = {}
    iam_actions: set[str] = set()
    resources: set[str] = set()
    total = 0
    for call in calls:
        total += 1
        by_service[call.service] = by_service.get(call.service, 0) + 1
        by_access[call.access_type] = by_access.get(call.access_type, 0) + 1
        iam_actions.add(call.iam_action)
        if isinstance(call.iam_resource, tuple):
            resources.update(call.iam_resource)
        else:
            resources.add(call.iam_resource)
    return {
        "total": total,
        "by_service": by_service,
        "by_access_type": by_access,
        "iam_actions": sorted(iam_actions),
        "resources_touched": sorted(resources),
    }


def write_capture(
    path: pathlib.Path | str,
    calls: Iterable[CapturedCall],
    *,
    schema: str = SCHEMA_VERSION_V1ALPHA1,
) -> int:
    """Write CapturedCalls to a JSONL file. Returns count written.

    Convenience for test fixtures + future producers. Production
    producers should write raw dicts (with the schema field set)
    rather than going through CapturedCall, since they may have
    additional fields the dataclass doesn't preserve.
    """
    count = 0
    p = pathlib.Path(path)
    opener = gzip.open if str(p).endswith(".gz") else open  # type: ignore[assignment]
    with opener(p, "wt", encoding="utf-8") as f:
        for call in calls:
            obj = {
                "schema": schema,
                "ts": call.ts,
                "service": call.service,
                "action": call.action,
                "region": call.region,
                "iam_jit": {
                    "iam_action": call.iam_action,
                    "iam_resource": (
                        list(call.iam_resource)
                        if isinstance(call.iam_resource, tuple)
                        else call.iam_resource
                    ),
                    "access_type": call.access_type,
                },
            }
            if call.account_id:
                obj["account_id"] = call.account_id
            if call.principal_arn:
                obj["principal_arn"] = call.principal_arn
            if call.response_status is not None:
                obj["response_status"] = call.response_status
            f.write(json.dumps(obj) + "\n")
            count += 1
    return count
