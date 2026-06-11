"""Lambda entry point. One function, dispatched by event source.

  - HTTP requests via the Function URL → FastAPI app via Mangum.
  - Scheduled EventBridge events → `scheduled.run_scheduled_tasks`,
    which aggregates every periodic chore (token sweep today; expired-
    grant cleanup + audit checkpoint in later phases).

The FastAPI app is built once at cold-start via `create_app()`, which
reads `IAM_JIT_*` env vars (set by the SAM template) to wire up the
DynamoDB-backed stores. Warm invocations reuse the same app instance.
"""

from __future__ import annotations

import logging
from typing import Any

from mangum import Mangum

from .app import create_app
from .scheduled import run_scheduled_tasks

logger = logging.getLogger("iam_jit.lambda")

# Build once at cold-start; reused across warm invocations.
_app = create_app()
_mangum = Mangum(_app, lifespan="off")


def _is_scheduled_event(event: dict[str, Any]) -> bool:
    return event.get("source") == "aws.events" or event.get("detail-type") == "Scheduled Event"


def handler(event: dict[str, Any], context: Any) -> Any:
    if _is_scheduled_event(event):
        tokens_store = getattr(_app.state, "api_tokens_store", None)
        result = run_scheduled_tasks(tokens_store=tokens_store)
        logger.info("scheduled sweep complete: %s", result)
        return result

    return _mangum(event, context)
