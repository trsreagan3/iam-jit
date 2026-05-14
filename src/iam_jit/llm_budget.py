"""Per-customer monthly LLM-narrative budget.

Pro and Team tiers include a fixed monthly allowance of LLM-
narrated scores. Above the cap, /api/v1/score continues to
return a fully-deterministic score (the calibration-discipline
floor) — just without the LLM narrative. The response includes
`llm_budget_exceeded: true` and a hint to upgrade.

Why a budget cap exists:
- LLM calls dominate marginal cost. A Pro customer running CI
  at scale could rack up $thousands/month in Bedrock charges
  vs a $99 subscription.
- The cap aligns customer expectation: Pro IS the
  "deterministic + summary narrative" tier, not "unlimited LLM
  on every PR."
- Enterprise tier is the unlimited-narrative option, priced
  to match the underlying compute cost.

Architecture:
- Counter is keyed by (customer_id, year_month). Month boundaries
  in UTC.
- `consume_or_reject(customer_id, tier)` increments the counter
  atomically. Returns `True` (consumed; you may call the LLM) or
  `False` (cap hit; serve deterministic-only).
- The atomic-increment primitive uses DynamoDB's
  `UpdateItem(UpdateExpression="ADD count :one", ReturnValues=...)`
  with a conditional check on the cap.

Caps (defaults, env-overridable):
- Pro (`IAM_JIT_LLM_BUDGET_PRO`):   1500/mo
- Team (`IAM_JIT_LLM_BUDGET_TEAM`): 15000/mo
- Enterprise (`IAM_JIT_LLM_BUDGET_ENTERPRISE`): None (unlimited)
"""

from __future__ import annotations

import datetime as _dt
import os
import threading
from collections import defaultdict
from typing import Protocol


_DEFAULT_BUDGETS = {
    "free":       0,       # free tier never gets LLM
    "indie":      0,       # indie is deterministic-only by design
    "pro":     1500,       # Sonnet narratives (see _DEFAULT_MODELS_BY_TIER)
    "team":    2500,       # Opus narratives — lower cap than Pro
                            # because Opus is 5× the cost; the cap
                            # keeps margin healthy at the $499 price
    "enterprise": None,    # None = unlimited
}


def _budget_for_tier(tier: str) -> int | None:
    """Return the monthly LLM-call budget for a tier. None = unlimited."""
    tier = (tier or "free").lower().strip()
    env_key = f"IAM_JIT_LLM_BUDGET_{tier.upper()}"
    raw = (os.environ.get(env_key) or "").strip()
    if raw:
        if raw.lower() in {"none", "unlimited", "-1"}:
            return None
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return _DEFAULT_BUDGETS.get(tier, 0)


def _current_year_month() -> str:
    """`YYYY-MM` in UTC. Counter rolls over at month boundaries."""
    now = _dt.datetime.now(_dt.UTC)
    return f"{now.year:04d}-{now.month:02d}"


class LLMBudgetStore(Protocol):
    def consume_or_reject(self, customer_id: str, tier: str) -> bool: ...

    def usage_for(self, customer_id: str) -> int: ...

    def reset_for_tests(self) -> None: ...


class InMemoryLLMBudgetStore:
    def __init__(self) -> None:
        self._counts: dict[tuple[str, str], int] = defaultdict(int)
        self._lock = threading.Lock()

    def consume_or_reject(self, customer_id: str, tier: str) -> bool:
        budget = _budget_for_tier(tier)
        if budget is None:
            # Unlimited — Enterprise tier.
            return True
        if budget == 0:
            return False
        key = (customer_id, _current_year_month())
        with self._lock:
            current = self._counts[key]
            if current >= budget:
                return False
            self._counts[key] = current + 1
            return True

    def usage_for(self, customer_id: str) -> int:
        key = (customer_id, _current_year_month())
        with self._lock:
            return self._counts.get(key, 0)

    def reset_for_tests(self) -> None:
        with self._lock:
            self._counts.clear()


class DynamoDBLLMBudgetStore:
    """DynamoDB-backed atomic LLM-call counter.

    Schema:
      table: <IAM_JIT_LLM_BUDGET_TABLE>
      partition key: `customer_id` (String)
      sort key:      `year_month`  (String, "YYYY-MM")
      attribute:     `count`       (Number)
      TTL attribute: `ttl_at`      (Number, unix seconds — 90 days
                                    past the year_month — retained
                                    only for compliance + visibility
                                    in the admin queue)
    """

    _TTL_SECONDS_BEYOND_MONTH = 90 * 24 * 60 * 60

    def __init__(self, table_name: str, *, client: object | None = None) -> None:
        self._table_name = table_name
        if client is not None:
            self._client = client
        else:
            import boto3

            self._client = boto3.client("dynamodb")

    def consume_or_reject(self, customer_id: str, tier: str) -> bool:
        budget = _budget_for_tier(tier)
        if budget is None:
            return True
        if budget == 0:
            return False
        year_month = _current_year_month()
        ttl_at = int(_dt.datetime.now(_dt.UTC).timestamp()) + self._TTL_SECONDS_BEYOND_MONTH
        try:
            resp = self._client.update_item(
                TableName=self._table_name,
                Key={
                    "customer_id": {"S": customer_id},
                    "year_month": {"S": year_month},
                },
                UpdateExpression="ADD #c :one SET ttl_at = :ttl",
                # Refuse if count already at or above the cap.
                ConditionExpression="attribute_not_exists(#c) OR #c < :cap",
                ExpressionAttributeNames={"#c": "count"},
                ExpressionAttributeValues={
                    ":one": {"N": "1"},
                    ":cap": {"N": str(budget)},
                    ":ttl": {"N": str(ttl_at)},
                },
                ReturnValues="UPDATED_NEW",
            )
            # If we got here without ConditionalCheckFailed, we
            # successfully consumed one unit.
            return True
        except Exception as e:
            if "ConditionalCheckFailedException" in str(e) or (
                hasattr(e, "response")
                and getattr(e, "response", {})
                .get("Error", {})
                .get("Code")
                == "ConditionalCheckFailedException"
            ):
                return False
            raise

    def usage_for(self, customer_id: str) -> int:
        year_month = _current_year_month()
        resp = self._client.get_item(
            TableName=self._table_name,
            Key={
                "customer_id": {"S": customer_id},
                "year_month": {"S": year_month},
            },
            ConsistentRead=True,
        )
        item = resp.get("Item") if isinstance(resp, dict) else None
        if not item:
            return 0
        try:
            return int(item["count"]["N"])
        except (KeyError, ValueError):
            return 0

    def reset_for_tests(self) -> None:
        return None


_GLOBAL: LLMBudgetStore | None = None


def get_default_store() -> LLMBudgetStore:
    global _GLOBAL
    if _GLOBAL is None:
        table = (os.environ.get("IAM_JIT_LLM_BUDGET_TABLE") or "").strip()
        if table:
            _GLOBAL = DynamoDBLLMBudgetStore(table)
        else:
            _GLOBAL = InMemoryLLMBudgetStore()
    return _GLOBAL


def reset_default_store_for_tests() -> None:
    global _GLOBAL
    _GLOBAL = None


# ---- Tier → model mapping ------------------------------------------
#
# Bedrock cost: Opus ~5x Sonnet for the same prompt. Reserve Opus for
# Enterprise (where the customer is paying enough to fund it); Pro and
# Team use Sonnet by default. Operators can override per tier via env
# (`IAM_JIT_LLM_MODEL_<TIER>`).

_DEFAULT_MODELS_BY_TIER = {
    "pro":        "claude-sonnet-4-6",  # 5× cheaper than Opus; ~70% of the
                                          # narrative quality for the
                                          # explain-the-score use case
    "team":       "claude-opus-4-7",    # Team customers paying $499 get
                                          # the better-quality narrative
    "enterprise": "claude-opus-4-7",
}


def model_for_tier(tier: str) -> str:
    """Resolve the LLM model id to use for a customer at `tier`.
    Returns a Bedrock-compatible model id (or an Anthropic-API
    model id; both share the same string)."""
    tier = (tier or "pro").lower().strip()
    env_key = f"IAM_JIT_LLM_MODEL_{tier.upper()}"
    explicit = (os.environ.get(env_key) or "").strip()
    if explicit:
        return explicit
    return _DEFAULT_MODELS_BY_TIER.get(tier, "claude-sonnet-4-6")
