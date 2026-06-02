"""#725 — coarse per-call cost estimator for the circuit breaker.

HONEST FRAMING (``[[ibounce-honest-positioning]]``):

This is an ORDER-OF-MAGNITUDE estimate, not your AWS bill. From inside
an HTTP proxy we see the request line (service + action) but not the
result-set size, the data-transfer bytes, or the negotiated price your
account actually pays. So we map each call to a coarse per-call USD
figure from a small rate card keyed on service class. Anything we
don't recognise gets a flat fallback.

The estimate is deliberately CONSERVATIVE-HIGH for known-expensive
verb shapes (KMS crypto ops, Bedrock invoke, expensive reads) so the
breaker errs toward tripping a true runaway slightly EARLY rather than
late. Every surface that prints a dollar figure says "estimated."

The point isn't to be a billing system — it's to give the cost
dimension *enough* signal that a 200×-normal-rate retry-loop crosses a
generous threshold while normal work doesn't. Operators who want exact
cost control use ``max_calls_per_window`` (which is exact) instead of
``max_usd_per_window`` (which is this estimate).
"""

from __future__ import annotations

# Per-call USD estimates by AWS service class. Figures are coarse
# round-number proxies — NOT vendor price-list values. They encode the
# RELATIVE expense of call classes (a Bedrock invoke is ~1000× an S3
# GET) which is what matters for catching a runaway, not absolute
# precision. Tunable in one place if a customer's mix differs.
_PER_CALL_USD_BY_SERVICE: dict[str, float] = {
    # Cheap, high-volume control-plane / object reads.
    "s3": 0.0000004,        # ~$0.40 per million GETs
    "dynamodb": 0.00000025,
    "sqs": 0.0000004,
    "sns": 0.0000005,
    "logs": 0.0000005,
    "cloudwatch": 0.00001,
    "sts": 0.0,             # AssumeRole etc. — free
    "iam": 0.0,             # IAM management — free
    "ec2": 0.00001,         # describe-class control-plane calls
    # Mid: crypto + secrets.
    "kms": 0.00003,         # ~$0.03 per 1000 crypto ops
    "secretsmanager": 0.000005,
    # Expensive: managed-inference. A runaway here is the headline
    # "$400M leaked" scenario.
    "bedrock": 0.01,        # one invoke is dollars-cents, not micro-cents
    "sagemaker": 0.005,
    "comprehend": 0.0001,
    "textract": 0.0015,
    "rekognition": 0.001,
}

# Fallback for any service not in the card. Set just above the cheap
# control-plane tier so unknown calls still accrue *some* cost and a
# runaway against an unmapped service can't slip the dollar dimension
# entirely.
_FALLBACK_PER_CALL_USD = 0.000001

# A few verbs are markedly pricier than their service's typical call.
# Multiplier applied when the action (lowercased) starts with one of
# these. Conservative-high per the module docstring.
_EXPENSIVE_VERB_MULTIPLIERS: dict[str, float] = {
    "invoke": 1.0,    # bedrock invoke already priced high; no extra bump
    "decrypt": 1.0,
    "encrypt": 1.0,
    "generatedatakey": 1.0,
}


def estimate_call_cost_usd(service: str | None, action: str | None) -> float:
    """Return a coarse, conservative-high USD estimate for ONE gated
    call to ``service:action``.

    Never raises; unknown inputs map to the fallback. The returned
    figure is an ESTIMATE — callers that surface it MUST label it so
    per ``[[ibounce-honest-positioning]]``.
    """
    svc = (service or "").strip().lower()
    base = _PER_CALL_USD_BY_SERVICE.get(svc, _FALLBACK_PER_CALL_USD)
    if base <= 0:
        return 0.0
    act = (action or "").strip().lower()
    mult = 1.0
    for verb, m in _EXPENSIVE_VERB_MULTIPLIERS.items():
        if act.startswith(verb):
            mult = max(mult, m)
    return base * mult


__all__ = ["estimate_call_cost_usd"]
