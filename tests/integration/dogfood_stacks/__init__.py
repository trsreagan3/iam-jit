"""Stack definitions used by the nightly dogfood (see
docs/CI-NIGHTLY-DOGFOOD.md).

Each stack module exports three top-level constants/functions:

  INTENDED_ACTIONS : list[dict]
    The boto3 calls plan-capture will record. Each entry is::

        {
          "service": "ec2",                    # boto3 client name
          "operation_name": "DescribeImages",  # snake_case-able op
          "params": {...},                     # boto3 kwargs
          "iam_action": "ec2:DescribeImages",  # canonical action
        }

    These flow through ibounce in plan-capture mode (no AWS state
    is mutated), then get folded into the iam-jit request policy.

  ACCURACY_PROBES : list[dict]
    Read-only Describes the assumed role MUST be able to perform.
    Same shape as INTENDED_ACTIONS but only the read-only subset.
    Used for F12 (accuracy cross-check).

  NEGATIVE_PROBES : list[str]
    IAM actions (e.g. `iam:ListUsers`) that MUST be denied when the
    assumed role tries them. Used for F13 (out-of-scope negative).

  STACK_TAG : str
    Per-stack tag value so cleanup + audit can distinguish stacks
    within a single RunId.

The stack modules are intentionally minimal data — no AWS calls,
no LLM, no agent. The dogfood script does all the wiring.
"""

from __future__ import annotations

from . import stack_1_vpc_ec2, stack_2_lambda_apigw, stack_3_s3_iam

ALL_STACKS = [stack_1_vpc_ec2, stack_2_lambda_apigw, stack_3_s3_iam]

__all__ = ["ALL_STACKS", "stack_1_vpc_ec2", "stack_2_lambda_apigw", "stack_3_s3_iam"]
