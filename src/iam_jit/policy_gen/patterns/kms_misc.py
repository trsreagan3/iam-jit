"""KMS, SQS, SNS, and miscellaneous service patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="kms-decrypt",
        phrases=(
            "decrypt", "kms decrypt", "use kms", "decrypt with kms",
            "envelope decrypt",
        ),
        allow_actions=(
            "kms:Decrypt",
            "kms:DescribeKey",
        ),
        deny_actions=("kms:Decrypt",),
        resource_kinds=("kms-key",),
        wildcard_resources=("arn:aws:kms:*:*:key/*",),
        access_hint="read",
    ),
    Pattern(
        name="kms-encrypt",
        phrases=(
            "encrypt", "kms encrypt", "encrypt with kms",
            "generate data key", "envelope encrypt",
        ),
        allow_actions=(
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:DescribeKey",
        ),
        deny_actions=("kms:Encrypt",),
        resource_kinds=("kms-key",),
        wildcard_resources=("arn:aws:kms:*:*:key/*",),
        access_hint="write",
    ),
    Pattern(
        name="sqs-send",
        phrases=(
            "send sqs", "send to queue", "publish to queue", "sqs send",
            "queue message", "send message",
        ),
        allow_actions=(
            "sqs:SendMessage",
            "sqs:SendMessageBatch",
            "sqs:GetQueueAttributes",
        ),
        deny_actions=("sqs:SendMessage",),
        resource_kinds=("sqs-queue",),
        wildcard_resources=("arn:aws:sqs:*:*:*",),
        access_hint="write",
    ),
    Pattern(
        name="sqs-receive",
        phrases=(
            "receive sqs", "consume queue", "pull from queue", "sqs receive",
            "read queue",
        ),
        allow_actions=(
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:GetQueueAttributes",
        ),
        deny_actions=("sqs:ReceiveMessage", "sqs:DeleteMessage"),
        resource_kinds=("sqs-queue",),
        wildcard_resources=("arn:aws:sqs:*:*:*",),
        access_hint="read",
    ),
    Pattern(
        name="sns-publish",
        phrases=(
            "publish sns", "send sns", "sns publish", "publish to topic",
            "notify via sns",
        ),
        allow_actions=(
            "sns:Publish",
            "sns:GetTopicAttributes",
        ),
        deny_actions=("sns:Publish",),
        resource_kinds=("sns-topic",),
        wildcard_resources=("arn:aws:sns:*:*:*",),
        access_hint="write",
    ),
    Pattern(
        name="sts-assume-role",
        phrases=(
            "assume role", "sts assume", "switch role", "assume the role",
        ),
        allow_actions=(
            "sts:AssumeRole",
        ),
        deny_actions=("sts:AssumeRole",),
        resource_kinds=("iam-role",),
        wildcard_resources=("arn:aws:iam::*:role/*",),
        access_hint="read-write",
    ),
]
