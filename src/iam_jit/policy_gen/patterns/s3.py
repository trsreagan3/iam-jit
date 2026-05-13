"""S3 task patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="s3-read",
        phrases=(
            "read s3", "read from s3", "get s3 object", "download from s3",
            "fetch from s3", "list s3", "list bucket", "list objects",
            "get object", "read bucket", "read from bucket", "read the",
            "s3 read", "from s3", "from bucket",
        ),
        allow_actions=(
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:ListBucket",
            "s3:ListBucketVersions",
            "s3:GetBucketLocation",
            "s3:GetBucketVersioning",
        ),
        deny_actions=("s3:GetObject", "s3:ListBucket"),
        resource_kinds=("s3-bucket",),
        wildcard_resources=("arn:aws:s3:::*", "arn:aws:s3:::*/*"),
        access_hint="read",
    ),
    Pattern(
        name="s3-write",
        phrases=(
            "write s3", "write to s3", "upload to s3", "put s3 object",
            "put object", "upload to bucket", "write to bucket", "s3 write",
            "upload file",
        ),
        allow_actions=(
            "s3:PutObject",
            "s3:PutObjectAcl",
            "s3:AbortMultipartUpload",
            "s3:GetObject",        # often need read-after-write
            "s3:ListBucket",
        ),
        deny_actions=("s3:PutObject",),
        resource_kinds=("s3-bucket",),
        wildcard_resources=("arn:aws:s3:::*", "arn:aws:s3:::*/*"),
        access_hint="write",
    ),
    Pattern(
        name="s3-delete",
        phrases=(
            "delete from s3", "delete s3 object", "remove from bucket",
            "s3 delete", "clean up bucket",
        ),
        allow_actions=(
            "s3:DeleteObject",
            "s3:DeleteObjectVersion",
            "s3:ListBucket",
            "s3:ListBucketVersions",
        ),
        deny_actions=("s3:DeleteObject",),
        resource_kinds=("s3-bucket",),
        wildcard_resources=("arn:aws:s3:::*", "arn:aws:s3:::*/*"),
        access_hint="write",
    ),
]
