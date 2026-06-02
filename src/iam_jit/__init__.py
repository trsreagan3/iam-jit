"""iam-jit: self-hosted, GitOps-driven, time-bound, least-privilege IAM."""

__version__ = "1.0.0"

# Python 3.10 compatibility: datetime.UTC was added in 3.11 (PEP 689).
# Patch it onto the stdlib datetime module so that all sub-modules that do
# `import datetime as _dt` and then use `_dt.UTC` work correctly on 3.10.
# See: https://docs.python.org/3/library/datetime.html#datetime.UTC
import datetime as _dt_compat
if not hasattr(_dt_compat, "UTC"):
    _dt_compat.UTC = _dt_compat.timezone.utc  # type: ignore[attr-defined]
