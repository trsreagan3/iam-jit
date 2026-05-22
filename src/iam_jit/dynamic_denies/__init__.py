# #324a — ibounce dynamic-deny core (cross-product schema v1.0).
"""ibounce's consumer side of the cross-product dynamic-deny rules
surface (#324, slice #324a).

The full cross-product design lives at
``docs/DYNAMIC-DENY-RULES.md`` and the on-disk YAML shape at
``docs/schemas/dynamic-denies-v1.json``. This package implements the
ibounce slice:

  * :mod:`loader` — read + JSON-schema-validate
    ``~/.iam-jit/dynamic-denies.yaml``, filter to rules whose
    ``applied_to`` list contains ``ibounce``, drop expired rules at
    load time.
  * :mod:`matcher` — classify a request's resource ARN against the
    rule set's compiled glob patterns and return the first matching
    rule (or ``None`` when nothing matches).
  * :mod:`watcher` — fsevents/inotify-driven hot reload via
    ``watchdog``. On parse error the previous in-memory rule set is
    retained (fail-CLOSED per
    ``[[ibounce-honest-positioning]]``) and a
    ``dynamic_deny.parse_error`` admin-action event is emitted.
  * :mod:`types` — shared dataclasses (Rule / RuleSet / File).

Why a separate package vs adding to ``bouncer/``? Two reasons:

  1. Cross-bouncer parity. Per ``[[cross-product-agent-parity]]`` the
     kbouncer + dbounce + gbounce siblings each ship their dynamic-deny
     code in a peer ``dynamicdeny/`` directory; mirroring the layout
     keeps the touch set discoverable across products.
  2. The #324e CLI fan-out (``src/iam_jit/cli_deny.py`` already in the
     repo) writes into the same on-disk file the loader here reads;
     the writer (still skeleton in #324e) will live alongside the
     reader at
     ``src/iam_jit/dynamic_denies/store.py`` per
     ``docs/tasks/324-dynamic-deny-rules.md``. This package is the
     reader half; #324e adds the writer.

Per ``[[creates-never-mutates]]`` the loader is read-only — no
mutation of the on-disk file. Per ``[[deliberate-feature-completion]]``
this slice ships the full reader pipeline (loader + watcher + matcher +
decision-pipeline integration + mgmt endpoint + tests + docs); no
half-finished surfaces.
"""

from .loader import (
    DEFAULT_PATH_ENV,
    DEFAULT_REL_PATH,
    PRODUCT_MAGIC,
    SCHEMA_VERSION,
    DynamicDenyLoadError,
    load_file,
    resolve_default_path,
)
from .matcher import ArnMatch, match_arn
from .types import Rule, RuleSet
from .watcher import (
    DynamicDenyWatcher,
    ReloadReason,
    make_admin_action_emitter,
)

__all__ = [
    "ArnMatch",
    "DEFAULT_PATH_ENV",
    "DEFAULT_REL_PATH",
    "DynamicDenyLoadError",
    "DynamicDenyWatcher",
    "PRODUCT_MAGIC",
    "ReloadReason",
    "Rule",
    "RuleSet",
    "SCHEMA_VERSION",
    "load_file",
    "make_admin_action_emitter",
    "match_arn",
    "resolve_default_path",
]
