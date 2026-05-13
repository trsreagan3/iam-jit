"""Locate data files that ship alongside the package.

In the source tree the data files live at repo root (`schemas/`,
`infrastructure/`) so cfn-lint, Makefile, and test fixtures can
reference them at fixed paths. In a Lambda deploy, SAM bundles the
contents of `CodeUri` (= `src/`) under `/var/task/`, so the same
files end up at `/var/task/schemas/...` rather than at `/var/...`.

`pathlib.Path(__file__).resolve().parents[2]` resolves to the repo
root locally but to `/var` in Lambda — that mismatch caused a hidden
class of FileNotFoundError errors that only surfaced in production
(request-validation, user-store-load, destination-account onboarding).

This resolver walks a handful of candidate ancestors and returns the
first that exists. Layouts checked:

  - parents[2] / parts       (source tree: <repo>/schemas/...)
  - parents[1] / parts       (lambda bundle: /var/task/schemas/...)
  - parent / parts           (package-local: <repo>/src/iam_jit/schemas/...)

The `prepare-lambda-bundle.sh` pre-build step keeps the lambda-bundle
layout populated; the resolver is the safety net so behavior is
identical whether the data files were copied, symlinked, or are
served from the canonical repo location.
"""

from __future__ import annotations

import pathlib


def find(*parts: str) -> pathlib.Path:
    """Return the first existing path among the supported layouts.

    `parts` is a sequence of path segments (e.g. `find("schemas",
    "request.schema.json")`). Raises FileNotFoundError if none of the
    candidate layouts exist, with all checked paths in the message so
    debugging is one stack-trace away from the answer.
    """
    here = pathlib.Path(__file__).resolve()
    rel = pathlib.Path(*parts)
    candidates = [
        here.parents[2] / rel,   # source tree: <repo>/<parts>
        here.parents[1] / rel,   # lambda bundle: /var/task/<parts>
        here.parent / rel,       # package-local fallback
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError(
        f"resource {rel} not found in any candidate layout: "
        f"{[str(c) for c in candidates]}"
    )
