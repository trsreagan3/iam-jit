# #345 / §A25 — Easy profile extension + deny visibility.
"""Easy-allow + deny-visibility operations.

Symmetric flip of :mod:`iam_jit.dynamic_denies`:

  * dynamic-deny direction (shipped #324e): "make sure agent doesn't
    touch X" -> append to ``~/.iam-jit/dynamic-denies.yaml``.
  * easy-allow direction (this slice): "this is safe, allow it" ->
    append to a profile's ``allow_rules`` in
    ``~/.iam-jit/bouncer/profiles.yaml``.
  * deny-visibility direction (this slice): "what just got blocked?"
    -> query each bouncer's ``/audit/events`` filtered to DENY verdicts.

Per ``[[creates-never-mutates]]`` profile mutations are ADDITIVE:
existing allow_rules / deny_actions are preserved; new rules go AT
THE END with a ``note`` field that carries provenance (origin tag +
reason + actor).

Per ``[[dynamic-deny-rules]]`` conflict resolution: a personal allow
CANNOT loosen an org-distributed deny (or an org-distributed dynamic-
deny rule). The dynamic-deny watcher continues to short-circuit
profile-level ALLOWs at request time.

Per ``[[ibounce-honest-positioning]]``: bouncer reload failures are
surfaced honestly but do NOT abort the CLI — the YAML file IS the
source of truth, and the bouncer's profile-watcher picks up the
change on its next reload poll (or operator can curl the reload
endpoint manually).
"""
