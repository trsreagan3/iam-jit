"""#403 / §A49 — ``iam-jit autopilot`` one-command background daemon.

Reads a ``.iam-jit.yaml`` declaration (per §A43 schema), starts the
bouncers, monitors them, and periodically calls
``iam_jit_improve_profile`` (#401) per the declaration's improve
cadence. Surfaces denies via the existing #389 notification hook
(stderr / webhook placeholder).

Subcommands:

  * ``iam-jit autopilot start [--config PATH] [--detach]``
  * ``iam-jit autopilot status``
  * ``iam-jit autopilot stop``

Strict per the brief:

  * Honors ``posture: managed`` — autopilot REFUSES to run improve in
    managed mode (clear error, no silent skip).
  * Auto-restart on bouncer crash, max 3 attempts per minute then alert.
  * PID file at ``~/.iam-jit/autopilot.pid``.

Per [[creates-never-mutates]] autopilot READS + STARTS bouncers; never
modifies the operator's existing bouncer configs.

Per [[ibounce-honest-positioning]] if autopilot cannot restart a
bouncer after 3 attempts, it surfaces the alert explicitly — it does
not keep retrying silently.

Per [[cross-product-agent-parity]] autopilot is a cross-product
orchestrator — per-bouncer logic lives in each bouncer's startup code;
autopilot only coordinates.
"""

from .daemon import (
    AutopilotError,
    AutopilotStatus,
    AutopilotSupervisor,
    autopilot_start,
    autopilot_status,
    autopilot_stop,
    register_autopilot_command,
    resolve_pid_path,
)

__all__ = [
    "AutopilotError",
    "AutopilotStatus",
    "AutopilotSupervisor",
    "autopilot_start",
    "autopilot_status",
    "autopilot_stop",
    "register_autopilot_command",
    "resolve_pid_path",
]
