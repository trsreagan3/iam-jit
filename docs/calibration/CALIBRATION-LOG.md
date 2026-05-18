# iam-jit calibration log

One-line entries per calibration run. See linked report for detail.

- 2026-05-16: 100-prompt sufficiency loop — joint rate 1.8%, top failure pattern no-policy-baseline-fallback-missed (28/49 insufficient cases), see 100-prompt-sufficiency-loop.md
- 2026-05-19: corpus sweep #256 — 2,267 cases re-scored against scorer commit 31417d2; 96 failures (95.77% pass). Two failure modes: 86 under-flags (concentrated in agent_discovered newer-service primitives + STS federated variants + condition vacuity edges) + 10 over-flags (concentrated in vendor_real_world read-mostly policies that hit sensitive-service rule linearly). Both modes were pre-documented in corpus YAML CALIBRATION-GAP annotations as scorer backlog from adversarial rounds 8-13. No scorer fixes shipped; 13 proposed fixes triaged for founder decision. CI exclusion remains in place pending fix prioritization. See ../CALIBRATION-SWEEP-2026-05-19.md.
