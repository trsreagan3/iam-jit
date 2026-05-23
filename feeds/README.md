# iam-jit threat-feed bundles

Per `[[ambient-autonomous-protection]]` (Phase C, tasks #407-#411 / §A51-§A55) this directory holds the **publishable** threat-feed bundles iam-jit ships with v1.0.

## Bundles

| File | Publisher | Entries | Status |
|------|-----------|---------|--------|
| `official-v1.json` | `iam-jit-official` | 35 CRITICAL+HIGH (3 MEDIUM, 2 LOW) | Bootstrap seed — see "How rules were sourced" below. |

The bundle is **signed Ed25519** by the iam-jit-official publisher. Operators who want to subscribe pin both the URL (or commit the file into their repo) and the publisher pubkey in their `.iam-jit.yaml`:

```yaml
iam-jit:
  threat_feed:
    enabled: true
    update_cadence: daily
    feeds:
      - url: "file:///path/to/feeds/official-v1.json"
        publisher_pubkey: "ed25519:<short-form>"
        severity_auto_apply_threshold: HIGH
        nickname: "iam-jit-official"
```

Per `[[independence-as-security-property]]` the bundle is operator-pinned and locally evaluated. No phone-home, no central server.

## Compliance-tag coverage

Per #441 Sysdig research, every entry MUST carry a non-empty `compliance_tags` list. The bootstrap bundle's tags break down as:

- NIST 800-53: AC-6 (Least Privilege), AC-3 (Access Enforcement), AC-2 (Account Management), AU-2 (Auditable Events), AU-12 (Audit Generation), SC-7 (Boundary Protection), IA-5 (Authenticator Management), CM-7 (Least Functionality)
- SOC 2: CC6.1 (Access Controls), CC6.2 (User Auth), CC6.3 (Authorization Management), CC6.7 (Restricted Information), CC7.2 (Anomaly Detection), CC7.3 (Incident Response)
- HIPAA: §164.312(a)(1), §164.312(b), §164.308(a)(4)
- DORA: Art. 5 (ICT risk management), Art. 17 (Incident response)
- MITRE ATT&CK: T1078 (Valid Accounts), T1098 (Account Manipulation), T1136 (Create Account), T1486 (Data Encrypted for Impact), T1530 (Data from Cloud Storage), T1538 (Cloud Service Dashboard), T1565 (Data Manipulation), T1611 (Escape to Host), T1098.001 (Additional Cloud Credentials)

## How rules were sourced

Per `[[ambient-autonomous-protection]]` §A54 the initial bundle draws from three buckets:

1. **Wave 3 real-world incidents** (`tests/dogfood/role-effectiveness-grades.md`) — incidents the dogfood corpus surfaced where a dynamic-deny would have caught the harmful action.
2. **Known CVEs** in MCP servers, agent frameworks, and recently-disclosed agent vulnerabilities.
3. **29 structural gaps** from #406 (the umbrella tracking corpus gaps) — gaps a `profile_safety_floor_extension` would close (routed via the §A25 pending-approval queue per `[[creates-never-mutates]]`).

## How to extend

1. Author a rule file (YAML or JSON) following the `FeedEntry` shape in `src/iam_jit/threat_feed/models.py`.
2. Run `iam-jit-feed-publish sign <rule.yaml> --publisher iam-jit-official --out signed.json`.
3. Re-bundle with `iam-jit-feed-publish bundle <signed1>.json <signed2>.json ... --feed-id iam-jit-official-v1 --publisher iam-jit-official --out feeds/official-v1.json`.
4. Verify with `iam-jit-feed-publish verify feeds/official-v1.json --pubkey <pubkey>`.

## Per `[[push-policy-public-repo]]`

The publisher's **private key** MUST live OUTSIDE this repo (default location: `~/.iam-jit/threat_feed/publisher.ed25519.pem`, 0600). The `.gitignore` at the repo root ensures it never lands here even by accident.

## Per `[[scorer-is-ground-truth]]`

Feed entries are ADVISORY — they install denies / pending entries / informational alerts. They DO NOT modify the deterministic scorer or its calibration corpus.
