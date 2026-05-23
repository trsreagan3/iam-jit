# Hardening ibounce against prompt-injected agents

How to harden ibounce (and the rest of the Bounce suite) against a
prompt-injected agent that tries to disable the proxy before issuing
calls. This doc is for SecOps + platform engineers deploying ibounce
on engineer laptops or shared workstations.

---

## The honest framing

ibounce is a **user-process on a user-machine.** A prompt-injected
agent that has shell access on the same machine — through a tool
primitive like `bash`/`exec`/`python -c`, or simply by writing a
shim script the user then runs — can `pkill ibounce`,
`unset HTTPS_PROXY`, `unset AWS_ENDPOINT_URL`, or just call AWS
through a different endpoint URL. ibounce by itself cannot stop any
of those moves.

What ibounce CAN do is make every disable-attempt **detectable** and
make the bypass **costly** when composed with the rest of an
operator's defense-in-depth stack:

- Heartbeat events emitted to the audit pipeline so a gap is visible
  within seconds (per the bouncer Slice-2 alert rule
  `heartbeat_gap`).
- Tamper-detection on the audit chain (hash-chained rows; a gap or
  rewrite shows up at `iam-jit audit verify`).
- Admin-action audit events so attempts to mutate the rule set,
  install a malicious profile, or change modes are themselves audited.

The rest of this doc walks through the **six-layer defense** that, in
combination, actually prevents (or at minimum reliably detects) the
disable-bouncer attack. ibounce is **one layer.** The other five are
the customer's OS, network, sandbox, and MDM tooling — not things
ibounce ships.

---

## The 6-layer defense

### Layer 1 — Don't give the agent shell access

**Strongest layer.** If the agent has no shell primitive, it can't run
`pkill`, can't `unset` an env var in the parent process, and can't
write a bypass script. Everything the agent does has to go through
its declared tools.

**How to ship this:**

- **MCP-only agent configuration.** Tools the agent can call are
  exhaustively listed in the MCP server manifest. No
  `bash` / `exec` / `shell` / `run_command` tool exposed.
- **Claude Code default config.** As of the current release, Claude
  Code does not give the agent a shell primitive by default; the user
  must opt in explicitly with `--dangerously-skip-permissions` or by
  approving each Bash invocation. Keep that default.
- **Cursor agent mode** without the "Run terminal commands" permission
  ticked.

**Tools that do NOT satisfy this layer out of the box:**

- Most LangChain ReAct agents bootstrapped with the standard
  `shell_tool` / `terminal_tool` — these expose `subprocess.run` to
  the LLM by design.
- Several open-source agent loops that ship with a shell tool as their
  primary capability (the "shell is the universal tool" school of
  thought). Treat any agent loop whose flagship example wires a shell
  tool as **not Layer-1 safe** without modification.

**What this layer does NOT cover:** an agent that asks the human to
copy-paste a command into a terminal still wins — the prompt-injection
moves up a level into social engineering. Layers 2–6 cover the residual
risk.

### Layer 2 — Sandbox the agent

**Very strong.** Run the agent inside a Docker container, microVM,
Firecracker VM, or browser sandbox where the laptop's shell is not
reachable.

Key properties:

- **Env vars set immutably inside the sandbox.** The sandbox starts
  with `AWS_ENDPOINT_URL=http://host.docker.internal:8767` baked into
  the container's `ENV`. Even if the agent runs `unset
  AWS_ENDPOINT_URL` inside the sandbox, that only unsets it in the
  sandbox's shell; the AWS SDK in the agent's Python/Node process
  inherits the original env from container `ENV`.
- **Sandbox network namespace only routes egress through ibounce's
  outbound IP.** The sandbox is on its own Docker network whose
  iptables rules forward all `*.amazonaws.com:443` traffic to the
  host's ibounce port.
- **Agent can `pkill` inside the sandbox.** ibounce is on the HOST,
  outside the sandbox; the agent's `pkill ibounce` finds no matching
  PID inside its container.

**Concrete: Docker run with a constrained network.**

```sh
# On the host, create a dedicated Docker network whose only outbound
# rule is "AWS endpoints go through ibounce".
docker network create \
  --driver bridge \
  --subnet 172.30.0.0/24 \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  bouncer-net

# iptables rule on the host: this network's AWS traffic goes to
# 127.0.0.1:8767 (where ibounce is listening).
sudo iptables -t nat -A PREROUTING \
  -s 172.30.0.0/24 \
  -p tcp --dport 443 \
  -m string --algo bm --string ".amazonaws.com" \
  -j DNAT --to-destination 127.0.0.1:8767

# Run the agent inside this network with the endpoint baked in.
docker run --rm -it \
  --network bouncer-net \
  -e AWS_ENDPOINT_URL=http://host.docker.internal:8767 \
  -e AWS_REGION=us-east-1 \
  my-agent:latest
```

(string-match on the DNAT is illustrative — production deployments
use a DNS-aware egress proxy or a Squid/Envoy egress controller
upstream of the iptables hop. The principle is what matters: the
sandbox's network namespace has **no path to AWS** except through
ibounce.)

### Layer 3 — Network egress allowlist

**Strong.** Block the dev-machine's direct egress to AWS endpoints,
kube-apiserver, DB hosts, etc., except via ibounce's outbound IP.
This catches the case where the agent (or a human under social
engineering) tries to call AWS directly with a fresh boto3 client
that doesn't use `AWS_ENDPOINT_URL`.

**macOS — pf (packet filter):**

`/etc/pf.anchors/com.bouncer`:

```
# Allow loopback (ibounce listens on 127.0.0.1:8767)
pass quick on lo0

# Allow ibounce's own process (uid 501 is the operator account) to
# reach AWS upstreams
pass out proto tcp from any to any port 443 user 501 keep state

# Block every OTHER user process from reaching *.amazonaws.com
# (resolution via host file or table — populate from `dig +short`
# of common AWS endpoint prefixes)
table <aws_endpoints> persist file "/etc/bouncer/aws_endpoints.txt"
block out quick proto tcp from any to <aws_endpoints> port 443
```

Load with:

```sh
sudo pfctl -a com.bouncer -f /etc/pf.anchors/com.bouncer
sudo pfctl -e
```

**Linux — nftables:**

```
table inet bouncer {
  chain output {
    type filter hook output priority 0; policy accept;

    # Allow loopback
    oifname "lo" accept

    # Allow ibounce's process (matched by cgroup or uid) to reach AWS
    meta skuid 1000 accept

    # Block everyone else from AWS endpoints
    ip daddr @aws_endpoints tcp dport 443 reject with tcp reset
  }

  set aws_endpoints {
    type ipv4_addr
    flags interval
    # Populate from /etc/bouncer/aws_endpoints.txt or dynamic DNS
  }
}
```

**Corporate / VPN exit:** push the same allowlist as a VPN egress ACL.
Every laptop's AWS traffic must exit through a corporate proxy whose
upstream is ibounce.

**Cloud dev workspaces (Codespaces, Gitpod, etc.):** VPC route tables
+ a NAT instance running ibounce. Same shape.

### Layer 4 — MDM-enforced signed binary + managed env vars

**Strong for managed fleets.** Use Jamf / Kandji / Intune / equivalent
to lock down:

- **Which processes can run.** Only the signed `ibounce` binary, with
  a known SHA-256, can listen on the loopback port. Modified binaries
  refuse to launch.
- **Managed env vars that the user (or agent) cannot modify.**
  `AWS_ENDPOINT_URL=http://127.0.0.1:8767` is shipped as a managed
  preference and re-applied on every login. `unset AWS_ENDPOINT_URL`
  in a shell unsets it for that shell session, but the next-launched
  process inherits the managed value again.
- **Prevent `pkill` of managed services.** macOS Endpoint Security
  framework profiles can block signal-delivery to processes in a
  managed list.

**macOS Configuration Profile** (illustrative `.mobileconfig` payload
keys — full XML omitted for brevity; consult Apple's `profiles`
reference):

```
PayloadType: com.apple.systempolicy.kernelextensionpolicy
  AllowedTeamIdentifiers: [ <ibounce-signing-team-id> ]

PayloadType: com.apple.ManagedClient.preferences
  ManagedPreferences:
    AWS_ENDPOINT_URL: "http://127.0.0.1:8767"
    HTTPS_PROXY: "http://127.0.0.1:8767"

PayloadType: com.apple.TCC.configuration-profile-policy
  Services.SystemPolicyAllFiles:
    - Identifier: <ibounce-bundle-id>
      Authorization: Allow
```

**Linux — systemd hardening:**

```
[Service]
ExecStart=/usr/local/bin/ibounce run --profile safe-default
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
```

Combined with **AppArmor** (`/etc/apparmor.d/usr.local.bin.ibounce`):

```
/usr/local/bin/ibounce {
  capability net_bind_service,
  network inet stream,
  /home/*/.ibounce/state.db rwk,
  /home/*/.ibounce/state.db-journal rwk,
  /etc/bouncer/** r,
  deny /home/*/.ssh/** rwx,
  deny /home/*/.aws/credentials rwx,
}
```

**Windows — Group Policy + WDAC (Windows Defender Application
Control):** ship a WDAC policy whose `Allowed Publishers` list
includes only the ibounce signing certificate; set the
`HTTPS_PROXY` / `AWS_ENDPOINT_URL` environment variables via a Group
Policy Preference (Computer Configuration → Preferences →
Environment) so they reapply on every user-login refresh.

### Layer 5 — launchd / systemd KeepAlive watchdog

**Medium.** If the agent does manage to kill ibounce, the OS-level
process supervisor restarts it within seconds. Combined with Layer 6,
the security team sees both the kill event AND the restart event in
the audit stream — a strong signal for incident response.

**macOS launchd plist** — `/Library/LaunchDaemons/com.bouncer.ibounce.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.bouncer.ibounce</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/ibounce</string>
    <string>run</string>
    <string>--profile</string>
    <string>safe-default</string>
  </array>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>StandardOutPath</key>
  <string>/var/log/ibounce.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/ibounce.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/operator</string>
  </dict>
</dict>
</plist>
```

Install:

```sh
sudo cp com.bouncer.ibounce.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.bouncer.ibounce.plist
```

**Linux systemd unit** — `/etc/systemd/system/ibounce.service`:

```ini
[Unit]
Description=ibounce — local AWS-API gating proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ibounce run --profile safe-default
Restart=always
RestartSec=5
User=ibounce
Group=ibounce

# Hardening (see Layer 4)
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Install:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now ibounce.service
```

Each restart emits an ibounce startup audit event (one row per process
start; see `iam-jit audit tail --event startup`). Pair with Layer 6 so
the SIEM sees the kill/restart cycle.

### Layer 6 — Heartbeat + admin-action audit (what ibounce ships)

**Detection, not prevention.** This is the layer ibounce itself
provides; the other five layers are customer-owned infrastructure.

What ibounce emits today (v1.0):

- **HEARTBEAT** events every N seconds (default 30s) to the audit
  pipeline. Configurable via `IAM_JIT_BOUNCER_HEARTBEAT_INTERVAL`.
- **Slice-2 alert rule `heartbeat_gap`** fires when the SIEM-side
  view of the audit stream sees a gap larger than 2× the configured
  interval. Routes to whichever sink the operator configures
  (Slack webhook, generic webhook, OCSF/Splunk HEC).
- **Admin-action OCSF events** (queued via Issue #278) for
  rule-mutation, profile-install, mode-change, and pause-override
  attempts. These are emitted even when the attempt fails the
  authorization check, so an agent trying to relax the rule set is
  visible.

**Cross-correlation signal:** the audit pipeline can correlate
ibounce events against CloudTrail. Any AWS API call attributed to a
JIT-issued role for which there is NO matching ibounce audit row in
the same window = the proxy was bypassed. That correlation is the
canonical bypass detector.

**What the operator must do:**

1. Route ibounce audit to a SIEM (Splunk, Sumo, Datadog,
   Elasticsearch, etc.) — see [docs/QUERYING-AUDIT-LOGS.md](QUERYING-AUDIT-LOGS.md).
2. Enable the `heartbeat_gap` alert rule on that SIEM.
3. Subscribe the security team to the alert channel.

---

## Worked example: combining layers 1 + 3 + 5 + 6

A common deployment for an engineer laptop running Claude Code as the
agent:

- **Layer 1 (partial):** Claude Code in its default config, with
  `Bash` tool approval prompts left on (don't `--dangerously-skip-permissions`).
- **Layer 3:** macOS pf rules blocking direct `*.amazonaws.com:443`
  egress except for the ibounce process.
- **Layer 5:** launchd plist with `KeepAlive: true` so any
  `pkill ibounce` triggers an automatic restart within ~5 seconds
  (controlled by `ThrottleInterval`).
- **Layer 6:** ibounce HEARTBEAT events routed to Splunk via the
  audit-export pipeline + `heartbeat_gap` alert wired to the SecOps
  Slack channel.

**Combined behavior on a prompt-injection disable attempt:**

1. Injected prompt arrives via a poisoned tool response.
2. Agent attempts `pkill ibounce` — Claude Code surfaces the Bash
   approval prompt; the user (hopefully) denies.
3. If the user approves (or the deployment skipped Layer 1), ibounce
   dies → launchd restarts it within ~5s.
4. During the gap, the agent attempts a direct `boto3.client('s3')`
   call without `AWS_ENDPOINT_URL` set — pf blocks the connection at
   the TCP layer.
5. `heartbeat_gap` alert fires in Splunk; security team is paged.
6. Audit chain shows the kill event, the restart event, and the
   blocked direct-egress attempt — full forensic picture.

The bypass attempt is **detected within seconds**, **can't reach AWS
APIs directly**, and **ibounce keeps coming back**. No single layer
provides this on its own; the combination does.

---

## What ibounce CAN'T do

Explicit, honest list of what is **not** in ibounce's lane:

- **We don't prevent the disable itself.** A user-process can be killed
  by the user. That's how operating systems work. ibounce can only
  make the kill visible.
- **We don't ship MDM.** Jamf, Kandji, Intune, and equivalent are the
  customer's IT-management tooling. ibounce can be packaged for
  managed deployment, but the policy enforcement is the MDM's.
- **We don't ship the sandbox.** Docker, Firecracker, gVisor, browser
  sandboxes — pick the one that fits your agent's runtime. ibounce
  runs on the host; the sandbox is the customer's container layer.
- **We don't ship the firewall rules.** pf, nftables, VPN ACLs, VPC
  route tables — these are network-team responsibilities. ibounce
  provides the loopback target; the routing decision is upstream.
- **We don't enforce file-system policy.** Whether the agent can read
  `~/.aws/credentials` directly (and then call AWS using those creds
  without going through the proxy) is an AppArmor / SELinux / macOS
  TCC concern. See Layer 4.

**What ibounce ships:** the audit signal, the heartbeat, the alert
rule, the admin-action event stream, and this doc explaining how to
compose all six layers.

---

## FAQ

**Q: What stops a prompt-injected agent from running `pkill ibounce`
as its first command?**

**A:** Nothing in ibounce itself. The full answer is "Layer 1
prevents the agent from having a shell, Layer 5 restarts ibounce if
it does get killed, Layer 6 alerts the SecOps team within seconds,
and Layer 3 blocks the direct-egress attempt during the restart
window." That combination is what stops the attack — not any single
layer.

This is the same shape as host-IDS or endpoint detection: a
prompt-injected agent can `rm -rf` a CrowdStrike agent's files too,
which is why CrowdStrike pairs detection with kernel-level
tamper-protection and a network-level egress block. ibounce uses the
same playbook, but the kernel-level tamper-protection is the
customer's MDM (Layer 4), not anything ibounce can ship as a
user-space binary.

**Q: Can ibounce be run as root to prevent the user (or agent) from
killing it?**

**A:** Running ibounce as root makes `pkill` require root, which
helps against an agent running as the unprivileged user — but it
introduces its own risks (a vulnerability in ibounce becomes a root
vulnerability) and it doesn't help against an agent that has sudo
(many dev-laptop setups give the engineer NOPASSWD sudo).

The Bounce-suite recommendation is: run ibounce as the engineer's
own user account, NOT as root. Use **Layer 5 (launchd / systemd
KeepAlive)** for the "always-restart-on-kill" property. Use
**Layer 4 (MDM-managed process protection)** for the "user can't
kill it at all" property — that one belongs to the OS, not ibounce.

If you have a hard requirement to run ibounce as a privileged
daemon, you can — `Restart=always` + `User=root` in the systemd
unit works — but the hardening team should review the resulting
threat model carefully. The default-recommended deployment is
user-process with launchd/systemd supervision.

---

## Related docs

- [`SECURITY-POSTURE.md`](SECURITY-POSTURE.md) — technical reference
  for what the binary actually does (network behavior, telemetry,
  audit).
- [`IBOUNCE.md`](IBOUNCE.md) — full ibounce v1.0 feature surface.
- [`QUERYING-AUDIT-LOGS.md`](QUERYING-AUDIT-LOGS.md) — wiring audit
  output to a SIEM (the Layer 6 prerequisite).
- [`PERMISSIONS-MODEL.md`](PERMISSIONS-MODEL.md) — the JIT-role
  permissions side of the defense-in-depth story.
- [`ANOMALY-DETECTION.md`](ANOMALY-DETECTION.md) — Phase H per-agent
  behavioral baseline + z-score scoring (Layer 5 advisory /
  enforcement option).
