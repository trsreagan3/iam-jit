# MITM mode (`gbounce run --mode mitm`)

**#315 / §A13.** Default-off. Opt-in.

MITM mode terminates the TLS tunnel using a CA-signed leaf cert per
host, decrypts the HTTPS payload, audits + redacts it, and
re-encrypts to the real upstream. Without MITM, gbounce only sees
`CONNECT host:port` — the inner URL path, method, request body, and
response body stay encrypted (`docs/AUDIT.md` calls this out).

This document covers the honest trade-offs. Read it before you flip
the switch.

---

## When MITM is the right choice

- Your compliance posture (PCI / SOC 2 / HIPAA / FedRAMP) requires
  full body-level audit of outbound API calls.
- A security review needs to answer "did this agent ever send PII
  outside the org?" — answerable only with URL + body visibility.
- You're investigating a specific incident and need to inspect the
  exact request bodies an AI agent sent to OpenAI / Anthropic /
  vendor X.

## When MITM is the wrong choice

- Cert-pinning SDKs (most modern AWS SDKs, banking SDKs, many mobile
  SDKs) will refuse to talk through MITM. The TLS handshake fails;
  gbounce returns a 502 with a clear error message. For these
  clients, run gbounce in `--mode discovery --allow-connect` and
  accept the host:port-only granularity.
- Dev/local workflows where the operator just wants to know "what's
  this agent calling?" — `--mode discovery` is faster to deploy
  (no CA install step) and the host:port answer is usually enough.
- Deployments where you can't add the CA to the OS trust store
  (locked-down corporate laptops, ephemeral containers).

Per `[[ibounce-honest-positioning]]`: we don't promote MITM as the
default. Honest positioning is "MITM is available when you need it;
default is the simpler, friction-free CONNECT-tunnel shape."

---

## How to install + use

```sh
# 1. Generate the local CA (writes ~/.iam-jit/gbounce/ca/{cert,key}.pem).
gbounce ca install

# 2. The install command prints the platform-specific OS-trust-store
#    command. Run it.

# 3. Start gbounce in MITM mode.
gbounce run --mode mitm --port 8080 --audit-log-path ~/.gbounce/audit.jsonl

# 4. Point your client at the proxy.
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export NO_PROXY=localhost,127.0.0.1

# 5. Run the agent / tool as usual.
```

To inspect the CA:

```sh
gbounce ca info
```

To rotate the CA (after long use, or if you suspect the key is
compromised):

```sh
gbounce ca rotate
# Re-add the new cert to your OS trust store + remove the old one.
```

To remove the CA (the install command's reverse):

```sh
gbounce ca uninstall
# Remove the cert from your OS trust store using the printed reminder.
```

---

## Body redaction policy

When MITM mode is active, gbounce runs every request body + every
header through the credential-shape redactor BEFORE the audit log
writes anything. This is **default-on** so a stray Authorization
header never lands in the JSONL.

**Headers redacted (case-insensitive):**

`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`,
`X-API-Key`, `X-Anthropic-API-Key`, `X-OpenAI-API-Key`,
`X-AWS-Access-Key-Id`, `X-AWS-Security-Token`,
`X-Amz-Security-Token`, `X-Vercel-Protection-Bypass`,
`X-GitHub-Token`, `X-Auth-Token`, `X-Access-Token`.

The value is replaced with `***REDACTED-CREDENTIAL***`. The KEY
remains in the audit row so an analyst can see which sensitive
headers WERE present (no value leak; only the existence is visible).

**JSON body fields redacted (case-insensitive name match):**

- Exact names: `password`, `passwd`, `secret`, `token`, `api_key`,
  `apikey`, `auth`, `authorization`, `bearer`, `access_token`,
  `refresh_token`, `id_token`, `client_secret`, `session_token`,
  `private_key`, `signing_key`.
- Suffix patterns: `*_token`, `*_secret`, `*_key`, `*_password`,
  `*_apikey`.

The walk handles nested JSON objects + arrays.

**Query string redacted:**

The same redactor scrubs `?secret=...`, `?api_key=...`, `?token=...`
shapes from the `unmapped.iam_jit.ext.url_query` field.

**Body snapshot opt-in:**

By default, gbounce records only the redaction MARK (the boolean
`unmapped.iam_jit.ext.request_body_redacted`) — NOT the full body.
If you want the redacted body bytes in the audit log too, pass
`--audit-log-include-bodies` at startup. Default OFF because even
the redacted body may contain user PII the operator hasn't
classified yet.

---

## Audit event extensions

MITM-mode audit events extend the standard OCSF v1.1.0 class 6003
shape with:

| Key                                                    | Type    | Meaning |
| ------------------------------------------------------ | ------- | ------- |
| `unmapped.iam_jit.ext.url_path`                        | string  | Full URL path (e.g. `/v1/chat/completions`) |
| `unmapped.iam_jit.ext.url_query`                       | string  | Redacted query string |
| `unmapped.iam_jit.ext.request_method`                  | string  | HTTP method (POST/PUT/GET/...) |
| `unmapped.iam_jit.ext.request_body_redacted`           | bool    | True if the body was redacted |
| `unmapped.iam_jit.ext.request_body_truncated`          | bool    | True if the body exceeded the 1 MiB snapshot cap |
| `unmapped.iam_jit.ext.request_body_snapshot`           | string  | Redacted body (only when `--audit-log-include-bodies` is set) |
| `unmapped.iam_jit.ext.response_status`                 | int     | HTTP status from the upstream |
| `unmapped.iam_jit.ext.mitm_upstream_handshake_failed`  | bool    | True when the upstream rejected the gbounce-side TLS handshake (cert-pinning shape) |
| `unmapped.iam_jit.ext.mitm_upstream_handshake_error`   | string  | Truncated error text from the failed handshake |

---

## Profile rules (path + method + query-param matching)

MITM mode lets the operator deny specific URL shapes (not just host
prefixes). Point `--profile-rules-file` at a JSON file:

```json
{
  "deny_rules": [
    {
      "host": "api.openai.com",
      "method": ["POST"],
      "path": "/v1/chat/completions",
      "reason": "AI chat completion denied per policy"
    },
    {
      "host": "*.amazonaws.com",
      "method": "DELETE",
      "path_prefix": "/buckets/",
      "reason": "S3 bucket deletes blocked"
    }
  ]
}
```

A match emits `verdict=DENY` with `status_id=4 (Denied)` and
`ext.deny_reason="<the rule's reason field>"`, then returns 403 to
the client.

Rules with `method`, `path*`, or `query_params` predicates are
SKIPPED in `--mode discovery` (the CONNECT-only shape lacks the
visibility to evaluate them); the operator gets a `gbounce doctor
caveats` reminder when they configure a MITM-required rule under
discovery mode.

---

## Performance impact

Per-call overhead (cold cache, ECDSA P-256): ~5-15% latency on top
of the upstream's own latency. On a hot cache (the per-host leaf is
cached LRU-bounded at 1024 entries) the overhead drops to <1 ms
per call. Memory: ~1 KiB per cached leaf cert.

The OCSF event builder writes a single audit row per request — the
same shape as the CONNECT-tunnel path, just with more `ext` keys.

---

## Security considerations

- **Private key permissions:** the CA private key is written with
  `0o600`. gbounce REFUSES to load a key that's group- or
  world-readable. If `chmod` ever wides the bits, MITM mode fails
  to start with a clear error.
- **Common Name:** the CA cert's CN is the literal string
  `iam-jit gbounce local CA` — no operator-identifying info.
- **No phone-home:** the CA is generated entirely on the operator's
  machine. There's no central signing service, no shared key per
  `[[self-host-zero-billing-dependency]]`.
- **CA lifetime:** 10 years by default. Operators can rotate
  early with `gbounce ca rotate`.
- **Leaf-cert lifetime:** 90 days (matches the Let's Encrypt
  industry baseline). In practice the LRU evicts long before that.

---

## Trade-offs summary

|                        | discovery (default) | mitm (#315)            |
| ---------------------- | ------------------- | ---------------------- |
| Setup friction         | none                | CA install + OS trust-store step |
| Cert-pinning SDKs work | yes                 | no (returns 502)       |
| URL path in audit log  | no (CONNECT only)   | yes                    |
| Request body audit     | no                  | redacted-by-default    |
| Latency overhead       | ~0%                 | ~5-15%                 |
| Compliance use         | partial             | full (with caveat)     |
| Privacy of operator    | maximum             | proxy sees decrypted body |

Per `[[ibounce-honest-positioning]]`: pick the mode that matches
your trade-off, not the one that maximizes visibility. Both are
first-class.
