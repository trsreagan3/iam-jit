# community-profiles

Bundled environment profiles that used to ship as ibounce (formerly
iam-jit-bouncer) built-ins (`dev-only`, `staging-work`,
`incident-response`). Moved here so the built-in defaults stay
to the cross-product general-purpose pair (`full-user` +
`readonly`) and the more opinionated profiles ship as
installable starting points.

Future home: <https://github.com/trsreagan3/bounce-profiles>
(the cross-product community-profile bundle). Until that repo
lands, these YAML files are usable directly via:

```bash
# Local file path is fine — `profile install --from` accepts
# https:// URLs in v1.0; the file:// path here is illustrative
# of the YAML shape engineers can curate + host themselves.
ibounce profile install --from https://example.com/profiles/staging-work.yaml
```

## What's included

| File | Replaces former built-in | Behavior |
|---|---|---|
| `dev-only.yaml` | `dev-only` | Block anything not in dev/sandbox account aliases |
| `staging-work.yaml` | `staging-work` | Block ARNs / names matching `prod`, `production`, `live`, `customer`, `uat` |
| `incident-response.yaml` | `incident-response` | Read everything, write nothing — strict during live ops |

## Why these are no longer built-ins

The general-purpose pair (`full-user` passthrough + `readonly`
write-block) covers the cross-product (ibounce + kbounce + ...)
default story. The more opinionated profiles here are useful but
not universal:

- `dev-only` assumes account-alias hygiene that not every shop has
- `staging-work` bakes in specific keyword choices (`prod`, `uat`,
  `customer`) that vary by team
- `incident-response` overlaps `readonly` and exists more as a
  "named context" than a distinct rule shape

Shipping them as installable starting points keeps the defaults
small + lets teams fork / adapt before adopting.
