# Research Pattern Corpus — Coverage Report

Systematic enumeration of every numbered pattern in
`docs/research/IAM-BYPASS-RESEARCH.md` into one YAML test fixture per
pattern. Generated 2026-05-13.

Source document: 197 numbered patterns across 13 sections.
Total YAML fixtures written: **217** (some sections — particularly §2
Pacu modules and §7 Access Analyzer validation checks — contain multiple
sub-patterns under one numbered heading, each enumerated as its own
fixture).

All 217 YAMLs parse successfully under PyYAML's `safe_load` and contain
the required top-level keys: `name`, `policy`, `request`, `expected`.

## Patterns per section

| Section | Topic                                                    | Numbered patterns in doc | YAMLs written |
|---------|----------------------------------------------------------|--------------------------|---------------|
| §1      | Known privilege-escalation paths                         | 60                       | 60            |
| §2      | Pacu framework modules                                   | 7 subsections (~26 named modules) | 27   |
| §3      | CloudGoat scenarios                                      | 17                       | 17            |
| §4      | Resource-based policy abuse                              | 15                       | 15            |
| §5      | Real-world incident root causes                          | 8                        | 8             |
| §6      | CloudSplaining high-risk categories                      | 6                        | 6             |
| §7      | AWS IAM Access Analyzer finding taxonomy                 | 5 categories + 6 validation checks | 10  |
| §8      | MITRE ATT&CK cloud (IaaS) — IAM-relevant techniques      | 9 tactics                | 9             |
| §9      | Newer-service attack surface (2023-2026)                 | 14                       | 14            |
| §10     | JSON / parser / grammar bypass techniques                | 15                       | 15            |
| §11     | Condition-key bypass techniques                          | 17                       | 17            |
| §12     | NotAction / NotResource / NotPrincipal anti-patterns     | 5                        | 5             |
| §13     | Service-aliasing & action-naming edge cases              | 14                       | 14            |
| **Total**|                                                          | **197**                  | **217**       |

## Encoding philosophy

1. **One YAML per numbered pattern.** Multi-module sections (§2) and
   multi-check sections (§7.5) get one YAML per named sub-item to keep
   1:1 grep-coverage mapping.
2. **Faithful encoding of the literal attack.** Resource-based policy
   patterns (§4, §11.16, §10.15) keep `Principal` and `NotPrincipal`
   intact rather than collapsing to identity-policy form. Condition-key
   patterns (§11) keep the exact `Condition` shape from the research
   doc.
3. **`score_min` reflects the documented severity, not what the scorer
   currently returns.** Privilege-escalation primitives → 7-8; "direct
   path to admin" / org-wide / fleet-wide RCE → 9; wildcard `*:*`
   admin → 10; data-only exfil at narrow scope → 5-6; recon-only →
   3-4; condition-misuse and parser quirks scored on the *effective*
   permission they grant.
4. **Abstract patterns** (e.g., "use STS to assume cross-account
   roles", §1.40 "weak audience/issuer", §1.57 eventual-consistency,
   §1.58 ECS undocumented protocol, §3.5 vulnerable_lambda business
   logic, §3.12 rce_web_app, §4.14 Lambda function URL, §4.15 hidden
   PassRole) are encoded as the simplest concrete IAM-policy form a
   scorer could see, with a `# NB: abstract pattern, encoded the
   simplest concrete form` note in the description.

## Skipped patterns

None. Every numbered pattern in §1-§13 has at least one corresponding
YAML fixture. Patterns that were too abstract to encode losslessly were
encoded as their simplest concrete IAM-policy form and tagged with
`# NB:` notes in the description (see list above).

The "Sources & Citations" appendix at the end of the research document
(lines 889+) is bibliographic and contains no patterns — not enumerated.

## File naming convention

`research-<section>-<subsection>-<short-slug>.yaml`

Examples:
- `research-01-1-createpolicyversion-default-flag.yaml` → §1.1
- `research-02-2-pacu-lambda-backdoor-new-users.yaml` → §2.2, Pacu module `lambda__backdoor_new_users`
- `research-07-5-aa-pass-role-with-star-in-resource.yaml` → §7.5, validation check `PASS_ROLE_WITH_STAR_IN_RESOURCE`
- `research-11-3-stringlike-sub-github.yaml` → §11.3

## How to use this corpus

Run each fixture against the deterministic scorer. For each YAML:
- If `score >= expected.score_min`, the pattern is **covered**.
- If `score < expected.score_min`, the pattern is **missed**. Note the
  gap — these are the patterns the scorer's signatures don't recognize.

Aggregated by section, this gives a section-level coverage percentage
that maps directly back to the research compendium's structure, so
gaps can be triaged by category (e.g., "we cover 55/60 of §1 privesc
paths but only 8/17 of §11 condition-key bypasses").
