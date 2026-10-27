# ADR 016 — Guardrails that learn from incidents

Status: accepted · MR !54 · Builds on ADR 004 (risk gate), ADR 005 (self-healing) and ADR 007
(dispatch from CI)

## Context

The risk gate (ADR 004) classifies a change as high-risk from a fixed list of paths: auth, keys,
crypto, the HTTP/MCP surface, chart security objects and CI. That list is what we _guessed_ was
dangerous. Incidents tell us what _was_ dangerous: incident #36 was caused by a change to
`apps/gateway/src/core/limits.ts` and `call-tool.ts`, two files the static list did not cover, so
the change went out as low-risk with no human look before release. After the loop healed it,
nothing stopped the same files from breaking production the same way again.

## Decision

- **Learn after the heal is released.** On the default branch, after `canary` released a commit
  (PROMOTE or PROMOTE_PENDING_APPROVAL), `duo:guardrail-learn` runs `scripts/duo/guardrail.py`. For
  each merged `autoheal` MR in the commit it reads the MR's changed files: the code the fix had to
  touch is, by evidence, where a change broke a release.
- **Propose, never apply.** It opens one MR per incident (`guardrail/incident-<iid>`) that adds
  those files to the rules. It never pushes to `main`. The MR edits `.gitlab/ci/`, so the risk gate
  classifies it high-risk and `release:human-approval` waits for a person; a person also merges
  it. Automation only _adds_ guardrails, never removes one.
- **Narrow by construction.** Exact paths only (no globs), at most 3 per incident, nothing under
  `.gitlab/`, `charts/` or `scripts/canary/` (already guarded or out of scope), unsafe names
  rejected, paths already covered skipped. Each rule's reason names its incident.
- **One rule set, three statements, kept identical.** The MR appends the same paths, in the same
  order, to `RULES` in `scripts/canary/risk.py` (what CI enforces), both `rules:changes` lists of
  `release:human-approval`, and the risk-gate prompt. `flows.test.sh` fails if they drift.
- **Back-fill.** The manual job `duo:guardrail-backfill` on main (`needs: []`) learns from the
  newest resolved incident that has no guardrail MR yet, one per click (used for #36). It is a job,
  not a pipeline variable, because pipeline variables are maintainer-only in this project.
- **Idempotent.** If the incident's guardrail MR exists (any state), nothing happens. A note on the
  incident links the MR.

## Alternatives

- **Let a Duo flow decide what to guard.** More flexible, but an LLM editing CI rules is exactly
  the kind of change we want deterministic and reviewable. The postmortem flow already explains
  _why_; the rule itself comes from the fix's diff.
- **Apply directly to `main`.** Faster, but self-modifying CI with no human check is a supply-chain
  risk. Rejected.
- **Learn from the bad commit's files.** Wider and noisier (a bad commit can touch tests, docs,
  unrelated files). The fix's diff is the smallest evidence of where the fault was.
- **Expire learned rules.** Not done: removing a guardrail should be a human decision.

## Consequences

- The gate gets stricter only where production proved it should. The cost is more manual
  approvals on files that broke once.
- The Duo risk-gate prompt in the GitLab UI must be re-pasted after a guardrail MR merges (flows
  are registered by hand, ADR 007). CI enforces the rules either way.
- Same token as the other dispatch jobs (`DUO_DISPATCH_TOKEN`, Developer, `api`): it can push a
  non-protected branch and open an MR, not merge to `main`.
