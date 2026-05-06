# When a waiver is the right call

Companion to `pre-deploy-checks.md` and `policy/exceptions.yaml`. The rules in
`policy/dab.rego` encode a *prod* security posture; in practice every rule has
edge cases where the right answer is a time-bounded waiver rather than
weakening the rule globally.

This document catalogs the legitimate-exception scenarios we have seen, so
reviewers approving an `exceptions.yaml` entry can compare against a known
pattern instead of reasoning from scratch each time.

## How to read this catalog

Each rule lists:

- **Pattern** — the recurring shape of the legitimate exception.
- **Risk accepted** — what the rule was protecting against, and why it is
  tolerable in this specific shape.
- **Waiver shape** — the `resource:` glob and `expires:` cadence that fit.

A waiver request that does not match one of these patterns is not
automatically wrong — but it should be discussed, and if it recurs, added
here.

The four pattern categories that cover most legitimate waivers:

1. **Bootstrap / break-glass** — the resource the rule depends on does not yet
   exist, or the SP path is broken and a human must deploy.
2. **Vendor constraint** — a third party requires an arrangement the rule
   forbids; we are stuck until they change or we migrate off.
3. **Legacy migration in flight** — the rule is correct; the asset predates
   it; remediation is scheduled.
4. **Internal contract** — an internal library or platform team owns a
   stricter contract that subsumes the rule.

---

## P2 — Prod target `mode: production`

**Pattern.** Bootstrap target deployed once to create the prod SP, catalog,
or workspace folder structure that subsequent prod deploys depend on.

**Risk accepted.** Schedules pause, deployment lock is disabled. Tolerable
because the bootstrap target has no schedules and is deployed by exactly one
person on a tracked change ticket.

**Waiver shape.** `resource: targets.bootstrap_prod`, `expires:` ≤ 14 days,
linked to the bootstrap change ticket.

---

## P3 — Prod `run_as` is a service principal

**Pattern A (bootstrap).** The target *creates* the service principal it
would otherwise run as. Until that deploy lands, `run_as` must be a human.

**Pattern B (break-glass).** SP credentials are revoked or rotated mid-
incident; on-call needs to deploy a hotfix as themselves to restore service.

**Risk accepted.** Production execution tied to a human lifecycle and audit
trail conflated with human activity. Tolerable for a single window; not
tolerable as a steady state.

**Waiver shape.** `expires:` ≤ 7 days. Break-glass waivers should be
post-hoc — opened during the incident, expired by the next sprint.

---

## P4 — Prod `workspace.root_path` not under `/Workspace/Users/`

**Pattern.** Short-lived prod-shadow target used to reproduce a prod issue
from a developer sandbox path. The path *is* a user folder, on purpose.

**Risk accepted.** Artifacts can be deleted when the user offboards.
Tolerable for the duration of the investigation.

**Waiver shape.** `resource: targets.prod_repro_*`, `expires:` ≤ 14 days,
ticket referencing the incident.

---

## P5 — Prod target pins `git.branch`

**Pattern.** Tag-based release pipeline where the source-of-truth is
`git.commit` resolved by CI, not a branch. The bundle file legitimately has
no branch pinned because the orchestrator passes the commit at deploy time.

**Risk accepted.** None additional, if the pipeline truly enforces commit
pinning. Verify the pipeline before approving.

**Waiver shape.** Wide `resource:` (the whole prod target), `expires:` ≤ 90
days. Renew alongside the release-pipeline review.

---

## P6 — `bundle.databricks_cli_version` is set

**Pattern.** Rare. Almost always the right answer is to set the version, not
waive. Only legitimate case: a bundle consumed exclusively by an internal
platform that pins the CLI version itself and intentionally elides the field
to surface drift.

**Waiver shape.** Document the platform that pins externally, link to its
version-pin policy. `expires:` ≤ 90 days.

---

## P7 — Identity not duplicated across top-level and resource permissions

**Pattern.** Migration. A team is moving permissions from per-resource into
top-level (or vice versa) and both forms coexist for a rollout window so
revert is one-line.

**Risk accepted.** Confusion if the two grants disagree. Tolerable if the
grants are identical and the migration is short.

**Waiver shape.** Narrow `resource:` glob covering only the resources mid-
migration. `expires:` ≤ 30 days.

---

## P8 — Broad groups (`users`, `account users`) without `CAN_MANAGE` / `IS_OWNER`

**Pattern.** Genuinely public internal artifact — a demo cluster or a shared
sandbox that the platform team intends everyone to be able to manage.

**Risk accepted.** Anyone in the workspace can modify or destroy the
resource. Tolerable only when the resource is non-production and easily
reproducible from the bundle itself.

**Waiver shape.** Specific resource path; never `resource: "*"`. `expires:`
≤ 90 days, with renewal contingent on confirming the artifact is still
non-production.

---

## P9 — Cluster `data_security_mode` is `USER_ISOLATION` or `SINGLE_USER`

**Pattern A (legacy DLT).** Older Delta Live Tables pipelines that pre-date
isolation-mode support. Migration plan exists; the runtime upgrade is
scheduled.

**Pattern B (GPU/ML runtime).** A specific ML runtime version the team
depends on did not support the isolation modes when the cluster was built;
upgrade requires retesting models.

**Risk accepted.** Cluster runs without per-user isolation. Tolerable when
the cluster runs only trusted, reviewed code and is not user-facing.

**Waiver shape.** `expires:` aligned to the migration milestone, not a fixed
window. Renew at most twice — beyond that, escalate.

---

## P10 — Init scripts only from `workspace` or `volumes`

**Pattern.** Vendor-supplied init script (security agent, monitoring agent,
proprietary driver) hosted on a vendor-controlled path the vendor refuses to
mirror. Common with endpoint security tooling.

**Risk accepted.** The init script's contents are outside our review chain.
Tolerable when the vendor is a reviewed dependency and we have a copy-to-
volume migration scheduled.

**Waiver shape.** `resource:` scoped to the specific cluster path; reason
must name the vendor and the migration ticket. `expires:` ≤ 90 days.

---

## P11 — Pinned library versions (no `~`, `>=`, ranges)

**Pattern A (internal lib).** An internal monorepo package with `>=2.0,<3.0`
because the publishing team treats SemVer as the contract and guarantees no
breaking changes within the major. The internal Artifactory enforces
immutability — published versions cannot be re-tagged.

**Pattern B (vendor wheel).** A vendor wheel published only as a floating
"latest" tag with no versioned alternative.

**Risk accepted.** Build is not bit-for-bit reproducible across deploys.
Tolerable for Pattern A because of the immutability guarantee; for Pattern B,
only until we vendor the wheel into a Volume.

**Waiver shape.** `resource:` scoped to the specific job/task/library;
reason must reference the immutability guarantee or vendoring plan.
`expires:` ≤ 90 days.

---

## P12 — No secret-shaped variable defaults

**Pattern.** Almost never legitimate. The one defensible case is a
*deliberate* test fixture default that is a known-revoked credential used by
a security training exercise. Do not waive real defaults.

**Waiver shape.** If you find yourself writing this waiver, escalate to
security review first. The waiver should reference the revocation evidence.

---

## P13 — Required `sync.exclude` entries

**Pattern.** Bundle in a repo where `.env`, `*.pem`, etc. are already
excluded at the `.gitignore` level *and* the team has a documented policy
that `sync.exclude` is redundant.

**Risk accepted.** Defense-in-depth lost; one mistake in `.gitignore`
exposes secrets. Tolerable only when a separate scanner enforces the
`.gitignore` policy.

**Waiver shape.** Reason must name the redundant control. `expires:` ≤ 90
days.

---

## P15 — Jobs / pipelines have `IS_OWNER` and `CAN_MANAGE`

**Pattern.** Bundle deployed by an SP whose ownership is assigned by
Databricks at deploy time and never re-declared in YAML. Defensible if the
deploying SP is itself version-controlled and stable.

**Risk accepted.** Ownership is implicit, not explicit. If the deploying SP
changes, ownership silently transfers. Tolerable when the SP is managed by
the same change process as the bundle.

**Waiver shape.** `resource:` scoped to specific resources; reason must name
the SP and where its lifecycle is managed. `expires:` ≤ 90 days.

---

## P16 — Model serving endpoints set `rate_limits` and `ai_gateway`

**Pattern A (internal-only endpoint).** Endpoint exposed only on a private
network behind an upstream gateway that already enforces rate limits and
auth.

**Pattern B (experimental endpoint).** Pre-launch endpoint not yet wired
through AI Gateway; traffic is bounded by being known-internal-only.

**Risk accepted.** No native rate limiting; abuse depends entirely on the
upstream control. Tolerable for Pattern A only when the upstream control is
documented and tested.

**Waiver shape.** Reason must name the upstream gateway or describe the
launch criteria. `expires:` ≤ 30 days for Pattern B; ≤ 90 days for Pattern A.

---

## What does *not* belong in a waiver

- "We disagree with the rule." — open a PR against `policy/dab.rego` or
  `pre-deploy-checks.md` instead.
- "The fix is complicated." — that's the point of the rule. File the ticket;
  the waiver is the *bridge*, not the destination.
- "It's only dev." — the policy pack already scopes prod-only rules with
  `is_prod`. If the rule is firing in dev, that is a rule bug, not a waiver
  case.
- Open-ended `resource: "*"` waivers. Always scope to the narrowest glob
  that covers the actual exception.

## Reviewer checklist

Before approving an `exceptions.yaml` entry:

- [ ] Does the pattern match one of the categories above? If not, document
      the new category in this file in the same PR.
- [ ] Is `resource:` the narrowest glob that covers the actual exception?
- [ ] Does `reason:` name the upstream constraint, not the symptom?
- [ ] Is `expires:` aligned to a real milestone (vendor release, migration
      ticket, incident close), not "90 days because that's the max"?
- [ ] Is `ticket:` a working link to a tracked piece of work?
- [ ] If this is a renewal, has the underlying work moved? Three renewals
      without progress is an escalation, not a fourth waiver.
