# Databricks Asset Bundles — Reference Pack

A self-contained set of reference materials for **understanding, hardening, and
gating Databricks Asset Bundles (DABs) before deployment**. Built for
developers and platform engineers shipping bundles into a regulated
environment.

If you are starting from zero, read `DAB.md` first — it is the conceptual
introduction. Everything else here is the production-grade tooling that
implements what `DAB.md` describes.

## What's in this directory

| Path | Purpose |
|---|---|
| `DAB.md` | Developer reference: what a DAB is, the structure of `databricks.yml`, resources, variables, targets, permissions, secure-by-default settings, and CLI commands. |
| `pre-deploy-checks.md` | Catalog of 20 deterministic, pre-deployment security checks (P1–P20) with severity, risk, predicate, and enforcement layer. |
| `secure-bundle.example.yml` | Annotated `databricks.yml` template demonstrating every secure-by-default setting. Each control is tagged with the P-rule it satisfies. |
| `policy/dab.rego` | OPA / Conftest policy pack implementing P2–P16 against the resolved bundle JSON. |
| `policy/dab.catalog.yaml` | Per-rule catalog of `title`, `severity`, `why`, `fix`, and references — consumed by the reporter to produce rich findings. |
| `scripts/conftest_report.py` | Wraps `conftest`, joins findings with the catalog, emits Markdown / JUnit / JSON. Used as the pipeline gate. |
| `scripts/diff_bundle.py` | P19 — structural diff of resolved-bundle vs deployed-bundle JSON. |
| `scripts/check_audit_delivery.py` | P20 — confirms `system.access.audit` is fresh in the target workspace. |
| `fixtures/good.json` | Resolved-bundle JSON that satisfies every rule. |
| `fixtures/bad.json` | Resolved-bundle JSON that deliberately violates every implemented rule. |
| `fixtures/test_policy.sh` | Smoke test: zero denies on `good.json`; every P-rule fires on `bad.json`. |
| `gitlab-ci.example.yml` | End-to-end GitLab CI pipeline (validate → security → drift → deploy) wiring all of the above together. |

## The pipeline at a glance

```
   bundle:validate    →   policy:conftest    →   bundle:drift
   (P1 — schema)          (P2–P16 via              (P19)
                           Rego + catalog
                           + reporter)         workspace:audit-delivery
                                               (P20)

   deps:audit                                  deploy:dev
   (P17 P18)                                   deploy:prod (manual,
                                                            main-only)

   policy:source-grep
   (P12 source / P14)
```

## Try it locally

```bash
# 1. Validate the secure example bundle and run the policy pack against it.
databricks bundle validate -t prod -o json > bundle.resolved.json
python scripts/conftest_report.py \
    --policy policy/ \
    --catalog policy/dab.catalog.yaml \
    --bundle bundle.resolved.json \
    --markdown report.md \
    --fail-on high

# 2. Run the policy regression suite against the fixture pack.
fixtures/test_policy.sh
```

`fixtures/test_policy.sh` should print `PASS` on the good fixture and
`PASS: every expected rule fired against bad.json` on the bad fixture.

## Wiring into CI

The `gitlab-ci.example.yml` in this directory is a drop-in starting point.
Adjust:

1. The runner image and `before_script` to match your runner setup.
2. `id_tokens` audience to your GitLab instance (or replace OIDC with
   protected/masked CI variables holding service-principal credentials).
3. The `--fail-on` threshold (default `high`) to your risk posture.
4. The `environment:` keywords (`development`, `production`) to match your
   GitLab environments.

The reporter writes:
- `report.md` — human-readable; logged to job output and stored as artifact.
- `conftest-report.xml` — surfaced in the GitLab MR test widget via
  `reports:junit:`.
- `report.json` — machine-readable; archive for downstream tooling.

## Severity policy

| Severity | What blocks the pipeline |
|---|---|
| `--fail-on critical` | Critical only |
| `--fail-on high` (default) | Critical + High |
| `--fail-on medium` | Critical + High + Medium |
| `--fail-on low` | All findings |
| `--fail-on none` | Reporter never fails (advisory mode) |

Findings below the threshold are still rendered in `report.md` and
`conftest-report.xml`, but do not fail the job.

## Adding or modifying a rule

1. Add the deny rule to `policy/dab.rego`. Use the message format:
   `[<id>/<Severity>] <body> (resource: <path>)`.
2. Add a matching entry to `policy/dab.catalog.yaml` with `title`,
   `severity`, `why`, `fix`, `references`. The reporter fails CI if a
   finding fires for a rule_id with no catalog entry.
3. Update `pre-deploy-checks.md` with the new row.
4. Add a violation to `fixtures/bad.json` and verify the rule fires:
   `fixtures/test_policy.sh`.
5. If the rule applies to `secure-bundle.example.yml`, ensure the example
   already satisfies it (run the test against the good fixture).

## Files this directory does **not** include

- An actual deployable DAB. `secure-bundle.example.yml` is a *template*,
  not a working bundle. Real notebook/wheel paths, group names, SP IDs, and
  workspace hosts must be supplied by the user.
- Workspace-side runtime checks (SAT, smoke tests, SP entitlement
  validation). Those are post-deployment scans; this directory is the
  pre-deployment gate.
- Any organization-specific allowlists or denylists. The `broad_groups`
  set in `policy/dab.rego` is a starting point — extend it per org.
