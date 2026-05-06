# Pre-Deployment Security Checks for Databricks Asset Bundles

Deterministic, boolean checks that run in CI against the **source bundle** before `databricks bundle deploy`. Each check is a predicate over either:

- The resolved bundle JSON: `databricks bundle validate -t <target> -o json`
- The bundle source tree (YAML, requirements, lockfiles)
- A workspace API call against the deploy target

Heuristic checks (entropy-based secret scanning, behavioral / anomaly signals) are intentionally excluded.

## Severity scale

| Level | Meaning | CI behavior |
|---|---|---|
| Critical | Direct path to credential exposure, RCE, or authorization bypass; or eliminates the ability to detect/respond. | Block deploy. No waiver. |
| High | Bypasses a control, exposes data to a wide population, or breaks the identity / governance model. | Block deploy unless waived with sunset date. |
| Medium | Operational or reproducibility risk; recoverable; doesn't directly grant access. | Warn; require justification. |
| Low | Hygiene only. | Warn; track in backlog. |

## Check catalog

| # | Check | Severity | Risk if violation ships | Predicate | Source |
|---|---|---|---|---|---|
| P1 | Bundle schema + substitution resolution | Medium | Deploy fails mid-flight leaving partial state, or a `${...}` resolves unexpectedly and creates resources in the wrong workspace / path / under the wrong identity. | `databricks bundle validate -o json` exits 0 | CLI |
| P2 | Prod target mode is `production` | High | Schedules silently paused; pipelines skip prod guardrails; deployment lock disabled. SLA + governance bypass with no visible error. | When `bundle.target` matches `^prod`, `bundle.mode == "production"` | Resolved JSON |
| P3 | Prod `run_as` is a service principal | High | Prod jobs run as a human identity. Offboarding breaks prod; user's full access is the blast radius for any compromise. | When `bundle.target` matches `^prod`: `run_as.service_principal_name` set; `run_as.user_name` absent | Resolved JSON |
| P4 | Prod paths not user-bound | High | Prod artifacts under `/Workspace/Users/<email>/...`. Offboarding deletes prod state; collisions across deployers. | When `bundle.target` matches `^prod`, `workspace.root_path` does not match `^/Workspace/Users/` | Resolved JSON |
| P5 | Prod git-branch enforcement set | High | Any branch can be deployed straight to prod. Code-review gate becomes voluntary. | When `bundle.target` matches `^prod`, `bundle.git.branch` is set | Resolved JSON |
| P6 | CLI version pinned | Low | Reproducibility loss; deploys behave differently between contributors / CI. | `bundle.databricks_cli_version` is set (>= 0.218.0 is the practical floor; verifying the constraint string is left to operators) | Resolved JSON |
| P7 | No permissions overlap | High | Docs forbid the overlap; observed behavior is deploy failure or silent shadowing where the broader permission wins. | No identity appears in both top-level and resource-level `permissions` | Resolved JSON |
| P8 | No `CAN_MANAGE` to broad groups | Critical | Every account user can edit, run, or delete the resource. Maximum insider blast radius. | No `permissions` entry at top-level or resource-level has `group_name` (case-insensitive) in the configured broad-groups set with `level in {CAN_MANAGE, IS_OWNER}`. Default broad set: `{users, account users}` — extend per-org. (Target-level permissions are merged into top-level by `bundle validate`.) | Resolved JSON |
| P9 | Cluster security mode is UC-compatible | High | Legacy / NONE mode bypasses Unity Catalog enforcement; row/column-level security and credential passthrough do not apply. | All `clusters[*]` and `job_clusters[*]` set `data_security_mode in {USER_ISOLATION, SINGLE_USER}` | Resolved JSON |
| P10 | Init scripts only from workspace or volumes | Critical | DBFS, S3, ABFSS, and other unsanctioned sources can be modified by anyone with write access to that backing store, leading to RCE as root on cluster startup. | Every `init_scripts[*]` entry uses exactly one of `{workspace, volumes}` as its source key. All other source keys (`dbfs`, `s3`, `abfss`, `gcs`, `file`) are denied. | Resolved JSON |
| P11 | Library versions exactly pinned | High | Floating versions allow a malicious upstream release to land in prod silently. SolarWinds-class. | Every `pypi.package` contains `==` and no wildcard/range characters (`*<>~!,`). Every `maven.coordinates` has at least three `:`-separated parts and no Maven range syntax (`[]()` or `,`). | Resolved JSON |
| P12 | No credentials in variable defaults | Critical | Long-lived credential committed to git history. Cannot be revoked by deletion. | No `variables[*].default` matches `dapi[a-f0-9]{32}`, `AKIA[0-9A-Z]{16}`, or workspace URL containing `token=` | Source YAML + resolved JSON |
| P13 | `sync.exclude` covers credential surfaces | High | `.env`, private keys, `variable-overrides.json` uploaded to workspace; visible to every workspace user. | `sync.exclude` contains `.env`, `*.pem`, `*.key`, `*.pfx`, `variable-overrides.json` | Resolved JSON |
| P14 | No raw infrastructure IDs | Medium | Hardcoded cluster / warehouse / job IDs reference objects that exist in only one environment. Cross-env leakage. | No literal cluster/warehouse/job/pipeline ID in resource fields; values use `${var...}`, `${resources...}`, or `lookup:` | **Source YAML** (resolved JSON cannot distinguish) |
| P15 | Prod resources have explicit ownership | Medium | Creator offboards, resources orphan. No one can modify or destroy. Effective DoS on operations. | For every `jobs[*]` and `pipelines[*]` in the prod-resolved JSON: `IS_OWNER` is set at the resource level (top-level cannot grant `IS_OWNER`); `CAN_MANAGE` is set at the resource level OR at the top-level (target-level permissions are merged into top-level by `bundle validate`). Run policy against `bundle validate -t prod -o json` to apply only to prod. | Resolved JSON |
| P16 | Model serving has rate limits + AI gateway | High | Unmetered inference: unbounded compute cost, no abuse throttling, no request audit. | Every `model_serving_endpoints[*]` defines `rate_limits` and `ai_gateway` | Resolved JSON |
| P17 | Dependencies hash-pinned | Medium | Registry compromise or cache poisoning installs a different artifact than reviewed. | `requirements*.txt` / lockfile installed with `--require-hashes`; lockfile present | Source tree |
| P18 | No known-vulnerable dependencies | Critical when active critical CVE; else Medium | Known-exploitable code shipped to prod. Direct exploitation against the runtime. | `pip-audit` / `osv-scanner` against a date-pinned vuln database returns zero findings ≥ chosen severity | Source tree |
| P19 | Bundle ≡ deployed structural diff | Medium | Deploy silently overwrites a legitimate out-of-band fix, or bundle is non-authoritative and drift accumulates. | Structural diff of `bundle validate -o json` against `bundle summary -o json` shows only intended changes | CLI + workspace |
| P20 | Audit log delivery enabled in target workspace | Critical | No audit trail in target → no detection, no response, no compliance evidence. | Workspace API confirms audit log delivery configured for the target workspace | Workspace API |

## How to run

```bash
# 1. Resolve bundle (P1)
databricks bundle validate -t "$TARGET" -o json > bundle.resolved.json

# 2. Policy on resolved bundle (P2-P16, source-tree variants of P12/P14)
conftest test --policy policy/dab/ bundle.resolved.json

# 3. Source-tree checks (P12 source variant, P14)
grep -rE 'dapi[a-f0-9]{32}|AKIA[0-9A-Z]{16}' --include='*.yml' --include='*.yaml' .

# 4. Dependency posture (P17, P18)
pip-audit --require-hashes -r requirements.txt
pip-audit --strict -r requirements.txt

# 5. Drift + workspace checks (P19, P20)
python scripts/diff_bundle.py bundle.resolved.json
python scripts/check_audit_delivery.py --target "$TARGET"
```

## Notes on enforcement layer

- **Resolved JSON** checks (P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P13, P15, P16) run in Rego via `conftest`. See `policy/*.rego` (package `dab`, split by domain — `helpers`, `targets`, `bundle`, `permissions`, `clusters`, `libraries`, `secrets`, `model_serving`).
- **Source YAML** checks (P14, and the source variant of P12) run via `grep` / `semgrep` against the YAML files before `bundle validate` resolves substitutions and lookups. After resolution, a `lookup:`-derived ID and a hardcoded ID are indistinguishable.
- **CLI / workspace** checks (P1, P19, P20) run via the `databricks` CLI and SDK in helper scripts.
- Dependency checks (P17, P18) run against the source tree via `pip-audit`.
