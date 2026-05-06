# package: dab — OPA Rego policy pack for Databricks Asset Bundles.
# Input: resolved JSON from `databricks bundle validate -o json`.
# Run:   `conftest test --policy DAB/policy <bundle.json>`.
# Deny format: [<ID>/<Severity>] <message> (resource: <path>)
# Not implemented: P14, P17, P18, P19, P20 — enforced by other CI tooling
# (source tree, dependency manifests, workspace API).

package dab

import rego.v1

# ---------- helpers ----------

is_prod(name) if regex.match(`^prod`, name)

all_clusters contains {"path": p, "cluster": c} if {
	some k
	c := input.resources.clusters[k]
	p := sprintf("resources.clusters.%s", [k])
}

all_clusters contains {"path": p, "cluster": c} if {
	some jk, i
	c := input.resources.jobs[jk].job_clusters[i].new_cluster
	p := sprintf("resources.jobs.%s.job_clusters[%d].new_cluster", [jk, i])
}

all_clusters contains {"path": p, "cluster": c} if {
	some pk, i
	c := input.resources.pipelines[pk].clusters[i]
	p := sprintf("resources.pipelines.%s.clusters[%d]", [pk, i])
}

identity_of(p) := p.user_name if p.user_name
identity_of(p) := p.group_name if p.group_name
identity_of(p) := p.service_principal_name if p.service_principal_name

resource_perms contains {"path": p, "perm": perm} if {
	some t, k, i
	perm := input.resources[t][k].permissions[i]
	p := sprintf("resources.%s.%s.permissions[%d]", [t, k, i])
}

# ---------- P2: prod targets must be mode=production ----------

deny contains msg if {
	some name
	t := input.targets[name]
	is_prod(name)
	not t.mode == "production"
	msg := sprintf("[P2/High] prod target must have mode=\"production\" (resource: targets.%s)", [name])
}

# ---------- P3: prod targets must run_as service_principal_name, not user_name ----------

deny contains msg if {
	some name
	target := input.targets[name]
	is_prod(name)
	not target.run_as.service_principal_name
	msg := sprintf("[P3/High] prod target must set run_as.service_principal_name (resource: targets.%s.run_as)", [name])
}

deny contains msg if {
	some name
	target := input.targets[name]
	is_prod(name)
	target.run_as.user_name
	msg := sprintf("[P3/High] prod target must NOT set run_as.user_name (resource: targets.%s.run_as)", [name])
}

# ---------- P4: prod workspace.root_path must not be a personal folder ----------

deny contains msg if {
	some name
	target := input.targets[name]
	is_prod(name)
	not target.workspace.root_path
	msg := sprintf("[P4/High] prod workspace.root_path must be set (resource: targets.%s.workspace)", [name])
}

deny contains msg if {
	some name
	target := input.targets[name]
	is_prod(name)
	regex.match(`^/Workspace/Users/`, target.workspace.root_path)
	msg := sprintf("[P4/High] prod workspace.root_path must not start with /Workspace/Users/ (resource: targets.%s.workspace.root_path)", [name])
}

deny contains msg if {
	some name
	target := input.targets[name]
	is_prod(name)
	contains(target.workspace.root_path, "${workspace.current_user")
	msg := sprintf("[P4/High] prod workspace.root_path must not interpolate ${workspace.current_user} (resource: targets.%s.workspace.root_path)", [name])
}

# ---------- P5: prod targets must have a git branch pinned ----------

deny contains msg if {
	some name
	target := input.targets[name]
	is_prod(name)
	not target.git.branch
	not input.bundle.git.branch
	msg := sprintf("[P5/High] prod target must pin git.branch at target or bundle level (resource: targets.%s.git)", [name])
}

# ---------- P6: bundle.databricks_cli_version present ----------

deny contains msg if {
	not input.bundle.databricks_cli_version
	msg := "[P6/Low] bundle.databricks_cli_version must be set (resource: bundle.databricks_cli_version)"
}

# ---------- P7: identity must not appear in both top-level and resource permissions ----------

top_level_identities contains id if {
	some i
	id := identity_of(input.permissions[i])
}

deny contains msg if {
	some rp in resource_perms
	id := identity_of(rp.perm)
	id in top_level_identities
	msg := sprintf("[P7/High] identity %q appears in both top-level and resource permissions (resource: %s)", [id, rp.path])
}

# ---------- P8: broad groups must not have CAN_MANAGE/IS_OWNER ----------

# Customize for your org's actual broad groups; comparison is case-insensitive.
broad_groups := {"users", "account users"}
dangerous_levels := {"CAN_MANAGE", "IS_OWNER"}

deny contains msg if {
	some i
	p := input.permissions[i]
	lower(p.group_name) in broad_groups
	p.level in dangerous_levels
	msg := sprintf("[P8/Critical] broad group %q must not have level %q (resource: permissions[%d])", [p.group_name, p.level, i])
}

deny contains msg if {
	some name, i
	p := input.targets[name].permissions[i]
	lower(p.group_name) in broad_groups
	p.level in dangerous_levels
	msg := sprintf("[P8/Critical] broad group %q must not have level %q (resource: targets.%s.permissions[%d])", [p.group_name, p.level, name, i])
}

deny contains msg if {
	some rp in resource_perms
	lower(rp.perm.group_name) in broad_groups
	rp.perm.level in dangerous_levels
	msg := sprintf("[P8/Critical] broad group %q must not have level %q (resource: %s)", [rp.perm.group_name, rp.perm.level, rp.path])
}

# ---------- P9: every cluster must use isolation mode ----------

deny contains msg if {
	some c in all_clusters
	not c.cluster.data_security_mode in {"USER_ISOLATION", "SINGLE_USER"}
	dsm := object.get(c.cluster, "data_security_mode", "<unset>")
	msg := sprintf("[P9/High] cluster has data_security_mode %q, must be USER_ISOLATION or SINGLE_USER (resource: %s)", [dsm, c.path])
}

# ---------- P10: init scripts only from workspace or volumes ----------

allowed_init_script_sources := {"workspace", "volumes"}

deny contains msg if {
	some c in all_clusters
	some i
	script := c.cluster.init_scripts[i]
	some src in object.keys(script)
	not src in allowed_init_script_sources
	msg := sprintf("[P10/Critical] init script source %q not allowed; only workspace or volumes (resource: %s.init_scripts[%d])", [src, c.path, i])
}

# ---------- P11: pinned library versions ----------

deny contains msg if {
	some jk, ti, li
	pkg := input.resources.jobs[jk].tasks[ti].libraries[li].pypi.package
	not contains(pkg, "==")
	msg := sprintf("[P11/High] pypi package %q must pin a version with == (resource: resources.jobs.%s.tasks[%d].libraries[%d].pypi)", [pkg, jk, ti, li])
}

deny contains msg if {
	some jk, ti, li
	pkg := input.resources.jobs[jk].tasks[ti].libraries[li].pypi.package
	regex.match(`[*<>~!,]`, pkg)
	msg := sprintf("[P11/High] pypi package %q must be exactly pinned; wildcard/range operators forbidden (resource: resources.jobs.%s.tasks[%d].libraries[%d].pypi)", [pkg, jk, ti, li])
}

deny contains msg if {
	some jk, ti, li
	coord := input.resources.jobs[jk].tasks[ti].libraries[li].maven.coordinates
	count(split(coord, ":")) < 3
	msg := sprintf("[P11/High] maven coordinates %q must be group:artifact:version (resource: resources.jobs.%s.tasks[%d].libraries[%d].maven)", [coord, jk, ti, li])
}

deny contains msg if {
	some jk, ti, li
	coord := input.resources.jobs[jk].tasks[ti].libraries[li].maven.coordinates
	regex.match(`[\[\]\(\),]`, coord)
	msg := sprintf("[P11/High] maven coordinates %q must be exactly pinned; range syntax forbidden (resource: resources.jobs.%s.tasks[%d].libraries[%d].maven)", [coord, jk, ti, li])
}

# ---------- P12: no secret-shaped variable defaults ----------

deny contains msg if {
	some name
	v := sprintf("%v", [input.variables[name].default])
	regex.match(`dapi[a-f0-9]{32}`, v)
	msg := sprintf("[P12/Critical] variable %q default looks like a Databricks PAT (resource: variables.%s.default)", [name, name])
}

deny contains msg if {
	some name
	v := sprintf("%v", [input.variables[name].default])
	regex.match(`AKIA[0-9A-Z]{16}`, v)
	msg := sprintf("[P12/Critical] variable %q default looks like an AWS access key (resource: variables.%s.default)", [name, name])
}

deny contains msg if {
	some name
	v := sprintf("%v", [input.variables[name].default])
	contains(v, "token=")
	msg := sprintf("[P12/Critical] variable %q default contains \"token=\" (resource: variables.%s.default)", [name, name])
}

# ---------- P13: required sync.exclude entries ----------

deny contains msg if {
	some pat in {".env", "*.pem", "*.key", "*.pfx", "variable-overrides.json"}
	excludes := object.get(input, ["sync", "exclude"], [])
	not pat in {e | some i; e := excludes[i]}
	msg := sprintf("[P13/High] sync.exclude must contain %q (resource: sync.exclude)", [pat])
}

# ---------- P15: jobs/pipelines must have IS_OWNER and CAN_MANAGE ----------
# Target context comes from the validate command (`bundle validate -t <target>`),
# not from the JSON content. Run this policy against the prod-resolved JSON only.
# IS_OWNER must be at the resource level (top-level supports only CAN_VIEW/CAN_RUN/CAN_MANAGE).
# CAN_MANAGE may cascade from top-level or target-level permissions.

has_inherited_can_manage if {
	some i
	input.permissions[i].level == "CAN_MANAGE"
}

has_inherited_can_manage if {
	some name, i
	input.targets[name].permissions[i].level == "CAN_MANAGE"
}

deny contains msg if {
	some jk
	perms := object.get(input.resources.jobs[jk], "permissions", [])
	not "IS_OWNER" in {p.level | some i; p := perms[i]}
	msg := sprintf("[P15/Medium] job must have at least one IS_OWNER permission at resource level (resource: resources.jobs.%s.permissions)", [jk])
}

deny contains msg if {
	some jk
	perms := object.get(input.resources.jobs[jk], "permissions", [])
	not "CAN_MANAGE" in {p.level | some i; p := perms[i]}
	not has_inherited_can_manage
	msg := sprintf("[P15/Medium] job must have a CAN_MANAGE permission at resource, target, or top level (resource: resources.jobs.%s)", [jk])
}

deny contains msg if {
	some pk
	perms := object.get(input.resources.pipelines[pk], "permissions", [])
	not "IS_OWNER" in {p.level | some i; p := perms[i]}
	msg := sprintf("[P15/Medium] pipeline must have at least one IS_OWNER permission at resource level (resource: resources.pipelines.%s.permissions)", [pk])
}

deny contains msg if {
	some pk
	perms := object.get(input.resources.pipelines[pk], "permissions", [])
	not "CAN_MANAGE" in {p.level | some i; p := perms[i]}
	not has_inherited_can_manage
	msg := sprintf("[P15/Medium] pipeline must have a CAN_MANAGE permission at resource, target, or top level (resource: resources.pipelines.%s)", [pk])
}

# ---------- P16: model serving endpoints must set rate_limits and ai_gateway ----------

deny contains msg if {
	some k
	ep := input.resources.model_serving_endpoints[k]
	count(object.get(ep, "rate_limits", [])) == 0
	msg := sprintf("[P16/High] model serving endpoint must set rate_limits (resource: resources.model_serving_endpoints.%s)", [k])
}

deny contains msg if {
	some k
	ep := input.resources.model_serving_endpoints[k]
	count(object.get(ep, "ai_gateway", {})) == 0
	msg := sprintf("[P16/High] model serving endpoint must set ai_gateway (resource: resources.model_serving_endpoints.%s)", [k])
}
