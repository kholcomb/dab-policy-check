# Identity & permission rules: P7, P8, P15.

package dab

import rego.v1

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
	some rp in resource_perms
	lower(rp.perm.group_name) in broad_groups
	rp.perm.level in dangerous_levels
	msg := sprintf("[P8/Critical] broad group %q must not have level %q (resource: %s)", [rp.perm.group_name, rp.perm.level, rp.path])
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
