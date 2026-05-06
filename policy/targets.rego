# Prod target shape rules: P2, P3, P4, P5.
#
# NOTE: `databricks bundle validate -t <target> -o json` flattens the active
# target's config into top-level keys. There is NO `targets` key in the
# resolved JSON. The active target name is at `input.bundle.target`; mode at
# `input.bundle.mode`; workspace at `input.workspace.*`; run_as at top level.
# Run the policy once per target you want to enforce.

package dab

import rego.v1

# ---------- P2: prod target must be mode=production ----------

deny contains msg if {
	is_prod(input.bundle.target)
	not input.bundle.mode == "production"
	msg := sprintf("[P2/High] prod target %q has mode %q; must be \"production\" (resource: bundle.mode)", [input.bundle.target, object.get(input.bundle, "mode", "<unset>")])
}

# ---------- P3: prod must run_as service_principal_name, not user_name ----------

deny contains msg if {
	is_prod(input.bundle.target)
	not input.run_as.service_principal_name
	msg := sprintf("[P3/High] prod target %q must set run_as.service_principal_name (resource: run_as)", [input.bundle.target])
}

deny contains msg if {
	is_prod(input.bundle.target)
	input.run_as.user_name
	msg := sprintf("[P3/High] prod target %q must NOT set run_as.user_name (resource: run_as)", [input.bundle.target])
}

# ---------- P4: prod workspace.root_path must not be a personal folder ----------

deny contains msg if {
	is_prod(input.bundle.target)
	not input.workspace.root_path
	msg := sprintf("[P4/High] prod target %q must set workspace.root_path (resource: workspace)", [input.bundle.target])
}

deny contains msg if {
	is_prod(input.bundle.target)
	regex.match(`^/Workspace/Users/`, input.workspace.root_path)
	msg := sprintf("[P4/High] prod target %q workspace.root_path must not start with /Workspace/Users/ (resource: workspace.root_path)", [input.bundle.target])
}

deny contains msg if {
	is_prod(input.bundle.target)
	contains(input.workspace.root_path, "${workspace.current_user")
	msg := sprintf("[P4/High] prod target %q workspace.root_path must not interpolate ${workspace.current_user} (resource: workspace.root_path)", [input.bundle.target])
}

# ---------- P5: prod must have a git branch pinned ----------
# Target-level git.branch is merged into bundle.git.branch in the resolved view.

deny contains msg if {
	is_prod(input.bundle.target)
	not input.bundle.git.branch
	msg := sprintf("[P5/High] prod target %q must pin bundle.git.branch (resource: bundle.git)", [input.bundle.target])
}
