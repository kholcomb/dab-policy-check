# Secret-leak prevention rules: P12, P13.

package dab

import rego.v1

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
