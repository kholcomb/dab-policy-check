# Cluster shape rules: P9, P10.

package dab

import rego.v1

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
