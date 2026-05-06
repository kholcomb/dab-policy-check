# Bundle-level metadata rules: P6.

package dab

import rego.v1

# ---------- P6: bundle.databricks_cli_version present ----------

deny contains msg if {
	not input.bundle.databricks_cli_version
	msg := "[P6/Low] bundle.databricks_cli_version must be set (resource: bundle.databricks_cli_version)"
}
