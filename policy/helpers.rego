# package: dab — OPA Rego policy pack for Databricks Asset Bundles.
# Input: resolved JSON from `databricks bundle validate -o json`.
# Run:   `conftest test --policy DAB/policy <bundle.json>`.
# Deny format: [<ID>/<Severity>] <message> (resource: <path>)
# Not implemented: P14, P17, P18, P19, P20 — enforced by other CI tooling
# (source tree, dependency manifests, workspace API).
#
# This pack is split across multiple files in the same `dab` package:
#   helpers.rego        shared helpers (this file)
#   targets.rego        P2, P3, P4, P5     prod target shape
#   bundle.rego         P6                 bundle metadata
#   permissions.rego    P7, P8, P15        identity & permissions
#   clusters.rego       P9, P10            cluster shape
#   libraries.rego      P11                task library pinning
#   secrets.rego        P12, P13           secret-leak prevention
#   model_serving.rego  P16                serving endpoints
# Conftest concatenates every .rego file under `--policy` into one package,
# so behavior is identical to a single-file pack.

package dab

import rego.v1

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
