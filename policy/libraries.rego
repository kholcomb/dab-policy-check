# Task library pinning rules: P11.

package dab

import rego.v1

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
