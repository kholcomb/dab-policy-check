# Model serving endpoint rules: P16.

package dab

import rego.v1

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
