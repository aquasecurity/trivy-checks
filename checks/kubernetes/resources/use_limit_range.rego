# METADATA
# title: limit range usage
# description: Ensure that a LimitRange policy is configured to limit resource usage for namespaces or nodes
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/policy/limit-range/
# - https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/memory-default-namespace/
# - https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/memory-constraint-namespace/
# custom:
#   id: KSV039
#   avd_id: AVD-KSV-0039
#   severity: LOW
#   short_code: limit-range-usage
#   recommended_action: Create a LimitRange policy with default requests and limits for each container
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: limitrange
package builtin.kubernetes.KSV039

import rego.v1

import data.lib.kubernetes

required_fields := {
	"type",
	"max",
	"min",
	"default",
	"defaultRequest",
}

limit_range_configured if {
	kubernetes.has_field(input.spec, "limits")
	some limit in input.spec.limits
	every field in required_fields {
		kubernetes.has_field(limit, field)
	}
}

deny contains res if {
	not limit_range_configured
	msg := "A LimitRange policy with a default requests and limits for each container should be configured"
	res := result.new(msg, input.spec)
}
