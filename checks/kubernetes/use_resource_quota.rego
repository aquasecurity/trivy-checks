# METADATA
# title: resource quota usage
# description: Ensure that a ResourceQuota policy is configured to limit aggregate resource usage within a namespace
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/quota-memory-cpu-namespace/
# custom:
#   id: KSV040
#   avd_id: AVD-KSV-0040
#   severity: LOW
#   short_code: resource-quota-usage
#   recommended_action: Create a ResourceQuota policy with memory and CPU quotas for each namespace
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: resourcequota
package builtin.kubernetes.KSV040

import rego.v1

import data.lib.kubernetes

required_fields := {
	"requests.cpu",
	"requests.memory",
	"limits.cpu",
	"limits.memory",
}

resource_quota_configured if {
	every field in required_fields {
		kubernetes.has_field(input.spec.hard, field)
	}
}

deny contains res if {
	not resource_quota_configured
	msg := "A resource quota policy with hard memory and CPU limits should be configured per namespace"
	res := result.new(msg, object.get(input.spec, "hard", input.spec))
}
