# METADATA
# title: Instances should not use the default service account
# description: |
#   The default service account has full project access. Instances should instead be assigned the minimal access they need.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0044
#   avd_id: AVD-GCP-0044
#   provider: google
#   service: compute
#   severity: CRITICAL
#   short_code: no-default-service-account
#   recommended_action: Remove use of default service account
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/no_default_service_account.yaml
package builtin.google.compute.google0044

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	instance.serviceaccount.isdefault.value
	res := result.new(
		"Instance uses the default service account.",
		instance.serviceaccount.isdefault,
	)
}
