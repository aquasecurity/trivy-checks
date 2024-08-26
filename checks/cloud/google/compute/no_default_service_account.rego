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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#
#     good_examples: checks/cloud/google/compute/no_default_service_account.tf.go
#     bad_examples: checks/cloud/google/compute/no_default_service_account.tf.go
package builtin.google.compute.google0044

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	service_account := instance.serviceaccount
	is_default_service_account(service_account)
	res := result.new(
		"Instance uses the default service account.",
		object.get(service_account, "email", service_account),
	)
}

is_default_service_account(service_account) := service_account.isdefault.value == true
