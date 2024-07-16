# METADATA
# title: Roles should not be assigned to default service accounts
# description: |
#   Default service accounts should not be used - consider creating specialised service accounts for individual purposes.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
# custom:
#   id: AVD-GCP-0006
#   avd_id: AVD-GCP-0006
#   provider: google
#   service: iam
#   severity: MEDIUM
#   short_code: no-project-level-default-service-account-assignment
#   recommended_action: Use specialised service accounts for specific purposes.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam
#     good_examples: checks/cloud/google/iam/no_project_level_default_service_account_assignment.tf.go
#     bad_examples: checks/cloud/google/iam/no_project_level_default_service_account_assignment.tf.go
package builtin.google.iam.google0006

import rego.v1

import data.lib.google.iam

deny contains res if {
	some member in iam.members("projects")
	member.defaultserviceaccount.value
	res := result.new("Role is assigned to a default service account at project level.", member.defaultserviceaccount)
}

deny contains res if {
	some member in iam.members("projects")
	iam.is_member_default_service_account(member.member.value)
	res := result.new("Role is assigned to a default service account at project level.", member.member)
}

deny contains res if {
	some binding in iam.bindings("projects")
	binding.includesdefaultserviceaccount.value == true
	res := result.new("Role is assigned to a default service account at project level.", binding.includesdefaultserviceaccount)
}

deny contains res if {
	some binding in iam.bindings("projects")
	some member in binding.members
	iam.is_member_default_service_account(member.value)
	res := result.new("Role is assigned to a default service account at project level.", member)
}
