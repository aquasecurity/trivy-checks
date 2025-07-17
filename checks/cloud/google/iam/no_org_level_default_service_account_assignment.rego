# METADATA
# title: Roles should not be assigned to default service accounts
# description: |
#   Default service accounts should not be used - consider creating specialised service accounts for individual purposes.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
# custom:
#   id: AVD-GCP-0008
#   avd_id: AVD-GCP-0008
#   provider: google
#   service: iam
#   severity: MEDIUM
#   short_code: no-org-level-default-service-account-assignment
#   recommended_action: Use specialised service accounts for specific purposes.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   examples: checks/cloud/google/iam/no_org_level_default_service_account_assignment.yaml
package builtin.google.iam.google0008

import rego.v1

import data.lib.google.iam

deny contains res if {
	some member in iam.members("organizations")
	member.defaultserviceaccount.value
	res := result.new("Role is assigned to a default service account at organization level.", member.defaultserviceaccount)
}

deny contains res if {
	some member in iam.members("organizations")
	iam.is_member_default_service_account(member.member.value)
	res := result.new("Role is assigned to a default service account at organization level.", member.member)
}

deny contains res if {
	some binding in iam.bindings("organizations")
	binding.includesdefaultserviceaccount.value == true
	res := result.new("Role is assigned to a default service account at organization level.", binding.includesdefaultserviceaccount)
}

deny contains res if {
	some binding in iam.bindings("organizations")
	some member in binding.members
	iam.is_member_default_service_account(member.value)
	res := result.new("Role is assigned to a default service account at organization level.", member)
}
