# METADATA
# title: Service accounts should not have roles assigned with excessive privileges
# description: |
#   Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/iam/docs/understanding-roles
# custom:
#   id: AVD-GCP-0007
#   avd_id: AVD-GCP-0007
#   provider: google
#   service: iam
#   severity: HIGH
#   short_code: no-privileged-service-accounts
#   recommended_action: Limit service account access to minimal required set
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam
#     good_examples: checks/cloud/google/iam/no_privileged_service_accounts.yaml
#     bad_examples: checks/cloud/google/iam/no_privileged_service_accounts.yaml
package builtin.google.iam.google0007

import rego.v1

import data.lib.google.iam

deny contains res if {
	some member in iam.all_members
	print(member)
	iam.is_service_account(member.member.value)
	iam.is_role_privileged(member.role.value)
	res := result.new("Service account is granted a privileged role.", member.role)
}

deny contains res if {
	some binding in iam.all_bindings
	iam.is_role_privileged(binding.role.value)
	some member in binding.members
	iam.is_service_account(member.value)
	res := result.new("Service account is granted a privileged role.", member)
}
