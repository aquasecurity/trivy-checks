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
#   id: GCP-0007
#   aliases:
#     - AVD-GCP-0007
#     - no-privileged-service-accounts
#   long_id: google-iam-no-privileged-service-accounts
#   provider: google
#   service: iam
#   severity: HIGH
#   recommended_action: Limit service account access to minimal required set
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   examples: checks/cloud/google/iam/no_privileged_service_accounts.yaml
package builtin.google.iam.google0007

import rego.v1

import data.lib.google.iam

deny contains res if {
	some member in iam.all_members
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
