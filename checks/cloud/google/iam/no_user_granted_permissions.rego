# METADATA
# title: IAM granted directly to user.
# description: |
#   Permissions should not be directly granted to users, you identify roles that contain the appropriate permissions, and then grant those roles to the user.
#
#   Granting permissions to users quickly become unwieldy and complex to make large scale changes to remove access to a particular resource.
#
#   Permissions should be granted on roles, groups, services accounts instead.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/iam/docs/overview#permissions
#   - https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy
# custom:
#   id: AVD-GCP-0003
#   avd_id: AVD-GCP-0003
#   provider: google
#   service: iam
#   severity: MEDIUM
#   short_code: no-user-granted-permissions
#   recommended_action: Roles should be granted permissions and assigned to users
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   examples: checks/cloud/google/iam/no_user_granted_permissions.yaml
package builtin.google.iam.google0003

import rego.v1

import data.lib.google.iam

deny contains res if {
	some member in iam.all_members
	startswith(member.member.value, "user:")
	res := result.new("Permissions are granted directly to a user.", member.member)
}

deny contains res if {
	some binding in iam.all_bindings
	print(binding)
	some member in binding.members
	startswith(member.value, "user:")
	res := result.new("Permissions are granted directly to a user.", member)
}
