# METADATA
# title: Roles limited to the required actions
# description: |
#   The permissions granted to a role should be kept to the minimum required to be able to do the task. Wildcard permissions must not be used.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0030
#   avd_id: AVD-AZU-0030
#   provider: azure
#   service: authorization
#   severity: MEDIUM
#   short_code: limit-role-actions
#   recommended_action: Use targeted permissions for roles
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: authorization
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition#actions
#     good_examples: checks/cloud/azure/authorization/limit_role_actions.tf.go
#     bad_examples: checks/cloud/azure/authorization/limit_role_actions.tf.go
package builtin.azure.authorization.azure0030

import rego.v1

deny contains res if {
	some roledef in input.azure.authorization.roledefinitions
	some action in roledef.permissions[_].actions
	contains(action.value, "*")
	some scope in roledef.assignablescopes
	scope.value == "/"
	res := result.new(
		"Role definition uses wildcard action with all scopes.",
		action,
	)
}
