# METADATA
# title: Role Definition Allows Custom Role Creation
# description: |
#   Allowing custom roles to include 'roleDefinitions/write' enables privilege escalation. A user could define or alter roles to gain excessive permissions.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition#actions
# custom:
#   id: AZU-0052
#   long_id: azure-authorization-prevent-custom-role-creation
#   aliases:
#     - AVD-AZU-0052
#     - prevent-custom-role-creation
#     - azure-role-definition-allows-custom-role-creation
#   provider: azure
#   service: authorization
#   severity: MEDIUM
#   recommended_action: Avoid granting 'Microsoft.Authorization/roleDefinitions/write' permission in custom roles. Restrict role creation capability to core admins only.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: authorization
#             provider: azure
#   examples: checks/cloud/azure/authorization/prevent_custom_role_creation.yaml
package builtin.azure.authorization.azure0052

import rego.v1

deny contains res if {
	some roledef in input.azure.authorization.roledefinitions
	isManaged(roledef)
	some action in roledef.permissions[_].actions
	allows_custom_role_creation(action.value)
	res := result.new(
		"Role definition allows custom role creation via 'Microsoft.Authorization/roleDefinitions/write' permission.",
		action,
	)
}

dangerous_actions := {"Microsoft.Authorization/roleDefinitions/write", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/*", "*"}

allows_custom_role_creation(action_value) if {
	action_value in dangerous_actions
}
