# METADATA
# title: Web App has registration with AD enabled
# description: |
#   Registering the identity used by an App with AD allows it to interact with other services without using username and password
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0002
#   avd_id: AVD-AZU-0002
#   provider: azure
#   service: appservice
#   severity: LOW
#   short_code: account-identity-registered
#   recommended_action: Register the app identity with AD
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#identity
#     good_examples: checks/cloud/azure/appservice/account_identity_registered.tf.go
#     bad_examples: checks/cloud/azure/appservice/account_identity_registered.tf.go
package builtin.azure.appservice.azure0002

import rego.v1

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not has_identity_type(service)
	res := result.new(
		"App service does not have an identity type.",
		object.get(service, ["identity", "type"], service),
	)
}

has_identity_type(service) := service.identity.type.value != ""
