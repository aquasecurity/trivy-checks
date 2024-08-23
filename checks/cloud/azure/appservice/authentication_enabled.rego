# METADATA
# title: App Service authentication is activated
# description: |
#   Enabling authentication ensures that all communications in the application are authenticated. The auth_settings block needs to be filled out with the appropriate auth backend settings
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0003
#   avd_id: AVD-AZU-0003
#   provider: azure
#   service: appservice
#   severity: MEDIUM
#   short_code: authentication-enabled
#   recommended_action: Enable authentication to prevent anonymous request being accepted
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#enabled
#     good_examples: checks/cloud/azure/appservice/authentication_enabled.tf.go
#     bad_examples: checks/cloud/azure/appservice/authentication_enabled.tf.go
package builtin.azure.appservice.azure0003

import rego.v1

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not service.authentication.enabled.value
	res := result.new(
		"App service does not have authentication enabled.",
		object.get(service, ["authentication", "enabled"], service),
	)
}
