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
#     good_examples: checks/cloud/azure/appservice/account_identity_registered.yaml
#     bad_examples: checks/cloud/azure/appservice/account_identity_registered.yaml
package builtin.azure.appservice.azure0002

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	identity_type_missed(service)
	res := result.new(
		"App service does not have an identity type.",
		metadata.obj_by_path(service, ["identity", "type"]),
	)
}

identity_type_missed(service) if value.is_empty(service.identity.type)

identity_type_missed(service) if not service.identity.type
