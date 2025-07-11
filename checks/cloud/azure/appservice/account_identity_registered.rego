# METADATA
# title: Web App has registration with AD enabled
# description: |
#   Registering the identity used by an App with AD allows it to interact with other services without using username and password
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AZU-0002
#   aliases:
#     - AVD-AZU-0002
#     - account-identity-registered
#   long_id: azure-appservice-account-identity-registered
#   provider: azure
#   service: appservice
#   severity: LOW
#   recommended_action: Register the app identity with AD
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/account_identity_registered.yaml
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
