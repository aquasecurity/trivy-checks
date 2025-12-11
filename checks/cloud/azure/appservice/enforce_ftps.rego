# METADATA
# title: App Service FTPS Enforce Disabled
# description: |
#   Allowing plain FTP risks credentials and data being transmitted unencrypted.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#ftps_state
# custom:
#   id: AZU-0071
#   long_id: azure-appservice-enforce-ftps
#   aliases:
#     - AVD-AZU-0071
#     - enforce-ftps
#   provider: azure
#   service: appservice
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Set FTPS state to 'FTPS Only' in App Service settings to prevent plaintext FTP.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/enforce_ftps.yaml
package builtin.azure.appservice.azure0071

import rego.v1

import data.lib.cloud.metadata

secure_ftps_states := {"FtpsOnly", "Disabled"}

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not is_secure_ftps_state(service)
	res := result.new(
		sprintf("App service allows insecure FTP access. FTPS state is set to '%s' but should be 'FtpsOnly' or 'Disabled'", [service.site.ftpsstate.value]),
		metadata.obj_by_path(service, ["site", "ftpsstate"]),
	)
}

is_secure_ftps_state(service) if {
	service.site.ftpsstate.value in secure_ftps_states
}
