# METADATA
# title: Web App Accepting Traffic Other Than HTTPS
# description: |
#   Allowing HTTP undermines transport encryption and exposes user data.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#https_only
# custom:
#   id: AZU-0072
#   long_id: azure-appservice-web-app-https-only
#   aliases:
#     - AVD-AZU-0072
#     - web-app-https-only
#   provider: azure
#   service: appservice
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Set 'HTTPS Only' to true in App Service TLS settings to force encrypted transport.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/web_app_https_only.yaml
package builtin.azure.appservice.azure0072

import rego.v1

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not service.httpsonly.value
	res := result.new(
		"App service does not have HTTPS enforced.",
		object.get(service, "httpsonly", service),
	)
}
