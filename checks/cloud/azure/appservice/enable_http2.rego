# METADATA
# title: Web App uses the latest HTTP version
# description: |
#   Use the latest version of HTTP to ensure you are benefiting from security fixes
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0005
#   avd_id: AVD-AZU-0005
#   provider: azure
#   service: appservice
#   severity: LOW
#   short_code: enable-http2
#   recommended_action: Use the latest version of HTTP
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#http2_enabled
#     good_examples: checks/cloud/azure/appservice/enable_http2.tf.go
#     bad_examples: checks/cloud/azure/appservice/enable_http2.tf.go
package builtin.azure.appservice.azure0005

import rego.v1

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not service.site.enablehttp2.value
	res := result.new(
		"App service does not have HTTP/2 enabled.",
		object.get(service, ["site", "enablehttp2"], service),
	)
}
