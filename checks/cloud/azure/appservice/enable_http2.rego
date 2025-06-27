# METADATA
# title: Web App uses the latest HTTP version
# description: |
#   Use the latest version of HTTP to ensure you are benefiting from security fixes
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AZU-0005
#   aliases:
#     - AVD-AZU-0005
#     - enable-http2
#   long_id: azure-appservice-enable-http2
#   provider: azure
#   service: appservice
#   severity: LOW
#   recommended_action: Use the latest version of HTTP
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/enable_http2.yaml
package builtin.azure.appservice.azure0005

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not service.site.enablehttp2.value
	res := result.new(
		"App service does not have HTTP/2 enabled.",
		metadata.obj_by_path(service, ["site", "enablehttp2"]),
	)
}
