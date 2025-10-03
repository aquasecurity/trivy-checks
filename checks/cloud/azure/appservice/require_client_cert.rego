# METADATA
# title: Web App accepts incoming client certificate
# description: |
#   The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0001
#   avd_id: AVD-AZU-0001
#   provider: azure
#   service: appservice
#   severity: LOW
#   short_code: require-client-cert
#   recommended_action: Enable incoming certificates for clients
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/require_client_cert.yaml
package builtin.azure.appservice.azure0001

import rego.v1

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not service.enableclientcert.value
	res := result.new(
		"App service does not have client certificates enabled.",
		object.get(service, "enableclientcert", service),
	)
}
