# METADATA
# title: Ensure the Function App can only be accessed via HTTPS. The default is false.
# description: |
#   By default, clients can connect to function endpoints by using both HTTP or HTTPS. You should redirect HTTP to HTTPs because HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https
#   - https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts
# custom:
#   id: AVD-AZU-0004
#   avd_id: AVD-AZU-0004
#   provider: azure
#   service: appservice
#   severity: CRITICAL
#   short_code: enforce-https
#   recommended_action: You can redirect all HTTP requests to the HTTPS port.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/enforce_https.yaml
package builtin.azure.appservice.azure0004

import rego.v1

deny contains res if {
	some app in input.azure.appservice.functionapps
	isManaged(app)
	not app.httpsonly.value
	res := result.new(
		"Function app does not have HTTPS enforced.",
		object.get(app, "httpsonly", app),
	)
}
