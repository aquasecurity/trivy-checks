# METADATA
# title: Web App uses latest TLS version
# description: |
#   Use a more recent TLS/SSL policy for the App Service
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AZU-0006
#   aliases:
#     - AVD-AZU-0006
#     - use-secure-tls-policy
#   long_id: azure-appservice-use-secure-tls-policy
#   provider: azure
#   service: appservice
#   severity: HIGH
#   recommended_action: The TLS version being outdated and has known vulnerabilities
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/use_secure_tls_policy.yaml
package builtin.azure.appservice.azure0006

import rego.v1

import data.lib.cloud.metadata

recommended_tls_version := "1.2"

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not is_recommended_tls_version(service)
	res := result.new(
		"App service does not require a secure TLS version.",
		metadata.obj_by_path(service, ["site", "minimumtlsversion"]),
	)
}

is_recommended_tls_version(service) := service.site.minimumtlsversion.value == recommended_tls_version
