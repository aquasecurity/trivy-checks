# METADATA
# title: Web App uses latest TLS version
# description: |
#   Use a more recent TLS/SSL policy for the App Service
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0006
#   avd_id: AVD-AZU-0006
#   provider: azure
#   service: appservice
#   severity: HIGH
#   short_code: use-secure-tls-policy
#   recommended_action: The TLS version being outdated and has known vulnerabilities
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#min_tls_version
#     good_examples: checks/cloud/azure/appservice/use_secure_tls_policy.tf.go
#     bad_examples: checks/cloud/azure/appservice/use_secure_tls_policy.tf.go
package builtin.azure.appservice.azure0006

import rego.v1

recommended_tls_version := "1.2"

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not is_recommended_tls_version(service)
	res := result.new(
		"App service does not require a secure TLS version.",
		object.get(service, ["site", "minimumtlsversion"], service),
	)
}

is_recommended_tls_version(service) := service.site.minimumtlsversion.value == recommended_tls_version
