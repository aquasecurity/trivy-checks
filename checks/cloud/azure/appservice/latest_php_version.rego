# METADATA
# title: App Service Without Latest PHP Version
# description: |
#   Running outdated PHP on App Service exposes apps to known vulnerabilities and performance degradation.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#php_version
# custom:
#   id: AVD-AZU-0069
#   avd_id: AVD-AZU-0069
#   provider: azure
#   service: appservice
#   severity: LOW
#   minimum_trivy_version: 0.68.0
#   short_code: latest-php-version
#   recommended_action: Upgrade to the latest supported PHP version in the App Service configuration settings.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/latest_php_version.yaml
package builtin.azure.appservice.azure0069

import rego.v1

import data.lib.cloud.metadata

# Latest supported PHP version as of common practice
latest_php_version := "8.2"

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	has_php_configured(service)
	not is_latest_php_version(service)
	res := result.new(
		sprintf("App service is not using the latest PHP version (%s). Current version: %s", [latest_php_version, service.site.phpversion.value]),
		metadata.obj_by_path(service, ["site", "phpversion"]),
	)
}

has_php_configured(service) if {
	service.site.phpversion.value != ""
}

is_latest_php_version(service) if {
	service.site.phpversion.value == latest_php_version
}
