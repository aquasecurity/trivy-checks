# METADATA
# title: App Service Using Unsupported PHP Version
# description: |
#   Using an unsupported PHP runtime in Azure App Service may expose applications to security vulnerabilities
#   as these versions no longer receive security patches. This check ensures PHP versions are still supported.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#php_version
# custom:
#   id: AZU-0069
#   long_id: azure-appservice-supported-php-version
#   aliases:
#     - AVD-AZU-0069
#     - supported-php-version
#   provider: azure
#   service: appservice
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Update to a supported PHP version (8.1 or higher). Consider migrating from azurerm_app_service to azurerm_linux_web_app for access to modern PHP versions.
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

# Minimum supported PHP version - PHP 8.0 reached EOL in November 2023
minimum_supported_php_version := "8.1"

# NOTE: Resource type considerations
# - azurerm_app_service (deprecated): Limited to older PHP versions, direct php_version in site_config
# - azurerm_linux_web_app (recommended): Supports modern PHP versions, php_version nested under application_stack
# The input.azure.appservice.services structure handles both resource types in a unified format,
# with the PHP version accessible via service.site.phpversion.value regardless of source resource type.

# Unsupported PHP versions (those that have reached EOL)
unsupported_php_versions := {
	"7.4", # EOL: November 2022
	"8.0", # EOL: November 2023
	"7.3", # EOL: December 2021
	"7.2", # EOL: November 2020
	"7.1", # EOL: December 2019
	"7.0", # EOL: January 2019
}

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	has_php_configured(service)
	is_unsupported_php_version(service)
	res := result.new(
		sprintf("App service is using an unsupported PHP version (%s). Use PHP %s or higher for continued security support.", [service.site.phpversion.value, minimum_supported_php_version]),
		metadata.obj_by_path(service, ["site", "phpversion"]),
	)
}

has_php_configured(service) if {
	service.site.phpversion.value != ""
}

is_unsupported_php_version(service) if {
	service.site.phpversion.value in unsupported_php_versions
}

is_unsupported_php_version(service) if {
	version := service.site.phpversion.value
	version != ""

	# Handle version strings like "8.0.x" by extracting major.minor
	version_parts := split(version, ".")
	count(version_parts) >= 2
	major_minor := sprintf("%s.%s", [version_parts[0], version_parts[1]])
	major_minor in unsupported_php_versions
}

isManaged(service) if {
	not service.unresolvable
}
