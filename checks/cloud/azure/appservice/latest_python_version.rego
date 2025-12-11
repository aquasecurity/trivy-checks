# METADATA
# title: App Service Using Unsupported Python Version
# description: |
#   Using an unsupported Python runtime in Azure App Service may expose applications to security vulnerabilities
#   as these versions no longer receive security patches. This check ensures Python versions are still supported by the Python Foundation.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#python_version
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_web_app#python_version
#   - https://peps.python.org/pep-0602/
# custom:
#   id: AZU-0070
#   long_id: azure-appservice-supported-python-version
#   aliases:
#     - AVD-AZU-0070
#     - supported-python-version
#   provider: azure
#   service: appservice
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Update to a supported Python version (3.9 or higher). Consider migrating from azurerm_app_service to azurerm_linux_web_app for access to modern Python versions.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/latest_python_version.yaml
package builtin.azure.appservice.azure0070

import rego.v1

import data.lib.cloud.metadata

# Minimum supported Python version - Python 3.8 reached EOL in October 2024
minimum_supported_python_version := "3.9"

# NOTE: Resource type considerations
# - azurerm_app_service (deprecated): Limited to older Python versions, direct python_version in site_config
# - azurerm_linux_web_app (recommended): Supports modern Python versions, python_version nested under application_stack
# The input.azure.appservice.services structure handles both resource types in a unified format,
# with the python version accessible via service.site.pythonversion.value regardless of source resource type.

# Unsupported Python versions (those that have reached EOL)
unsupported_python_versions := {
	"3.7", # EOL: June 2023
	"3.8", # EOL: October 2024
	"2.7", # EOL: January 2020
}

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	has_python_configured(service)
	is_unsupported_python_version(service)
	res := result.new(
		sprintf("App service is using an unsupported Python version (%s). Use Python %s or higher for continued security support.", [service.site.pythonversion.value, minimum_supported_python_version]),
		metadata.obj_by_path(service, ["site", "pythonversion"]),
	)
}

has_python_configured(service) if {
	service.site.pythonversion.value != ""
}

is_unsupported_python_version(service) if {
	service.site.pythonversion.value in unsupported_python_versions
}

is_unsupported_python_version(service) if {
	version := service.site.pythonversion.value
	version != ""

	# Handle version strings like "3.8.x" by extracting major.minor
	version_parts := split(version, ".")
	count(version_parts) >= 2
	major_minor := sprintf("%s.%s", [version_parts[0], version_parts[1]])
	major_minor in unsupported_python_versions
}
