# METADATA
# title: App Service Without Latest Python Version
# description: |
#   An outdated Python runtime in Azure App Service may miss security patches and improvements, leading to exploitable conditions.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#python_version
# custom:
#   id: AVD-AZU-0070
#   avd_id: AVD-AZU-0070
#   provider: azure
#   service: appservice
#   severity: LOW
#   minimum_trivy_version: 0.68.0
#   short_code: latest-python-version
#   recommended_action: Update the App Service runtime to the newest stable Python version for security and support.
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

# Latest supported Python version as of common practice
latest_python_version := "3.11"

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	has_python_configured(service)
	not is_latest_python_version(service)
	res := result.new(
		sprintf("App service is not using the latest Python version (%s). Current version: %s", [latest_python_version, service.site.pythonversion.value]),
		metadata.obj_by_path(service, ["site", "pythonversion"]),
	)
}

has_python_configured(service) if {
	service.site.pythonversion.value != ""
}

is_latest_python_version(service) if {
	service.site.pythonversion.value == latest_python_version
}
