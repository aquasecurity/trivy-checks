# METADATA
# title: SSL should be enforced on database connections where applicable
# description: |
#   SSL connections should be enforced were available to ensure secure transfer and reduce the risk of compromising data in flight.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0020
#   avd_id: AVD-AZU-0020
#   provider: azure
#   service: database
#   severity: MEDIUM
#   short_code: enable-ssl-enforcement
#   recommended_action: Enable SSL enforcement
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_enforcement_enabled
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_enforcement_enabled
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#ssl_enforcement_enabled
#     good_examples: checks/cloud/azure/database/enable_ssl_enforcement.yaml
#     bad_examples: checks/cloud/azure/database/enable_ssl_enforcement.yaml
package builtin.azure.database.azure0020

import rego.v1

import data.lib.azure.database

deny contains res if {
	some server in database.servers(["postgresqlservers", "mysqlservers", "mariadbservers"])
	not server.enablesslenforcement.value
	res := result.new(
		"Database server does not have enforce SSL.",
		object.get(server, "enablesslenforcement", server),
	)
}
