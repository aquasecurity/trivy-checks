# METADATA
# title: SSL should be enforced on database connections where applicable
# description: |
#   SSL connections should be enforced were available to ensure secure transfer and reduce the risk of compromising data in flight.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AZU-0020
#   aliases:
#     - AVD-AZU-0020
#     - enable-ssl-enforcement
#   long_id: azure-database-enable-ssl-enforcement
#   provider: azure
#   service: database
#   severity: MEDIUM
#   recommended_action: Enable SSL enforcement
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   examples: checks/cloud/azure/database/enable_ssl_enforcement.yaml
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
