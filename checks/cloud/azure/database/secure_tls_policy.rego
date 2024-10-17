# METADATA
# title: Databases should have the minimum TLS set for connections
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0026
#   avd_id: AVD-AZU-0026
#   provider: azure
#   service: database
#   severity: MEDIUM
#   short_code: secure-tls-policy
#   recommended_action: Use the most modern TLS policies available
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#minimum_tls_version
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_minimal_tls_version_enforced
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_minimal_tls_version_enforced
#     good_examples: checks/cloud/azure/database/secure_tls_policy.yaml
#     bad_examples: checks/cloud/azure/database/secure_tls_policy.yaml
package builtin.azure.database.azure0026

import rego.v1

import data.lib.azure.database
import data.lib.cloud.metadata

recommended_tls_version := "TLS1_2"

recommended_mssql_tls_version := "1.2"

deny contains res if {
	some server in database.servers(["mysqlservers", "postgresqlservers"])
	not is_recommended_tls(server)
	res := result.new(
		"Database server does not require a secure TLS version.",
		metadata.obj_by_path(server, "minimumtlsversion"),
	)
}

deny contains res if {
	some server in database.servers(["mssqlservers"])
	not is_recommended_mssql_tls(server)
	res := result.new(
		"Database server does not require a secure TLS version.",
		metadata.obj_by_path(server, "minimumtlsversion"),
	)
}

is_recommended_tls(server) := server.minimumtlsversion.value == recommended_tls_version

is_recommended_mssql_tls(server) := server.minimumtlsversion.value == recommended_mssql_tls_version
