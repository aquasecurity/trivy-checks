# METADATA
# title: Ensure databases are not publicly accessible
# description: |
#   Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0022
#   avd_id: AVD-AZU-0022
#   provider: azure
#   service: database
#   severity: MEDIUM
#   short_code: no-public-access
#   recommended_action: Disable public access to database when not required
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   examples: checks/cloud/azure/database/no_public_access.yaml
package builtin.azure.database.azure0022

import rego.v1

import data.lib.azure.database

deny contains res if {
	some server in database.all_servers
	server.enablepublicnetworkaccess.value
	res := result.new(
		"Database server has public network access enabled.",
		server.enablepublicnetworkaccess,
	)
}
