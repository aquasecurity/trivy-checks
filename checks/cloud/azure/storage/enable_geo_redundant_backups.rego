# METADATA
# title: Storage account should use geo-redundant replication
# description: |
#   Geo-redundant storage (GRS) replicates your data to a secondary region that is hundreds of miles away from the primary region.
#   This provides an additional level of durability for your data in the event of a complete regional outage or a disaster.
#   Options include GRS, RAGRS, GZRS, and RAGZRS for geo-redundancy.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/storage-redundancy
# custom:
#   id: AZU-0058
#   long_id: azure-storage-enable-geo-redundant-backups
#   aliases:
#     - AVD-AZU-0058
#     - enable-geo-redundant-backups
#   provider: azure
#   service: storage
#   severity: LOW
#   minimum_trivy_version: 0.68.0
#   recommended_action: Configure storage account to use geo-redundant replication (GRS, RAGRS, GZRS, or RAGZRS)
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/enable_geo_redundant_backups.yaml
package builtin.azure.storage.azure0058

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	not_geo_redundant(account)
	res := result.new(
		"Storage account does not use geo-redundant replication.",
		metadata.obj_by_path(account, ["accountreplicationtype"]),
	)
}

not_geo_redundant(account) if {
	not account.accountreplicationtype
}

geo_redundant_types := {"GRS", "RAGRS", "GZRS", "RAGZRS"}

not_geo_redundant(account) if {
	not value.is_unresolvable(account.accountreplicationtype)
	not account.accountreplicationtype.value in geo_redundant_types
}
