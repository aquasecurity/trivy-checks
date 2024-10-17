# METADATA
# title: Unencrypted data lake storage.
# description: |
#   Datalake storage encryption defaults to Enabled, it shouldn't be overridden to Disabled.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/data-lake-store/data-lake-store-security-overview
# custom:
#   id: AVD-AZU-0036
#   avd_id: AVD-AZU-0036
#   provider: azure
#   service: datalake
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: Enable encryption of data lake storage
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: datalake
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_lake_store
#     good_examples: checks/cloud/azure/datalake/enable_at_rest_encryption.yaml
#     bad_examples: checks/cloud/azure/datalake/enable_at_rest_encryption.yaml
package builtin.azure.datalake.azure0036

import rego.v1

deny contains res if {
	some store in input.azure.datalake.stores
	not store.enableencryption.value
	res := result.new(
		"Data lake store is not encrypted.",
		object.get(store, "enableencryption", store),
	)
}
