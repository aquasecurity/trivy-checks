# METADATA
# title: Storage accounts should be configured to only accept transfers that are over secure connections
# description: |
#   You can configure your storage account to accept requests from secure connections only by setting the Secure transfer required property for the storage account.
#   When you require secure transfer, any requests originating from an insecure connection are rejected.
#   Microsoft recommends that you always require secure transfer for all of your storage accounts.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer
# custom:
#   id: AVD-AZU-0008
#   avd_id: AVD-AZU-0008
#   provider: azure
#   service: storage
#   severity: HIGH
#   short_code: enforce-https
#   recommended_action: Only allow secure connection for transferring data into storage accounts
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#enable_https_traffic_only
#     good_examples: checks/cloud/azure/storage/enforce_https.tf.go
#     bad_examples: checks/cloud/azure/storage/enforce_https.tf.go
package builtin.azure.storage.azure0008

import rego.v1

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	not account.enforcehttps.value
	res := result.new(
		"Account does not enforce HTTPS.",
		object.get(account, "enforcehttps", account),
	)
}
