# METADATA
# title: Storage containers in blob storage mode should not have public access
# description: |
#   Storage container public access should be off. It can be configured for blobs only, containers and blobs or off entirely. The default is off, with no public access.
#   Explicitly overriding publicAccess to anything other than off should be avoided.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal#set-the-public-access-level-for-a-container
# custom:
#   id: AZU-0007
#   aliases:
#     - AVD-AZU-0007
#     - no-public-access
#   long_id: azure-storage-no-public-access
#   provider: azure
#   service: storage
#   severity: HIGH
#   recommended_action: Disable public access to storage containers
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/no_public_access.yaml
package builtin.azure.storage.azure0007

import rego.v1

deny contains res if {
	some account in input.azure.storage.accounts
	some container in account.containers
	container.publicaccess.value != "off"

	res := result.new(
		"Container allows public access.",
		container.publicaccess,
	)
}
