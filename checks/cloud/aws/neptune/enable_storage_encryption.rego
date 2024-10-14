# METADATA
# title: Neptune storage must be encrypted at rest
# description: |
#   Encryption of Neptune storage ensures that if their is compromise of the disks, the data is still protected.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html
# custom:
#   id: AVD-AWS-0076
#   avd_id: AVD-AWS-0076
#   provider: aws
#   service: neptune
#   severity: HIGH
#   short_code: enable-storage-encryption
#   recommended_action: Enable encryption of Neptune storage
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: neptune
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#storage_encrypted
#     good_examples: checks/cloud/aws/neptune/enable_storage_encryption.yaml
#     bad_examples: checks/cloud/aws/neptune/enable_storage_encryption.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/neptune/enable_storage_encryption.yaml
#     bad_examples: checks/cloud/aws/neptune/enable_storage_encryption.yaml
package builtin.aws.neptune.aws0076

import rego.v1

deny contains res if {
	some cluster in input.aws.neptune.clusters
	not cluster.storageencrypted.value
	res := result.new(
		"Cluster does not have storage encryption enabled.",
		object.get(cluster, "storageencrypted", cluster),
	)
}
