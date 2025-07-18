# METADATA
# title: DocumentDB storage must be encrypted
# description: |
#   Unencrypted sensitive data is vulnerable to compromise. Encryption of the underlying storage used by DocumentDB ensures that if their is compromise of the disks, the data is still protected.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html
# custom:
#   id: AWS-0021
#   aliases:
#     - AVD-AWS-0021
#     - enable-storage-encryption
#   long_id: aws-documentdb-enable-storage-encryption
#   provider: aws
#   service: documentdb
#   severity: HIGH
#   recommended_action: Enable storage encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: documentdb
#             provider: aws
#   examples: checks/cloud/aws/documentdb/enable_storage_encryption.yaml
package builtin.aws.documentdb.aws0021

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.aws.documentdb.clusters
	not cluster.storageencrypted.value
	res := result.new(
		"Cluster storage does not have encryption enabled.",
		metadata.obj_by_path(cluster, ["storageencrypted"]),
	)
}
