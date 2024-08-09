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
#   id: AVD-AWS-0021
#   avd_id: AVD-AWS-0021
#   provider: aws
#   service: documentdb
#   severity: HIGH
#   short_code: enable-storage-encryption
#   recommended_action: Enable storage encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: documentdb
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#storage_encrypted
#     good_examples: checks/cloud/aws/documentdb/enable_storage_encryption.tf.go
#     bad_examples: checks/cloud/aws/documentdb/enable_storage_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/documentdb/enable_storage_encryption.cf.go
#     bad_examples: checks/cloud/aws/documentdb/enable_storage_encryption.cf.go
package builtin.aws.documentdb.aws0021

import rego.v1

deny contains res if {
	some cluster in input.aws.documentdb.clusters
	not cluster.storageencrypted.value
	res := result.new("Cluster storage does not have encryption enabled.", cluster.storageencrypted)
}
