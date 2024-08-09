# METADATA
# title: DocumentDB encryption should use Customer Managed Keys
# description: |
#   Using AWS managed keys does not allow for fine grained control. Encryption using AWS keys provides protection for your DocumentDB underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.public-key.html
# custom:
#   id: AVD-AWS-0022
#   avd_id: AVD-AWS-0022
#   provider: aws
#   service: documentdb
#   severity: LOW
#   short_code: encryption-customer-key
#   recommended_action: Enable encryption using customer managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: documentdb
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#kms_key_id
#     good_examples: checks/cloud/aws/documentdb/encryption_customer_key.tf.go
#     bad_examples: checks/cloud/aws/documentdb/encryption_customer_key.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/documentdb/encryption_customer_key.cf.go
#     bad_examples: checks/cloud/aws/documentdb/encryption_customer_key.cf.go
package builtin.aws.documentdb.aws0022

import rego.v1

deny contains res if {
	some cluster in input.aws.documentdb.clusters
	cluster.kmskeyid.value == ""

	res := result.new("Cluster encryption does not use a customer-managed KMS key.", cluster)
}

deny contains res if {
	some cluster in input.aws.documentdb.clusters
	some instance in cluster.instances
	instance.kmskeyid.value == ""

	res := result.new("Instance encryption does not use a customer-managed KMS key.", cluster)
}
