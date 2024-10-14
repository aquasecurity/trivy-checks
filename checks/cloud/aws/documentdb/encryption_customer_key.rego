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
#     good_examples: checks/cloud/aws/documentdb/encryption_customer_key.yaml
#     bad_examples: checks/cloud/aws/documentdb/encryption_customer_key.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/documentdb/encryption_customer_key.yaml
#     bad_examples: checks/cloud/aws/documentdb/encryption_customer_key.yaml
package builtin.aws.documentdb.aws0022

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.documentdb.clusters
	isManaged(cluster)
	without_cmk(cluster)
	res := result.new(
		"Cluster encryption does not use a customer-managed KMS key.",
		metadata.obj_by_path(cluster, ["kmskeyid"]),
	)
}

deny contains res if {
	some cluster in input.aws.documentdb.clusters
	some instance in cluster.instances
	isManaged(instance)
	without_cmk(instance)
	res := result.new(
		"Instance encryption does not use a customer-managed KMS key.",
		metadata.obj_by_path(instance, ["kmskeyid"]),
	)
}

without_cmk(obj) if value.is_empty(obj.kmskeyid)

without_cmk(obj) if not obj.kmskeyid
