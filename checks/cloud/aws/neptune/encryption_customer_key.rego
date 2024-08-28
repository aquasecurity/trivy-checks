# METADATA
# title: Neptune encryption should use Customer Managed Keys
# description: |
#   Encryption using AWS keys provides protection for your Neptune underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html
# custom:
#   id: AVD-AWS-0128
#   avd_id: AVD-AWS-0128
#   provider: aws
#   service: neptune
#   severity: HIGH
#   short_code: encryption-customer-key
#   recommended_action: Enable encryption using customer managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: neptune
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#storage_encrypted
#     good_examples: checks/cloud/aws/neptune/encryption_customer_key.tf.go
#     bad_examples: checks/cloud/aws/neptune/encryption_customer_key.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/neptune/encryption_customer_key.cf.go
#     bad_examples: checks/cloud/aws/neptune/encryption_customer_key.cf.go
package builtin.aws.neptune.aws0128

import rego.v1

deny contains res if {
	some cluster in input.aws.neptune.clusters
	not has_kms_key(cluster)
	res := result.new(
		"Cluster does not encrypt data with a customer managed key.",
		object.get(cluster, "kmskeyid", cluster),
	)
}

has_kms_key(cluster) if cluster.kmskeyid.value != ""
