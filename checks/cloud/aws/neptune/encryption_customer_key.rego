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
#   id: AWS-0128
#   aliases:
#     - AVD-AWS-0128
#     - encryption-customer-key
#   long_id: aws-neptune-encryption-customer-key
#   provider: aws
#   service: neptune
#   severity: HIGH
#   recommended_action: Enable encryption using customer managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: neptune
#             provider: aws
#   examples: checks/cloud/aws/neptune/encryption_customer_key.yaml
package builtin.aws.neptune.aws0128

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.neptune.clusters
	without_cmk(cluster)
	res := result.new(
		"Cluster does not encrypt data with a customer managed key.",
		object.get(cluster, "kmskeyid", cluster),
	)
}

without_cmk(cluster) if value.is_empty(cluster.kmskeyid)

without_cmk(cluster) if not cluster.kmskeyid
