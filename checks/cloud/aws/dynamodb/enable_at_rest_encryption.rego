# METADATA
# title: DAX Cluster should always encrypt data at rest
# description: |
#   Data can be freely read if compromised. Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection by helping secure your data from unauthorized access to the underlying storage.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html
#   - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html
# custom:
#   id: AWS-0023
#   aliases:
#     - AVD-AWS-0023
#     - enable-at-rest-encryption
#   long_id: aws-dynamodb-enable-at-rest-encryption
#   provider: aws
#   service: dynamodb
#   severity: HIGH
#   recommended_action: Enable encryption at rest for DAX Cluster
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: dynamodb
#             provider: aws
#   examples: checks/cloud/aws/dynamodb/enable_at_rest_encryption.yaml
package builtin.aws.dynamodb.aws0023

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.dynamodb.daxclusters
	not_encrypted(cluster)

	res := result.new(
		"DAX encryption is not enabled.",
		metadata.obj_by_path(cluster, ["serversideencryption", "enabled"]),
	)
}

not_encrypted(cluster) if value.is_false(cluster.serversideencryption.enabled)

not_encrypted(cluster) if not cluster.serversideencryption.enabled
