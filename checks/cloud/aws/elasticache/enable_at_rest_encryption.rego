# METADATA
# title: Elasticache Replication Group stores unencrypted data at-rest.
# description: |
#   Data stored within an Elasticache replication node should be encrypted to ensure sensitive data is kept private.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html
# custom:
#   id: AWS-0045
#   aliases:
#     - AVD-AWS-0045
#     - enable-at-rest-encryption
#   long_id: aws-elasticache-enable-at-rest-encryption
#   provider: aws
#   service: elasticache
#   severity: HIGH
#   recommended_action: Enable at-rest encryption for replication group
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticache
#             provider: aws
#   examples: checks/cloud/aws/elasticache/enable_at_rest_encryption.yaml
package builtin.aws.elasticache.aws0045

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some group in input.aws.elasticache.replicationgroups
	not group.atrestencryptionenabled.value
	res := result.new(
		"Replication group does not have at-rest encryption enabled.",
		metadata.obj_by_path(group, ["atrestencryptionenabled"]),
	)
}
