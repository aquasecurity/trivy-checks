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
#   aliases:
#     - aws-elasticache-enable-at-rest-encryption
#   avd_id: AVD-AWS-0045
#   provider: aws
#   service: elasticache
#   severity: HIGH
#   short_code: enable-at-rest-encryption
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
