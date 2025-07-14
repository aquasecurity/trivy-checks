# METADATA
# title: Elasticache Replication Group uses unencrypted traffic.
# description: |
#   Traffic flowing between Elasticache replication nodes should be encrypted to ensure sensitive data is kept private.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html
# custom:
#   id: AWS-0051
#   aliases:
#     - AVD-AWS-0051
#     - enable-in-transit-encryption
#   long_id: aws-elasticache-enable-in-transit-encryption
#   provider: aws
#   service: elasticache
#   severity: HIGH
#   recommended_action: Enable in transit encryption for replication group
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticache
#             provider: aws
#   examples: checks/cloud/aws/elasticache/enable_in_transit_encryption.yaml
package builtin.aws.elasticache.aws0051

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some group in input.aws.elasticache.replicationgroups
	not group.transitencryptionenabled.value
	res := result.new(
		"Replication group does not have transit encryption enabled.",
		metadata.obj_by_path(group, ["transitencryptionenabled"]),
	)
}
