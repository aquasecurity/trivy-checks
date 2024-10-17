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
#   id: AVD-AWS-0051
#   avd_id: AVD-AWS-0051
#   provider: aws
#   service: elasticache
#   severity: HIGH
#   short_code: enable-in-transit-encryption
#   recommended_action: Enable in transit encryption for replication group
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticache
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#transit_encryption_enabled
#     good_examples: checks/cloud/aws/elasticache/enable_in_transit_encryption.yaml
#     bad_examples: checks/cloud/aws/elasticache/enable_in_transit_encryption.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/elasticache/enable_in_transit_encryption.yaml
#     bad_examples: checks/cloud/aws/elasticache/enable_in_transit_encryption.yaml
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
