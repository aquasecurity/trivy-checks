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
#   id: AVD-AWS-0045
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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#at_rest_encryption_enabled
#     good_examples: checks/cloud/aws/elasticache/enable_at_rest_encryption.tf.go
#     bad_examples: checks/cloud/aws/elasticache/enable_at_rest_encryption.tf.go
package builtin.aws.elasticache.aws0045

import rego.v1

deny contains res if {
	some group in input.aws.elasticache.replicationgroups
	group.atrestencryptionenabled.value == false
	res := result.new("Replication group does not have at-rest encryption enabled.", group.atrestencryptionenabled)
}
