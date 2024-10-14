# METADATA
# title: Redis cluster should have backup retention turned on
# description: |
#   Redis clusters should have a snapshot retention time to ensure that they are backed up and can be restored if required.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html
# custom:
#   id: AVD-AWS-0050
#   avd_id: AVD-AWS-0050
#   provider: aws
#   service: elasticache
#   severity: MEDIUM
#   short_code: enable-backup-retention
#   recommended_action: Configure snapshot retention for redis cluster
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticache
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#snapshot_retention_limit
#     good_examples: checks/cloud/aws/elasticache/enable_backup_retention.yaml
#     bad_examples: checks/cloud/aws/elasticache/enable_backup_retention.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/elasticache/enable_backup_retention.yaml
#     bad_examples: checks/cloud/aws/elasticache/enable_backup_retention.yaml
package builtin.aws.elasticache.aws0050

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.elasticache.clusters
	cluster.engine.value == "redis"
	value.is_not_equal(cluster.nodetype, "cache.t1.micro")
	value.is_equal(cluster.snapshotretentionlimit, 0)
	res := result.new("Cluster snapshot retention is not enabled.", cluster.snapshotretentionlimit)
}
