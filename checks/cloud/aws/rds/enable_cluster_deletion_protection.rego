# METADATA
# title: "RDS Cluster Deletion Protection Disabled"
# description: "Ensure deletion protection is enabled for RDS clusters."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/config/latest/developerguide/rds-cluster-deletion-protection-enabled.html
# custom:
#   aliases:
#     - aws-rds-enable-cluster-deletion-protection
#   id: AWS-0343
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   long_id: aws-rds-enable-cluster-deletion-protection
#   recommended_action: "Modify the RDS clusters to enable deletion protection."
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: rds
#           provider: aws
package builtin.aws.rds.aws0343

import rego.v1

deny contains res if {
	cluster := input.aws.rds.clusters[_]
	isManaged(cluster.deletionprotection)
	not cluster.deletionprotection.value
	res := result.new("Cluster does not have Deletion Protection enabled", cluster.deletionprotection)
}
