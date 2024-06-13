# METADATA
# title: Point in time recovery should be enabled to protect DynamoDB table
# description: |
#   DynamoDB tables should be protected against accidentally or malicious write/delete actions by ensuring that there is adequate protection.
#   By enabling point-in-time-recovery you can restore to a known point in the event of loss of data.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html
# custom:
#   id: AVD-AWS-0024
#   avd_id: AVD-AWS-0024
#   provider: aws
#   service: dynamodb
#   severity: MEDIUM
#   short_code: enable-recovery
#   recommended_action: Enable point in time recovery
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: dynamodb
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#point_in_time_recovery
#     good_examples: checks/cloud/aws/dynamodb/enable_recovery.tf.go
#     bad_examples: checks/cloud/aws/dynamodb/enable_recovery.tf.go
package builtin.aws.dynamodb.aws0024

import rego.v1

deny contains res if {
	some cluster in input.aws.dynamodb.daxclusters
	cluster.pointintimerecovery.value == false

	res := result.new("Point-in-time recovery is not enabled.", cluster.pointintimerecovery)
}

deny contains res if {
	some table in input.aws.dynamodb.tables
	table.pointintimerecovery.value == false

	res := result.new("Point-in-time recovery is not enabled.", table.pointintimerecovery)
}
