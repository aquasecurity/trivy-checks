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
#   examples: checks/cloud/aws/dynamodb/enable_recovery.yaml
package builtin.aws.dynamodb.aws0024

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.dynamodb.daxclusters
	recovery_is_not_enabled(cluster)
	res := result.new(
		"Point-in-time recovery is not enabled.",
		metadata.obj_by_path(cluster, ["pointintimerecovery"]),
	)
}

deny contains res if {
	some table in input.aws.dynamodb.tables
	recovery_is_not_enabled(table)
	res := result.new(
		"Point-in-time recovery is not enabled.",
		metadata.obj_by_path(table, ["pointintimerecovery"]),
	)
}

recovery_is_not_enabled(obj) if value.is_false(obj.pointintimerecovery)

recovery_is_not_enabled(obj) if not obj.pointintimerecovery
