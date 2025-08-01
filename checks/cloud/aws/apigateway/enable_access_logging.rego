# METADATA
# title: API Gateway stages for V1 and V2 should have access logging enabled
# description: |
#   API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html
# custom:
#   id: AWS-0001
#   aliases:
#     - AVD-AWS-0001
#     - enable-access-logging
#   long_id: aws-apigateway-enable-access-logging
#   provider: aws
#   service: apigateway
#   severity: MEDIUM
#   recommended_action: Enable logging for API Gateway stages
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
#   examples: checks/cloud/aws/apigateway/enable_access_logging.yaml
package builtin.aws.apigateway.aws0001

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some stage in input.aws.apigateway.v1.apis[_].stages
	logging_is_not_configured(stage)
	res := result.new(
		"Access logging is not configured.",
		metadata.obj_by_path(stage, ["accesslogging", "cloudwatchloggrouparn"]),
	)
}

deny contains res if {
	some stage in input.aws.apigateway.v2.apis[_].stages
	logging_is_not_configured(stage)
	res := result.new(
		"Access logging is not configured.",
		metadata.obj_by_path(stage, ["accesslogging", "cloudwatchloggrouparn"]),
	)
}

logging_is_not_configured(stage) if {
	isManaged(stage)
	value.is_empty(stage.accesslogging.cloudwatchloggrouparn)
}

logging_is_not_configured(stage) if not stage.accesslogging.cloudwatchloggrouparn
