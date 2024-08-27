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
#   id: AVD-AWS-0001
#   avd_id: AVD-AWS-0001
#   provider: aws
#   service: apigateway
#   severity: MEDIUM
#   short_code: enable-access-logging
#   recommended_action: Enable logging for API Gateway stages
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/apigatewayv2_stage#access_log_settings
#     good_examples: checks/cloud/aws/apigateway/enable_access_logging.tf.go
#     bad_examples: checks/cloud/aws/apigateway/enable_access_logging.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/apigateway/enable_access_logging.cf.go
#     bad_examples: checks/cloud/aws/apigateway/enable_access_logging.cf.go
package builtin.aws.apigateway.aws0001

import rego.v1

deny contains res if {
	some stage in input.aws.apigateway.v1.apis[_].stages
	not logging_is_configured(stage)
	res := result.new("Access logging is not configured.", stage.accesslogging.cloudwatchloggrouparn)
}

deny contains res if {
	some stage in input.aws.apigateway.v2.apis[_].stages
	not logging_is_configured(stage)
	res := result.new("Access logging is not configured.", stage.accesslogging.cloudwatchloggrouparn)
}

logging_is_configured(stage) if {
	isManaged(stage)
	stage.accesslogging.cloudwatchloggrouparn.value != ""
}
