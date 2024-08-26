# METADATA
# title: SAM HTTP API stages for V1 and V2 should have access logging enabled
# description: |
#   API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-httpapi.html#sam-httpapi-accesslogsettings
# custom:
#   id: AVD-AWS-0116
#   avd_id: AVD-AWS-0116
#   provider: aws
#   service: sam
#   severity: MEDIUM
#   short_code: enable-http-api-access-logging
#   recommended_action: Enable logging for API Gateway stages
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   cloudformation:
#     good_examples: checks/cloud/aws/sam/enable_http_api_access_logging.cf.go
#     bad_examples: checks/cloud/aws/sam/enable_http_api_access_logging.cf.go
package builtin.aws.sam.aws0116

import rego.v1

deny contains res if {
	some api in input.aws.sam.httpapis
	isManaged(api)
	api.accesslogging.cloudwatchloggrouparn.value == ""
	res := result.new(
		"Access logging is not configured.",
		api.accesslogging,
	)
}
