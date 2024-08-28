# METADATA
# title: API Gateway must have X-Ray tracing enabled
# description: |
#   X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AWS-0003
#   avd_id: AVD-AWS-0003
#   provider: aws
#   service: apigateway
#   severity: LOW
#   short_code: enable-tracing
#   recommended_action: Enable tracing
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage#xray_tracing_enabled
#     good_examples: checks/cloud/aws/apigateway/enable_tracing.tf.go
#     bad_examples: checks/cloud/aws/apigateway/enable_tracing.tf.go
package builtin.aws.apigateway.aws0003

import rego.v1

deny contains res if {
	some api in input.aws.apigateway.v1.apis
	isManaged(api)
	some stage in api.stages
	isManaged(stage)
	not stage.xraytracingenabled.value
	res := result.new(
		"X-Ray tracing is not enabled.",
		object.get(stage, "xraytracingenabled", stage),
	)
}
