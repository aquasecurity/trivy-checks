# METADATA
# title: API Gateway must have X-Ray tracing enabled
# description: |
#   X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AWS-0003
#   aliases:
#     - AVD-AWS-0003
#     - enable-tracing
#   long_id: aws-apigateway-enable-tracing
#   provider: aws
#   service: apigateway
#   severity: LOW
#   recommended_action: Enable tracing
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
#   examples: checks/cloud/aws/apigateway/enable_tracing.yaml
package builtin.aws.apigateway.aws0003

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some api in input.aws.apigateway.v1.apis
	isManaged(api)
	some stage in api.stages
	isManaged(stage)
	tracing_is_not_enabled(stage)
	res := result.new(
		"X-Ray tracing is not enabled.",
		metadata.obj_by_path(stage, ["xraytracingenabled"]),
	)
}

tracing_is_not_enabled(stage) if value.is_false(stage.xraytracingenabled)

tracing_is_not_enabled(stage) if not stage.xraytracingenabled
