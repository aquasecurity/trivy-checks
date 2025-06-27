# METADATA
# title: Lambda functions should have X-Ray tracing enabled
# description: |
#   X-Ray tracing enables end-to-end debugging and analysis of all function activity. This will allow for identifying bottlenecks, slow downs and timeouts.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html
# custom:
#   id: AWS-0066
#   aliases:
#     - AVD-AWS-0066
#     - enable-tracing
#   long_id: aws-lambda-enable-tracing
#   provider: aws
#   service: lambda
#   severity: LOW
#   recommended_action: Enable tracing
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: lambda
#             provider: aws
#   examples: checks/cloud/aws/lambda/enable_tracing.yaml
package builtin.aws.lambda.aws0066

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some func in input.aws.lambda.functions
	isManaged(func)
	not is_active_mode(func)
	res := result.new(
		"Function does not have tracing enabled.",
		metadata.obj_by_path(func, ["tracing", "mode"]),
	)
}

is_active_mode(func) if func.tracing.mode.value == "Active"
