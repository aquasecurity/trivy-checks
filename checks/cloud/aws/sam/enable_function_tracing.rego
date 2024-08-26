# METADATA
# title: SAM Function must have X-Ray tracing enabled
# description: |
#   X-Ray tracing enables end-to-end debugging and analysis of the function.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-tracing
# custom:
#   id: AVD-AWS-0125
#   avd_id: AVD-AWS-0125
#   provider: aws
#   service: sam
#   severity: LOW
#   short_code: enable-function-tracing
#   recommended_action: Enable tracing
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   cloudformation:
#     good_examples: checks/cloud/aws/sam/enable_function_tracing.cf.go
#     bad_examples: checks/cloud/aws/sam/enable_function_tracing.cf.go
package builtin.aws.sam.aws0125

import rego.v1

tracing_mode_active := "Active"

deny contains res if {
	some fn in input.aws.sam.functions
	isManaged(fn)
	fn.tracing.value != tracing_mode_active
	res := result.new(
		"X-Ray tracing is not enabled",
		fn.tracing,
	)
}
