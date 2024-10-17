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
#   id: AVD-AWS-0066
#   avd_id: AVD-AWS-0066
#   provider: aws
#   service: lambda
#   severity: LOW
#   short_code: enable-tracing
#   recommended_action: Enable tracing
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: lambda
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#mode
#     good_examples: checks/cloud/aws/lambda/enable_tracing.yaml
#     bad_examples: checks/cloud/aws/lambda/enable_tracing.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/lambda/enable_tracing.yaml
#     bad_examples: checks/cloud/aws/lambda/enable_tracing.yaml
package builtin.aws.lambda.aws0066

import rego.v1

deny contains res if {
	some func in input.aws.lambda.functions
	func.tracing.mode.value != "Active"
	res := result.new("Function does not have tracing enabled.", func.tracing.mode)
}
