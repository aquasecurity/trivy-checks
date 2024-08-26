# METADATA
# title: SAM API must have X-Ray tracing enabled
# description: |
#   X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html#sam-api-tracingenabled
# custom:
#   id: AVD-AWS-0111
#   avd_id: AVD-AWS-0111
#   provider: aws
#   service: sam
#   severity: LOW
#   short_code: enable-api-tracing
#   recommended_action: Enable tracing
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   cloudformation:
#     good_examples: checks/cloud/aws/sam/enable_api_tracing.cf.go
#     bad_examples: checks/cloud/aws/sam/enable_api_tracing.cf.go
package builtin.aws.sam.aws0111

import rego.v1

deny contains res if {
	some api in input.aws.sam.apis
	isManaged(api)
	not api.tracingenabled.value
	res := result.new(
		"X-Ray tracing is not enabled",
		api.tracingenabled,
	)
}
