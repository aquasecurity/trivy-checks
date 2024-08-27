# METADATA
# title: No unauthorized access to API Gateway methods
# description: |
#   API Gateway methods should generally be protected by authorization or api key. OPTION verb calls can be used without authorization
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AWS-0004
#   avd_id: AVD-AWS-0004
#   provider: aws
#   service: apigateway
#   severity: LOW
#   short_code: no-public-access
#   recommended_action: Use and authorization method or require API Key
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method#authorization
#     good_examples: checks/cloud/aws/apigateway/no_public_access.tf.go
#     bad_examples: checks/cloud/aws/apigateway/no_public_access.tf.go
package builtin.aws.apigateway.aws0004

import rego.v1

authorization_none := "NONE"

deny contains res if {
	some api in input.aws.apigateway.v1.apis
	isManaged(api)
	some method in api.resources[_].methods
	not method_is_option(method)
	not is_apikey_required(api)
	method.authorizationtype.value == authorization_none
	res := result.new("Authorization is not enabled for this method.", method.authorizationtype)
}

method_is_option(method) := method.httpmethod.value == "OPTION"

is_apikey_required(api) := api.apikeyrequired.value
