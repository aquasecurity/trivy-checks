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
#   examples: checks/cloud/aws/apigateway/no_public_access.yaml
package builtin.aws.apigateway.aws0004

import rego.v1

import data.lib.cloud.value

authorization_none := "NONE"

deny contains res if {
	some api in input.aws.apigateway.v1.apis
	isManaged(api)
	some method in api.resources[_].methods
	method_is_not_option(method)
	apikey_is_not_required(method)
	method.authorizationtype.value == authorization_none
	res := result.new("Authorization is not enabled for this method.", method.authorizationtype)
}

method_is_not_option(method) if value.is_not_equal(method.httpmethod, "OPTION")

method_is_not_option(method) if not method.httpmethod

apikey_is_not_required(api) if value.is_false(api.apikeyrequired)

apikey_is_not_required(api) if not api.apikeyrequired
