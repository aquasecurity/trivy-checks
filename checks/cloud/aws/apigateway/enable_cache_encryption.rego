# METADATA
# title: API Gateway must have cache enabled
# description: |
#   Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AWS-0002
#   avd_id: AVD-AWS-0002
#   provider: aws
#   service: apigateway
#   severity: MEDIUM
#   short_code: enable-cache-encryption
#   recommended_action: Enable cache encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings#cache_data_encrypted
#     good_examples: checks/cloud/aws/apigateway/enable_cache_encryption.yaml
#     bad_examples: checks/cloud/aws/apigateway/enable_cache_encryption.yaml
package builtin.aws.apigateway.aws0002

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some api in input.aws.apigateway.v1.apis
	isManaged(api)
	some stage in api.stages
	isManaged(stage)
	some settings in stage.restmethodsettings
	isManaged(settings)
	settings.cacheenabled.value
	cache_is_not_encrypted(settings)

	res := result.new(
		"Cache data is not encrypted.",
		metadata.obj_by_path(settings, ["cachedataencrypted"]),
	)
}

cache_is_not_encrypted(settings) if value.is_false(settings.cachedataencrypted)

cache_is_not_encrypted(settings) if not settings.cachedataencrypted
