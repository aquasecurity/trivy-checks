# METADATA
# title: Ensure that response caching is enabled for your Amazon API Gateway REST APIs.
# description: |
#   A REST API in API Gateway is a collection of resources and methods that are integrated with backend HTTP endpoints, Lambda functions, or other AWS services. You can enable API caching in Amazon API Gateway to cache your endpoint responses. With caching, you can reduce the number of calls made to your endpoint and also improve the latency of requests to your API.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html
# custom:
#   id: AVD-AWS-0190
#   avd_id: AVD-AWS-0190
#   provider: aws
#   service: apigateway
#   severity: LOW
#   short_code: enable-cache
#   recommended_action: Enable cache
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings#cache_enabled
#     good_examples: checks/cloud/aws/apigateway/enable_cache.yaml
#     bad_examples: checks/cloud/aws/apigateway/enable_cache.yaml
package builtin.aws.apigateway.aws0190

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
	cache_is_not_enabled(settings)
	res := result.new(
		"Cache data is not enabled.",
		metadata.obj_by_path(settings, ["cacheenabled"]),
	)
}

cache_is_not_enabled(settings) if value.is_false(settings.cacheenabled)

cache_is_not_enabled(settings) if not settings.cacheenabled
