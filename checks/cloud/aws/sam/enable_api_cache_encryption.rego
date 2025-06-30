# METADATA
# title: SAM API must have data cache enabled
# description: |
#   Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-stage-methodsetting.html#cfn-apigateway-stage-methodsetting-cachedataencrypted
# custom:
#   id: AVD-AWS-0110
#   avd_id: AVD-AWS-0110
#   provider: aws
#   service: sam
#   severity: MEDIUM
#   short_code: enable-api-cache-encryption
#   recommended_action: Enable cache encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   examples: checks/cloud/aws/sam/enable_api_cache_encryption.yaml
package builtin.aws.sam.aws0110

import rego.v1

deny contains res if {
	some api in input.aws.sam.apis
	isManaged(api)
	not api.restmethodsettings.cachedataencrypted.value
	res := result.new(
		"Cache data is not encrypted.",
		api.restmethodsettings.cachedataencrypted,
	)
}
