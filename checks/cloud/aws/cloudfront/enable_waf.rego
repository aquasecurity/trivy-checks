# METADATA
# title: CloudFront distribution does not have a WAF in front.
# description: |
#   You should configure a Web Application Firewall in front of your CloudFront distribution. This will mitigate many types of attacks on your web application.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html
# custom:
#   id: AVD-AWS-0011
#   avd_id: AVD-AWS-0011
#   provider: aws
#   service: cloudfront
#   severity: HIGH
#   short_code: enable-waf
#   recommended_action: Enable WAF for the CloudFront distribution
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudfront
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#web_acl_id
#     good_examples: checks/cloud/aws/cloudfront/enable_waf.tf.go
#     bad_examples: checks/cloud/aws/cloudfront/enable_waf.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/cloudfront/enable_waf.cf.go
#     bad_examples: checks/cloud/aws/cloudfront/enable_waf.cf.go
package builtin.aws.cloudfront.aws0011

import rego.v1

deny contains res if {
	some dist in input.aws.cloudfront.distributions
	not is_waf_enabled(dist)
	res := result.new(
		"Distribution does not utilise a WAF.",
		object.get(dist, "wafid", dist),
	)
}

is_waf_enabled(dist) := dist.wafid.value != ""
