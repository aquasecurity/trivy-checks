# METADATA
# title: CloudFront distribution uses outdated SSL/TLS protocols.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
#   Note: that setting *minimum_protocol_version = "TLSv1.2_2021"* is only possible when *cloudfront_default_certificate* is false (eg. you are not using the cloudfront.net domain name).
#   If *cloudfront_default_certificate* is true then the Cloudfront API will only allow setting *minimum_protocol_version = "TLSv1"*, and setting it to any other value will result in a perpetual diff in your *terraform plan*'s.
#   The only option when using the cloudfront.net domain name is to ignore this rule.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html
#   - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesGeneral
# custom:
#   id: AVD-AWS-0013
#   avd_id: AVD-AWS-0013
#   provider: aws
#   service: cloudfront
#   severity: HIGH
#   short_code: use-secure-tls-policy
#   recommended_action: Use the most modern TLS/SSL policies available
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudfront
#             provider: aws
#   examples: checks/cloud/aws/cloudfront/use_secure_tls_policy.yaml
package builtin.aws.cloudfront.aws0013

import rego.v1

protocol_version_tls1_2_2021 := "TLSv1.2_2021"

import data.lib.cloud.metadata

deny contains res if {
	some dist in input.aws.cloudfront.distributions
	not dist.viewercertificate.cloudfrontdefaultcertificate.value
	not is_tls_1_2(dist)
	res := result.new(
		"Distribution allows unencrypted communications.",
		metadata.obj_by_path(dist, ["viewercertificate", "minimumprotocolversion"]),
	)
}

is_tls_1_2(dist) := dist.viewercertificate.minimumprotocolversion.value == protocol_version_tls1_2_2021
