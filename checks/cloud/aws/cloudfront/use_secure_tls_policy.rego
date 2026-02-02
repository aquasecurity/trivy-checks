# METADATA
# title: CloudFront distribution uses outdated SSL/TLS protocols.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using the latest TLS policies available.
#   Note: that setting *minimum_protocol_version = "TLSv1.2_2025"* is only possible when *cloudfront_default_certificate* is false (eg. you are not using the cloudfront.net domain name).
#   If *cloudfront_default_certificate* is true then the Cloudfront API will only allow setting *minimum_protocol_version = "TLSv1"*, and setting it to any other value will result in a perpetual diff in your *terraform plan*'s.
#   The only option when using the cloudfront.net domain name is to ignore this rule.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html
#   - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesGeneral
# custom:
#   id: AWS-0013
#   long_id: aws-cloudfront-use-secure-tls-policy
#   aliases:
#     - AVD-AWS-0013
#     - use-secure-tls-policy
#     - aws-cloudfront-use-secure-tls-policy
#   provider: aws
#   service: cloudfront
#   severity: HIGH
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

protocol_version_tls1_2_2025 := "TLSv1.2_2025"
protocol_version_tls1_3_2025 := "TLSv1.3_2025"

allowed_minimum_protocol_versions := {
	protocol_version_tls1_2_2025,
	protocol_version_tls1_3_2025,
}

import data.lib.cloud.metadata

deny contains res if {
	some dist in input.aws.cloudfront.distributions
	not dist.viewercertificate.cloudfrontdefaultcertificate.value
	not has_allowed_minimum_protocol_version(dist)
	res := result.new(
		"Distribution uses an insecure minimum TLS protocol version.",
		metadata.obj_by_path(dist, ["viewercertificate", "minimumprotocolversion"]),
	)
}

has_allowed_minimum_protocol_version(dist) := dist.viewercertificate.minimumprotocolversion.value in allowed_minimum_protocol_versions
