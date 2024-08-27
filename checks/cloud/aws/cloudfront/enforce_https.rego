# METADATA
# title: CloudFront distribution allows unencrypted (HTTP) communications.
# description: |
#   Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.
#   You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html
# custom:
#   id: AVD-AWS-0012
#   avd_id: AVD-AWS-0012
#   provider: aws
#   service: cloudfront
#   severity: CRITICAL
#   short_code: enforce-https
#   recommended_action: Only allow HTTPS for CloudFront distribution communication
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudfront
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy
#     good_examples: checks/cloud/aws/cloudfront/enforce_https.tf.go
#     bad_examples: checks/cloud/aws/cloudfront/enforce_https.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/cloudfront/enforce_https.cf.go
#     bad_examples: checks/cloud/aws/cloudfront/enforce_https.cf.go
package builtin.aws.cloudfront.aws0012

import rego.v1

viewer_protocol_policy_allow_all := "allow-all"

deny contains res if {
	some cachebehavior in input.aws.cloudfront.distributions[_]
	cachebehavior.viewerprotocolpolicy.value == viewer_protocol_policy_allow_all
	res := result.new("Distribution allows unencrypted communications.", cachebehavior.viewerprotocolpolicy)
}

deny contains res if {
	some cachebehavior in input.aws.cloudfront.distributions[_].orderercachebehaviours
	cachebehavior.viewerprotocolpolicy.value == viewer_protocol_policy_allow_all
	res := result.new("Distribution allows unencrypted communications.", cachebehavior.viewerprotocolpolicy)
}
