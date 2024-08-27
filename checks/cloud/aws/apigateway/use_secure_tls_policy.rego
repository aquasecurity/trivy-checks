# METADATA
# title: API Gateway domain name uses outdated SSL/TLS protocols.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html
# custom:
#   id: AVD-AWS-0005
#   avd_id: AVD-AWS-0005
#   provider: aws
#   service: apigateway
#   severity: HIGH
#   short_code: use-secure-tls-policy
#   recommended_action: Use the most modern TLS/SSL policies available
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy
#     good_examples: checks/cloud/aws/apigateway/use_secure_tls_policy.tf.go
#     bad_examples: checks/cloud/aws/apigateway/use_secure_tls_policy.tf.go
package builtin.aws.apigateway.aws0005

import rego.v1

deny contains res if {
	some domain in input.aws.apigateway.v1.domainnames
	not is_tls_1_2(domain)
	res := result.new(
		"Domain name is configured with an outdated TLS policy.",
		object.get(domain, "securitypolicy", domain),
	)
}

deny contains res if {
	some domain in input.aws.apigateway.v2.domainnames
	not is_tls_1_2(domain)
	res := result.new(
		"Domain name is configured with an outdated TLS policy.",
		object.get(domain, "securitypolicy", domain),
	)
}

is_tls_1_2(domain) := domain.securitypolicy.value == "TLS_1_2"
