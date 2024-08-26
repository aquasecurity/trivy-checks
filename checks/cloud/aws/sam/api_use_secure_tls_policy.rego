# METADATA
# title: SAM API domain name uses outdated SSL/TLS protocols.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-api-domainconfiguration.html#sam-api-domainconfiguration-securitypolicy
# custom:
#   id: AVD-AWS-0112
#   avd_id: AVD-AWS-0112
#   provider: aws
#   service: sam
#   severity: HIGH
#   short_code: api-use-secure-tls-policy
#   recommended_action: Use the most modern TLS/SSL policies available
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   cloudformation:
#     good_examples: checks/cloud/aws/sam/api_use_secure_tls_policy.cf.go
#     bad_examples: checks/cloud/aws/sam/api_use_secure_tls_policy.cf.go
package builtin.aws.sam.aws0112

import rego.v1

deny contains res if {
	some api in input.aws.sam.apis
	not is_secure_tls_policy(api.domainconfiguration)
	res := result.new(
		"Domain name is configured with an outdated TLS policy.",
		api.domainconfiguration.securitypolicy,
	)
}

is_secure_tls_policy(domainconfiguration) if domainconfiguration.securitypolicy.value == "TLS_1_2"
