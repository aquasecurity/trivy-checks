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
#   id: AWS-0112
#   long_id: aws-sam-api-use-secure-tls-policy
#   aliases:
#     - AVD-AWS-0112
#     - api-use-secure-tls-policy
#     - aws-sam-api-use-secure-tls-policy
#   provider: aws
#   service: sam
#   severity: HIGH
#   recommended_action: Use the most modern TLS/SSL policies available
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   examples: checks/cloud/aws/sam/api_use_secure_tls_policy.yaml
package builtin.aws.sam.aws0112

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some api in input.aws.sam.apis
	not is_secure_tls_policy(api)
	res := result.new(
		"Domain name is configured with an outdated TLS policy.",
		metadata.obj_by_path(api, ["domainconfiguration", "securitypolicy"]),
	)
}

# Every SecurityPolicy value accepted by AWS::ApiGateway::DomainName except
# TLS_1_0, which is the only one that permits TLS 1.0. The rest negotiate
# TLS 1.2 or higher, so flagging them as "outdated" is a false positive.
#
# This is an allow list rather than a deny list on TLS_1_0 so that a policy
# AWS introduces later is reported until it has been reviewed, instead of
# being silently accepted.
secure_tls_policies := {
	"TLS_1_2",
	"SecurityPolicy_TLS13_1_3_2025_09",
	"SecurityPolicy_TLS13_1_3_FIPS_2025_09",
	"SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_2021_06",
	"SecurityPolicy_TLS13_2025_EDGE",
	"SecurityPolicy_TLS12_PFS_2025_EDGE",
	"SecurityPolicy_TLS12_2018_EDGE",
}

is_secure_tls_policy(api) if api.domainconfiguration.securitypolicy.value in secure_tls_policies
