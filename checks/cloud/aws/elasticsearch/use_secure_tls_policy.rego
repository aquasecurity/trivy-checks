# METADATA
# title: Elasticsearch domain endpoint is using outdated TLS policy.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html
# custom:
#   id: AWS-0126
#   long_id: aws-elasticsearch-use-secure-tls-policy
#   aliases:
#     - AVD-AWS-0126
#     - use-secure-tls-policy
#     - aws-elasticsearch-use-secure-tls-policy
#   provider: aws
#   service: elasticsearch
#   severity: HIGH
#   recommended_action: Use the most modern TLS/SSL policies available
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticsearch
#             provider: aws
#   examples: checks/cloud/aws/elasticsearch/use_secure_tls_policy.yaml
package builtin.aws.elasticsearch.aws0126

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	non_compliant_tls(domain)
	res := result.new(
		"Domain does not have a secure TLS policy.",
		metadata.obj_by_path(domain, ["endpoint", "tlspolicy"]),
	)
}

# A domain that declares no TLS policy at all cannot be shown to use a secure
# one, so it stays reported.
non_compliant_tls(domain) if not domain.endpoint.tlspolicy

# A policy that Trivy could not resolve carries no value to judge, so it is not
# reported: the scan sees a Terraform variable, not a weak configuration.
non_compliant_tls(domain) if {
	value.is_known(domain.endpoint.tlspolicy)
	not is_tls_policy_secure(domain)
}

# Match the policy families that guarantee TLS 1.2 or better rather than an
# exact list of names: AWS adds a dated policy per family, and an allowlist of
# names has to be edited every time one is introduced, which reported the
# strictest current policy as outdated. Policy-Min-TLS-1-0-2019-07 does not
# match any of these and stays reported.
secure_tls_policies := ["Policy-Min-TLS-1-2-*", "Policy-Min-TLS-1-3-*"]

is_tls_policy_secure(domain) if {
	some p in secure_tls_policies
	glob.match(p, [], domain.endpoint.tlspolicy.value)
}
