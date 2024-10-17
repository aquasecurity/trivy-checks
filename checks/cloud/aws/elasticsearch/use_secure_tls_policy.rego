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
#   id: AVD-AWS-0126
#   avd_id: AVD-AWS-0126
#   provider: aws
#   service: elasticsearch
#   severity: HIGH
#   short_code: use-secure-tls-policy
#   recommended_action: Use the most modern TLS/SSL policies available
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticsearch
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#tls_security_policy
#     good_examples: checks/cloud/aws/elasticsearch/use_secure_tls_policy.yaml
#     bad_examples: checks/cloud/aws/elasticsearch/use_secure_tls_policy.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/elasticsearch/use_secure_tls_policy.yaml
#     bad_examples: checks/cloud/aws/elasticsearch/use_secure_tls_policy.yaml
package builtin.aws.elasticsearch.aws0126

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	not is_tls_policy_secure(domain)
	res := result.new(
		"Domain does not have a secure TLS policy.",
		metadata.obj_by_path(domain, ["endpoint", "tlspolicy"]),
	)
}

is_tls_policy_secure(domain) if domain.endpoint.tlspolicy.value == "Policy-Min-TLS-1-2-2019-07"
