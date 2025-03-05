# METADATA
# title: Elasticsearch doesn't enforce HTTPS traffic.
# description: |
#   Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.
#   You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html
# custom:
#   id: AVD-AWS-0046
#   avd_id: AVD-AWS-0046
#   provider: aws
#   service: elasticsearch
#   severity: CRITICAL
#   short_code: enforce-https
#   recommended_action: Enforce the use of HTTPS for ElasticSearch
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticsearch
#             provider: aws
#   examples: checks/cloud/aws/elasticsearch/enforce_https.yaml
package builtin.aws.elasticsearch.aws0046

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	not domain.endpoint.enforcehttps.value
	res := result.new(
		"Domain does not enforce HTTPS.",
		metadata.obj_by_path(domain, ["endpoint", "enforcehttps"]),
	)
}
