# METADATA
# title: Elasticsearch domain isn't encrypted at rest.
# description: |
#   You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html
# custom:
#   id: AVD-AWS-0048
#   avd_id: AVD-AWS-0048
#   provider: aws
#   service: elasticsearch
#   severity: HIGH
#   short_code: enable-domain-encryption
#   recommended_action: Enable ElasticSearch domain encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticsearch
#             provider: aws
#   examples: checks/cloud/aws/elasticsearch/enable_domain_encryption.yaml
package builtin.aws.elasticsearch.aws0048

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	not domain.atrestencryption.enabled.value
	res := result.new(
		"Domain does not have at-rest encryption enabled.",
		metadata.obj_by_path(domain, ["atrestencryption", "enabled"]),
	)
}
