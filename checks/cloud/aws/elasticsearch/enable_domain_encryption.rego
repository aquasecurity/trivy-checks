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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest
#     good_examples: checks/cloud/aws/elasticsearch/enable_domain_encryption.tf.go
#     bad_examples: checks/cloud/aws/elasticsearch/enable_domain_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/elasticsearch/enable_domain_encryption.cf.go
#     bad_examples: checks/cloud/aws/elasticsearch/enable_domain_encryption.cf.go
package builtin.aws.elasticsearch.aws0048

import rego.v1

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	domain.atrestencryption.enabled.value == false
	res := result.new(
		"Domain does not have at-rest encryption enabled.",
		domain.atrestencryption.enabled,
	)
}
