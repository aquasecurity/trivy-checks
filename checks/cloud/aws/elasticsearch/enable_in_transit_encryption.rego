# METADATA
# title: Elasticsearch domain uses plaintext traffic for node to node communication.
# description: |
#   Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html
# custom:
#   id: AVD-AWS-0043
#   avd_id: AVD-AWS-0043
#   provider: aws
#   service: elasticsearch
#   severity: HIGH
#   short_code: enable-in-transit-encryption
#   recommended_action: Enable encrypted node to node communication
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticsearch
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest
#     good_examples: checks/cloud/aws/elasticsearch/enable_in_transit_encryption.tf.go
#     bad_examples: checks/cloud/aws/elasticsearch/enable_in_transit_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/elasticsearch/enable_in_transit_encryption.cf.go
#     bad_examples: checks/cloud/aws/elasticsearch/enable_in_transit_encryption.cf.go
package builtin.aws.elasticsearch.aws0043

import rego.v1

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	domain.transitencryption.enabled.value == false
	res := result.new("Domain does not have in-transit encryption enabled.", domain.transitencryption.enabled)
}
