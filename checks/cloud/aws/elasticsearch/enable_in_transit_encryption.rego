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
#   id: AWS-0043
#   aliases:
#     - AVD-AWS-0043
#     - enable-in-transit-encryption
#   long_id: aws-elasticsearch-enable-in-transit-encryption
#   provider: aws
#   service: elasticsearch
#   severity: HIGH
#   recommended_action: Enable encrypted node to node communication
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticsearch
#             provider: aws
#   examples: checks/cloud/aws/elasticsearch/enable_in_transit_encryption.yaml
package builtin.aws.elasticsearch.aws0043

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	not domain.transitencryption.enabled.value
	res := result.new(
		"Domain does not have in-transit encryption enabled.",
		metadata.obj_by_path(domain, ["transitencryption", "enabled"]),
	)
}
