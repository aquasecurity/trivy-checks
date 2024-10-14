# METADATA
# title: A MSK cluster allows unencrypted data at rest.
# description: |
#   Encryption should be forced for Kafka clusters, including at rest. This ensures sensitive data is kept private.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html
# custom:
#   id: AVD-AWS-0179
#   avd_id: AVD-AWS-0179
#   provider: aws
#   service: msk
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: Enable at rest encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: msk
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference
#     good_examples: checks/cloud/aws/msk/enable_at_rest_encryption.yaml
#     bad_examples: checks/cloud/aws/msk/enable_at_rest_encryption.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/msk/enable_at_rest_encryption.yaml
#     bad_examples: checks/cloud/aws/msk/enable_at_rest_encryption.yaml
package builtin.aws.msk.aws0179

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.aws.msk.clusters
	not cluster.encryptionatrest.enabled.value
	res := result.new(
		"The cluster is not encrypted at rest.",
		metadata.obj_by_path(cluster, ["encryptionatrest", "enabled"]),
	)
}
