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
#   id: AWS-0179
#   aliases:
#     - AVD-AWS-0179
#     - enable-at-rest-encryption
#   long_id: aws-msk-enable-at-rest-encryption
#   provider: aws
#   service: msk
#   severity: HIGH
#   recommended_action: Enable at rest encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: msk
#             provider: aws
#   examples: checks/cloud/aws/msk/enable_at_rest_encryption.yaml
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
