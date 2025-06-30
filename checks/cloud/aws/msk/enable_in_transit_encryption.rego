# METADATA
# title: A MSK cluster allows unencrypted data in transit.
# description: |
#   Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html
# custom:
#   id: AVD-AWS-0073
#   avd_id: AVD-AWS-0073
#   provider: aws
#   service: msk
#   severity: HIGH
#   short_code: enable-in-transit-encryption
#   recommended_action: Enable in transit encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: msk
#             provider: aws
#   examples: checks/cloud/aws/msk/enable_in_transit_encryption.yaml
package builtin.aws.msk.aws0073

import rego.v1

deny contains res if {
	some cluster in input.aws.msk.clusters
	cluster.encryptionintransit.clientbroker.value in {"PLAINTEXT", "TLS_PLAINTEXT"}
	res := result.new(
		"Cluster allows plaintext communication.",
		cluster.encryptionintransit.clientbroker,
	)
}
