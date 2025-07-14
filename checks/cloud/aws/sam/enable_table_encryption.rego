# METADATA
# title: SAM Simple table must have server side encryption enabled.
# description: |
#   Encryption should be enabled at all available levels to ensure that data is protected if compromised.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-simpletable.html#sam-simpletable-ssespecification
# custom:
#   id: AWS-0121
#   aliases:
#     - AVD-AWS-0121
#     - enable-table-encryption
#   long_id: aws-sam-enable-table-encryption
#   provider: aws
#   service: sam
#   severity: HIGH
#   recommended_action: Enable server side encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   examples: checks/cloud/aws/sam/enable_table_encryption.yaml
package builtin.aws.sam.aws0121

import rego.v1

deny contains res if {
	some table in input.aws.sam.simpletables
	not table.ssespecification.enabled.value
	res := result.new(
		"Domain name is configured with an outdated TLS policy.",
		table.ssespecification.enabled,
	)
}
