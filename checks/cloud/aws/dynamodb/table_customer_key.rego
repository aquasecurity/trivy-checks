# METADATA
# title: DynamoDB tables should use at rest encryption with a Customer Managed Key
# description: |
#   Using AWS managed keys does not allow for fine grained control. DynamoDB tables are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html
# custom:
#   id: AVD-AWS-0025
#   avd_id: AVD-AWS-0025
#   provider: aws
#   service: dynamodb
#   severity: LOW
#   short_code: table-customer-key
#   recommended_action: Enable server side encryption with a customer managed key
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: dynamodb
#             provider: aws
#   examples: checks/cloud/aws/dynamodb/table_customer_key.yaml
package builtin.aws.dynamodb.aws0025

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some table in input.aws.dynamodb.tables
	not_encrypted(table)
	res := result.new(
		"Table encryption does not use a customer-managed KMS key.",
		metadata.obj_by_path(table, ["serversideencryption", "enabled"]),
	)
}

deny contains res if {
	some table in input.aws.dynamodb.tables
	table.serversideencryption.enabled.value
	non_valid_key(table)
	res := result.new("Table encryption explicitly uses the default KMS key.", table.serversideencryption.kmskeyid)
}

not_encrypted(table) if value.is_false(table.serversideencryption.enabled)

not_encrypted(table) if not table.serversideencryption.enabled

non_valid_key(table) if value.is_empty(table.serversideencryption.kmskeyid)

non_valid_key(table) if value.is_equal(table.serversideencryption.kmskeyid, "alias/aws/dynamodb")

non_valid_key(table) if not table.serversideencryption.kmskeyid
