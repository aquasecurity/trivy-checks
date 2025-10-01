# METADATA
# title: Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted
# description: |
#   Data can be read if the Athena Database is compromised. Athena databases and workspace result sets should be encrypted at rests. These databases and query sets are generally derived from data in S3 buckets and should have the same level of at rest protection.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/athena/latest/ug/encryption.html
# custom:
#   id: AVD-AWS-0006
#   avd_id: AVD-AWS-0006
#   provider: aws
#   service: athena
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: Enable encryption at rest for Athena databases and workgroup configurations
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: athena
#             provider: aws
#   examples: checks/cloud/aws/athena/enable_at_rest_encryption.yaml
package builtin.aws.athena.aws0006

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

encryption_type_none := ""

deny contains res if {
	some workgroup in input.aws.athena.workgroups
	not_encrypted(workgroup)
	res := result.new(
		"Workgroup does not have encryption configured.",
		metadata.obj_by_path(workgroup, ["encryption", "type"]),
	)
}

deny contains res if {
	some database in input.aws.athena.databases
	not_encrypted(database)
	res := result.new(
		"Database does not have encryption configured.",
		metadata.obj_by_path(database, ["encryption", "type"]),
	)
}

not_encrypted(encryptable) if value.is_equal(encryptable.encryption.type, encryption_type_none)

not_encrypted(encryptable) if not encryptable.encryption.type
