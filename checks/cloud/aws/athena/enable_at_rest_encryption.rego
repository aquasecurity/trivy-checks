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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database#encryption_configuration
#     good_examples: checks/cloud/aws/athena/enable_at_rest_encryption.tf.go
#     bad_examples: checks/cloud/aws/athena/enable_at_rest_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/athena/enable_at_rest_encryption.cf.go
#     bad_examples: checks/cloud/aws/athena/enable_at_rest_encryption.cf.go
package builtin.aws.athena.aws0006

import rego.v1

encryption_type_none := ""

deny contains res if {
	some workgroup in input.aws.athena.workgroups
	is_encryption_type_none(workgroup.encryption)
	res := result.new("Workgroup does not have encryption configured.", workgroup)
}

deny contains res if {
	some database in input.aws.athena.databases
	is_encryption_type_none(database.encryption)
	res := result.new("Database does not have encryption configured.", database)
}

is_encryption_type_none(encryption) if {
	encryption.type.value == encryption_type_none
}
