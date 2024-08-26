# METADATA
# title: Secrets Manager should use customer managed keys
# description: |
#   Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt
# custom:
#   id: AVD-AWS-0098
#   avd_id: AVD-AWS-0098
#   provider: aws
#   service: ssm
#   severity: LOW
#   short_code: secret-use-customer-key
#   recommended_action: Use customer managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ssm
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id
#     good_examples: checks/cloud/aws/ssm/secret_use_customer_key.tf.go
#     bad_examples: checks/cloud/aws/ssm/secret_use_customer_key.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ssm/secret_use_customer_key.cf.go
#     bad_examples: checks/cloud/aws/ssm/secret_use_customer_key.cf.go
package builtin.aws.ssm.aws0098

import rego.v1

deny contains res if {
	some secret in input.aws.ssm.secrets
	secret.kmskeyid.value == ""
	res := result.new("Secret is not encrypted with a customer managed key.", secret.kmskeyid)
}

deny contains res if {
	some secret in input.aws.ssm.secrets
	secret.kmskeyid.value == "alias/aws/secretsmanager"
	res := result.new("Secret explicitly uses the default key.", secret.kmskeyid)
}
