# METADATA
# title: ECR Repository should use customer managed keys to allow more control
# description: |
#   Images in the ECR repository are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html
# custom:
#   id: AVD-AWS-0033
#   avd_id: AVD-AWS-0033
#   provider: aws
#   service: ecr
#   severity: LOW
#   short_code: repository-customer-key
#   recommended_action: Use customer managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ecr
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#encryption_configuration
#     good_examples: checks/cloud/aws/ecr/repository_customer_key.tf.go
#     bad_examples: checks/cloud/aws/ecr/repository_customer_key.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ecr/repository_customer_key.cf.go
#     bad_examples: checks/cloud/aws/ecr/repository_customer_key.cf.go
package builtin.aws.ecr.aws0033

import rego.v1

deny contains res if {
	some repo in input.aws.ecr.repositories
	not is_encyption_type_kms(repo.encryption.type)
	res := result.new("Repository is not encrypted using KMS.", repo.encryption.type)
}

deny contains res if {
	some repo in input.aws.ecr.repositories
	is_encyption_type_kms(repo.encryption.type)
	repo.encryption.kmskeyid.value == ""
	res := result.new("Repository encryption does not use a customer managed KMS key.", repo.encryption.kmskeyid)
}

is_encyption_type_kms(typ) if typ.value == "KMS"
