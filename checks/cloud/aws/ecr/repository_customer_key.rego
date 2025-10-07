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
#   examples: checks/cloud/aws/ecr/repository_customer_key.yaml
package builtin.aws.ecr.aws0033

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some repo in input.aws.ecr.repositories
	encyption_type_no_kms(repo)
	res := result.new("Repository is not encrypted using KMS.", repo.encryption.type)
}

deny contains res if {
	some repo in input.aws.ecr.repositories
	repo.encryption.type.value == "KMS"
	without_cmk(repo)
	res := result.new(
		"Repository encryption does not use a customer managed KMS key.",
		metadata.obj_by_path(repo, ["encryption", "kmskeyid"]),
	)
}

encyption_type_no_kms(repo) if value.is_not_equal(repo.encryption.type, "KMS")

encyption_type_no_kms(repo) if not repo.encryption.type

without_cmk(repo) if value.is_empty(repo.encryption.kmskeyid)

without_cmk(repo) if not repo.encryption.kmskeyid
